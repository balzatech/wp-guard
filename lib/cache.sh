# shellcheck disable=SC2034  # shared state: assigned here, read by the modules and commands that source this file
# cache.sh - incremental scanning.
# Single responsibility: remember which files were already scanned and found CLEAN, so the next scan only reads
# the content of files that are new or changed. Everything else (file names, permissions, database, HTTP...)
# is still checked on every run; only the expensive content passes (php, js, ioc, uploads) are skipped.
#
# Safety rules (a mistake here would hide malware, so it errs on the side of rescanning):
#  - Only files that matched NOTHING are cached. A file that ever produced a finding is always scanned again.
#  - "Unchanged" means same size, mtime AND ctime (ctime cannot be set with touch) and the same trusted/untrusted
#    status. Any difference means the file is read again.
#  - The whole cache is dropped when the rules, the configuration that affects matching, the allow list or the
#    wp-guard version change, after FULL_SCAN_DAYS days, and with --full.
#  - A scan restricted with --only/--skip to some of the content groups neither reads nor writes the cache.
#
# Cache file: $STATE/scan_cache.tsv   first line "#wpg-cache<TAB>profile<TAB>created", then
#             path<TAB>size<TAB>mtime<TAB>ctime<TAB>trusted(0|1)

CACHE_ON=0; CACHE_SKIPPED=0; CACHE_SCANNED=0

cache_profile() {
  { cat "$WPG_HOME"/rules/*.rules 2>/dev/null
    printf '%s\n' "$VERSION|$IOC_LIST|$KNOWN_HOSTS|$ALLOW_RE|$CF_A|$CF_B|$CF_C|$EXT_RX"
    cat "$ALLOW_FILE" 2>/dev/null
  } | sha256sum | cut -c1-64
}

# cache_init: decide whether the cache can be used and compute $TMP/clean.set (paths unchanged and clean).
cache_init() {
  local g tag prof created now
  : > "$TMP/clean.set"; CACHE_ON=0; CACHE_CREATED=""; CACHE_FILE="$STATE/scan_cache.tsv"
  [ "${INCREMENTAL:-1}" = 1 ] || return 0
  CACHE_ON=1
  for g in php js ioc uploads; do should_run "$g" || CACHE_ON=0; done
  [ "$CACHE_ON" = 1 ] || return 0
  CACHE_PROFILE=$(cache_profile)
  [ "${FORCE_FULL:-0}" = 1 ] && return 0
  [ -s "$CACHE_FILE" ] || return 0
  IFS=$'\t' read -r tag prof created < "$CACHE_FILE"
  [ "$tag" = "#wpg-cache" ] && [ "$prof" = "$CACHE_PROFILE" ] || return 0
  case "$created" in ''|*[!0-9]*) return 0 ;; esac
  now=$(date +%s)
  [ $((now - created)) -lt $(( ${FULL_SCAN_DAYS:-7} * 86400 )) ] || return 0
  CACHE_CREATED=$created
  # INV columns: path mtime size mode user ctime
  awk -F'\t' -v OFS='\t' '
    FILENAME == ARGV[1] { tr[$0] = 1; next }
    FILENAME == ARGV[2] { if (FNR > 1) c[$1] = $2 OFS $3 OFS $4 OFS $5; next }
    { t = ($1 in tr) ? 1 : 0; if (($1 in c) && c[$1] == $3 OFS $2 OFS $6 OFS t) print $1 }
  ' "$TRUSTED" "$CACHE_FILE" "$INV" > "$TMP/clean.set"
  CACHE_SKIPPED=$(wc -l < "$TMP/clean.set")
}

# cache_filter LIST -> LIST without the files known to be unchanged and clean
cache_filter() {
  if [ -s "$TMP/clean.set" ]; then awk 'NR == FNR { c[$0]; next } !($0 in c)' "$TMP/clean.set" "$1"; else cat "$1"; fi
}

# ---------------------------------------------------------------------------------------------------
# Verification cache. `wp plugin verify-checksums` boots WordPress once per plugin (about 2 s of CPU each) and was
# most of the cost of a scan. If every file of a plugin (or of the core) is identical to the last time it
# verified successfully (same path, size, mtime and ctime, and no file added or removed), that result still holds.
# Only SUCCESS is cached: a plugin that failed, could not be verified, or had mismatches is always checked again.
# Cache file: $STATE/verify_cache.tsv   "#wpg-verify<TAB>version<TAB>created", then unit<TAB>signature<TAB>ok

# vc_sigs -> "unit<TAB>signature" for the core and for every plugin folder, computed from the inventory
vc_sigs() {
  local d="$TMP/vsig"; rm -rf "$d"; mkdir -p "$d"
  awk -F'\t' -v OFS='\t' -v ok=" $ROOT_PHP_OK license.txt readme.html " '
    function emit(u) { print u, $1, $3, $2, $6 }
    $1 ~ /^\.\/(wp-admin|wp-includes)\// { emit("core"); next }
    $1 ~ /^\.\/[^\/]+$/ { f = substr($1, 3); if (index(ok, " " f " ")) emit("core"); next }
    $1 ~ /^\.\/wp-content\/(themes\/twenty|plugins\/hello\.php)/ { emit("core"); next }
    $1 ~ /^\.\/wp-content\/plugins\/[^\/]+\// { split($1, a, "/"); emit("plugin:" a[4]) }
  ' "$INV" | LC_ALL=C sort | awk -F'\t' -v d="$d" '
      { if (!($1 in id)) { id[$1] = ++n; print id[$1] "\t" $1 > (d "/index") }
        print $2 "\t" $3 "\t" $4 "\t" $5 > (d "/" id[$1]) }'
  [ -s "$d/index" ] || return 0
  ( cd "$d" && sha256sum [0-9]* ) | awk -F'  ' -v idx="$d/index" '
    BEGIN { while ((getline l < idx) > 0) { split(l, a, "\t"); u[a[1]] = a[2] } }
    { print u[$2] "\t" $1 }'
}

# verify_checksums: leave $TMP/core.vc and $TMP/pv/<slug>.vc ready for compute_trusted, running wp-cli only for
# the units that changed (or all of them when the cache is off).
verify_checksums() {
  local tag ver created now slug u s
  local -A reuse=()
  : > "$TMP/vc.old"; VC_CREATED=""; VC_FILE="$STATE/verify_cache.tsv"
  if [ "${WPG_CACHE:-0}" = 1 ] && [ "${INCREMENTAL:-1}" = 1 ] && [ "${FORCE_FULL:-0}" != 1 ] && [ -s "$VC_FILE" ]; then
    IFS=$'\t' read -r tag ver created < "$VC_FILE"
    now=$(date +%s)
    case "$created" in ''|*[!0-9]*) created=0 ;; esac
    if [ "$tag" = "#wpg-verify" ] && [ "$ver" = "$VERSION" ] && [ $((now - created)) -lt $(( ${FULL_SCAN_DAYS:-7} * 86400 )) ]; then
      tail -n +2 "$VC_FILE" > "$TMP/vc.old"; VC_CREATED=$created
    fi
  fi
  vc_sigs > "$TMP/vc.new"
  awk -F'\t' 'NR == FNR { o[$1] = $2 "\t" $3; next } ($1 in o) { split(o[$1], p, "\t"); if (p[1] == $2 && p[2] == "ok") print $1 }' \
    "$TMP/vc.old" "$TMP/vc.new" > "$TMP/vc.reuse"
  while IFS= read -r u; do reuse[$u]=1; done < "$TMP/vc.reuse"

  mkdir -p "$TMP/pv"; : > "$TMP/vc.todo"
  if [ -n "${reuse[core]:-}" ]; then echo "Success: WordPress installation verifies against checksums." > "$TMP/core.vc"
  else ( T 180 $WP core verify-checksums > "$TMP/core.vc" 2>&1 ) &
  fi
  while IFS= read -r slug; do
    if [ -n "${reuse[plugin:$slug]:-}" ]; then echo "Success: Verified 1 of 1 plugins." > "$TMP/pv/$slug.vc"
    else printf '%s\n' "$slug" >> "$TMP/vc.todo"; fi
  done < "$TMP/plug.names"
  VC_REUSED=${#reuse[@]}; VC_RUN=$(wc -l < "$TMP/vc.todo")
  xargs -a "$TMP/vc.todo" -d '\n' -r -P "$WORKERS" -I{} bash -c \
    'timeout 120 wp --path="$WP_PATH" --skip-plugins --skip-themes plugin verify-checksums "$1" --format=csv > "$2/$1.vc" 2>&1' _ {} "$TMP/pv"
  wait

  [ "${WPG_CACHE:-0}" = 1 ] && [ "${INCREMENTAL:-1}" = 1 ] || return 0
  {
    printf '#wpg-verify\t%s\t%s\n' "$VERSION" "${VC_CREATED:-$(date +%s)}"
    awk -F'\t' -v OFS='\t' '$1 == "core" { print $1, $2, "ok" }' "$TMP/vc.new" | { grep -q '^Success: WordPress installation verifies' "$TMP/core.vc" && cat; }
    while IFS=$'\t' read -r u s; do
      slug=${u#plugin:}; [ "$u" = "plugin:$slug" ] || continue
      grep -qE '^[^,]+,[^,]+,(Checksum does not match|File was added|File is missing|File doesn.t exist)' "$TMP/pv/$slug.vc" 2>/dev/null && continue
      grep -q '^Success: Verified' "$TMP/pv/$slug.vc" 2>/dev/null && printf '%s\t%s\tok\n' "$u" "$s"
    done < "$TMP/vc.new"
  } > "$TMP/vc.save" 2>/dev/null
  install -m 600 "$TMP/vc.save" "$VC_FILE" 2>/dev/null
}

# cache_save: rewrite the cache after a complete scan: keep still-valid clean files, add the files scanned now
# that matched nothing.
cache_save() {
  [ "$CACHE_ON" = 1 ] || return 0
  local lst
  cat "$FD"/*.matched 2>/dev/null | sort -u > "$TMP/matched.lst"
  : > "$TMP/scanned.lst"
  for lst in php_scan.c.lst js_scan.c.lst ioc.c.lst up.c.lst; do cat "$TMP/$lst" 2>/dev/null >> "$TMP/scanned.lst"; done
  sort -u "$TMP/scanned.lst" -o "$TMP/scanned.lst"
  CACHE_SCANNED=$(wc -l < "$TMP/scanned.lst")
  {
    printf '#wpg-cache\t%s\t%s\n' "$CACHE_PROFILE" "${CACHE_CREATED:-$(date +%s)}"
    awk -F'\t' -v OFS='\t' '
      FILENAME == ARGV[1] { tr[$0] = 1; next }
      FILENAME == ARGV[2] { bad[$0] = 1; next }
      FILENAME == ARGV[3] { scanned[$0] = 1; next }
      FILENAME == ARGV[4] { clean[$0] = 1; next }
      { p = $1; if (p in bad) next
        if ((p in clean) || (p in scanned)) print p, $3, $2, $6, (p in tr) ? 1 : 0 }
    ' "$TRUSTED" "$TMP/matched.lst" "$TMP/scanned.lst" "$TMP/clean.set" "$INV"
  } > "$TMP/cache.new" && install -m 600 "$TMP/cache.new" "$CACHE_FILE" 2>/dev/null
}
