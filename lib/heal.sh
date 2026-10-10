# heal.sh - safe remediation.
# Single responsibility: from what the inventory/checksums already flag as bad, plan and (with --apply)
# act. Never deletes: quarantine in $STATE/quarantine with a MANIFEST. The database part lives in php/heal_db.php.

# heal_exclude FILE OFFSET LIST -> drop the lines of FILE whose number (+OFFSET) is in the comma list LIST
heal_exclude() {
  awk -v off="$2" -v ex=",$3," 'index(ex, "," (NR + off) ",") == 0' "$1" > "$1.new" && mv "$1.new" "$1"
}

# Principles: 1) high confidence only, 2) never deletes: quarantine in ~/.wp_auditor/quarantine
# with a MANIFEST to restore, 3) dry run by default, 4) MAX_HEAL cap, 5) everything is logged
heal_run() {
  local PLAN="$TMP/heal.plan" QALL="$TMP/q.all" QDIRS="$TMP/q.dirs" RE="$TMP/reinstall.lst"
  local now cutoff ts QDIR f rel sha reason d n slug ver p msg total loc nrei=0
  : > "$PLAN"; : > "$QALL"; : > "$QDIRS"; : > "$RE"
  now=$(date +%s); cutoff=$((now - MIN_AGE_MIN * 60)); ts=$(date +%Y%m%d_%H%M%S)
  QDIR="$STATE/quarantine/$ts"
  awk -F'\t' -v c="$cutoff" '$2 <= c {print $1}' "$INV" > "$TMP/old.lst"
  add_q() { local reason=$1 pth; while IFS= read -r pth; do [ -n "$pth" ] && printf '%s\t%s\n' "$pth" "$reason" >> "$QALL"; done; }

  # 1) executables inside uploads
  awk -F'\t' '$1 ~ /^\.\/wp-content\/uploads\// && tolower($1) ~ /\.(php[0-9]?|phtml|phar|pht|phps|inc|shtml|cgi|pl|py|sh|asp|aspx|jsp|exe|so)$/ && $1 !~ /\/index\.php$/ {print $1}' "$INV" | add_q "executable inside uploads"
  # 2) images/media with PHP inside (polyglot)
  awk -F'\t' '$1 ~ /^\.\/wp-content\/uploads\// && tolower($1) ~ /\.(jpe?g|png|gif|ico|bmp|webp|avif|mp3|mp4|woff2?|ttf)$/ && $3 < 8000000 {print $1}' "$INV" \
    | xargs -d '\n' -r -n 250 grep -laE '<\?php' 2>/dev/null | add_q "image/media with PHP code inside (polyglot)"
  # 3) PHP where there must never be any (languages/upgrade/fonts), except .l10n.php translations
  awk -F'\t' '$1 ~ /^\.\/wp-content\/(languages|upgrade|fonts|bcf-fonts)\// && tolower($1) ~ /\.(php[0-9]?|phtml|phar|pht|phps|inc)$/ && $1 !~ /\/index\.php$/ && $1 !~ /\.l10n\.php$/ {print $1}' "$INV" | add_q "PHP in a folder that should have no code"
  # 4) PHP in the web root that is not WordPress and contains PHP code (a host's default.php that is plain HTML is left alone)
  awk -F'\t' -v ok=" $ROOT_PHP_OK " '$1 ~ /^\.\/[^\/]+\.(php[0-9]?|phtml|phar)$/ { f=substr($1,3); if (index(ok," " f " ")==0) print $1 }' "$INV" \
    | while IFS= read -r f; do grep -qs '<?' "$f" && echo "$f"; done | add_q "PHP in the web root that does not belong to WordPress"
  # 5) files with attacker markers outside what checksums verified
  awk -F'\t' '$3 < 8000000 {print $1}' "$INV" | grep -vxFf "$TRUSTED" | xargs -d '\n' -r -n 300 grep -lIE -e "$IOC_RE" 2>/dev/null | add_q "contains known attacker markers"
  # 6) WordPress core: extras -> quarantine; modified -> restore from wordpress.org
  local CORE_RESTORE=0
  if [ "${CORE_OK:-0}" = 1 ]; then
    grep -E 'should not exist' "$TMP/core.vc" | sed -E 's/^.*exist: *//; s#^#./#' | grep -E '^\./(wp-admin|wp-includes)/' | add_q "extra file inside the WordPress core"
    grep -q "verify against checksum" "$TMP/core.vc" && CORE_RESTORE=1
  fi
  # 7) official plugins: extra code files -> quarantine; modified/missing -> reinstall the same version
  if [ -s "$TMP/plug.bad" ]; then
    while IFS=$'\t' read -r p msg; do
      slug=${p#./wp-content/plugins/}; slug=${slug%%/*}
      case "$msg" in
        *added*) printf '%s\n' "$p" | grep -iE '\.(php[0-9]?|phtml|phar|inc|js|html?)$' | add_q "extra code file inside the official plugin $slug" ;;
        *) grep -qxF "$slug" "$RE" || echo "$slug" >> "$RE" ;;
      esac
    done < "$TMP/plug.bad"
  fi
  # 8) fake plugin folders: not recognized by WordPress AND (no 'Plugin Name:' header or a name with a long number)
  if [ -s "$TMP/plug.names" ]; then
    for d in wp-content/plugins/*/; do
      [ -d "$d" ] || continue; n=$(basename "$d")
      grep -qxF "$n" "$TMP/plug.names" && continue
      find "$d" -type f -name '*.php' 2>/dev/null | grep -q . || continue
      find "$d" -type f -newermt "@$cutoff" 2>/dev/null | grep -q . && continue
      if echo "$n" | grep -qE -- '-[0-9]{6,}$' || ! { find "$d" -maxdepth 1 -type f -name '*.php' -print0 2>/dev/null | xargs -0 -r head -c 8192 2>/dev/null | grep -qi 'Plugin Name:'; }; then
        printf './wp-content/plugins/%s\tfake plugin folder (not recognized by WordPress)\n' "$n" >> "$QDIRS"
      fi
    done
  fi
  # age filter + no duplicates
  sort -u -t$'\t' -k1,1 "$QALL" | awk -F'\t' 'NR==FNR{o[$1]=1;next} ($1 in o)' "$TMP/old.lst" - > "$TMP/q.final"

  # ---- plan
  local qi=0   # quarantine items are numbered so the user can leave some out ("select" at the prompt)
  while IFS=$'\t' read -r f reason; do qi=$((qi + 1)); echo "QUARANTINE   [$qi] $f   [$reason]" >> "$PLAN"; done < "$TMP/q.final"
  while IFS=$'\t' read -r f reason; do qi=$((qi + 1)); echo "QUARANTINE   [$qi] $f/ (folder)   [$reason]" >> "$PLAN"; done < "$QDIRS"
  [ "$CORE_RESTORE" = 1 ] && echo "CORE         restore modified WordPress files from wordpress.org" >> "$PLAN"
  while IFS= read -r slug; do [ -n "$slug" ] && echo "REINSTALL    plugin $slug (same version, from wordpress.org)" >> "$PLAN"; done < "$RE"
  local nw; nw=$(find . -perm -0002 ! -type l -not -path './wp-content/cache/*' 2>/dev/null | wc -l)
  [ "$nw" -gt 0 ] && echo "PERMISSIONS  remove world-write from $nw files/folders" >> "$PLAN"
  local needhta=0
  if [ -d wp-content/uploads ] && ! grep -qsiE 'Require all denied|deny from all|php_flag engine off|RemoveHandler' wp-content/uploads/.htaccess; then
    needhta=1; echo "HTACCESS     block PHP in uploads/.htaccess" >> "$PLAN"
  fi
  if [ "$NOWP" = 0 ]; then
    APPLY=0 T 120 $WP eval-file "$WPG_HOME/lib/php/heal_db.php" 2>&1 | grep -E '^(DB|SKIPPED)' >> "$PLAN"
  fi

  # nothing to do: silent under cron, a one-line answer in a terminal
  if [ ! -s "$PLAN" ]; then [ -t 1 ] && echo "Nothing to fix: no high-confidence problems found. (Run 'wp-guard scan' for the full picture.)"; return 0; fi
  total=$(( $(wc -l < "$TMP/q.final") + $(wc -l < "$QDIRS") ))
  {
    echo "== wp-guard fix ($( [ "$APPLY" = 1 ] && echo APPLYING || echo 'DRY RUN' )) $(date '+%F %H:%M') $SITE_HOST =="
    cat "$PLAN"
  } | tee -a "$STATE/heal.log"
  if [ "$APPLY" != 1 ]; then echo "(dry run: nothing was touched. To act: wp-guard fix --apply)"; return 0; fi
  if [ "$total" -gt "$MAX_HEAL" ]; then
    msg="[fix] $total quarantine targets (> MAX_HEAL=$MAX_HEAL): NOTHING was touched. Many findings at once are usually a false positive or a large compromise: review by hand (wp-guard scan)."
    echo "$msg" | tee -a "$STATE/heal.log"; notify "$msg"; return 2
  fi

  # ---- confirmation (interactive terminal only: cron and --yes go straight through)
  if [ -t 0 ] && [ -t 1 ] && [ "$YES" != 1 ]; then
    echo
    echo "Nothing is deleted: files go to quarantine (${STATE}/quarantine) and can be restored with: wp-guard undo DIR"
    read -r -p "Apply these changes to $SITE_HOST? [y]es / [N]o / [s]elect items to leave out: " msg
    case $msg in
      y|Y) ;;
      s|S)
        read -r -p "Numbers of the quarantine items to LEAVE ALONE (e.g. 2,5): " excl
        excl=$(printf '%s' "$excl" | tr -c '0-9\n' ',')
        nq=$(wc -l < "$TMP/q.final")
        heal_exclude "$TMP/q.final" 0 "$excl"; heal_exclude "$QDIRS" "$nq" "$excl"
        awk -v ex=",$excl," '/^QUARANTINE/ { i++; if (index(ex, "," i ",")) next } { print }' "$PLAN" > "$PLAN.new" && mv "$PLAN.new" "$PLAN"
        total=$(( $(wc -l < "$TMP/q.final") + $(wc -l < "$QDIRS") ))
        echo "Leaving out: ${excl:-nothing}. Proceeding with the rest." ;;
      *) echo "Cancelled. Nothing was touched." | tee -a "$STATE/heal.log"; return 0 ;;
    esac
  fi

  # ---- ejecucion
  if [ "$total" -gt 0 ]; then
    mkdir -p "$QDIR" && chmod 700 "$STATE/quarantine" "$QDIR" 2>/dev/null
    : > "$QDIR/MANIFEST.tsv"
    while IFS=$'\t' read -r f reason; do
      rel=${f#./}; sha=$(sha256sum "$f" 2>/dev/null | cut -c1-64)
      mkdir -p "$QDIR/$(dirname "$rel")" && mv -- "$f" "$QDIR/$rel" && chmod a-x "$QDIR/$rel" 2>/dev/null \
        && printf '%s\t%s\t%s\n' "$f" "$sha" "$reason" >> "$QDIR/MANIFEST.tsv"
    done < "$TMP/q.final"
    while IFS=$'\t' read -r f reason; do
      rel=${f#./}
      mkdir -p "$QDIR/$(dirname "$rel")" && mv -- "$f" "$QDIR/$rel" && find "$QDIR/$rel" -type f -exec chmod a-x {} + 2>/dev/null \
        && printf '%s\t-\t%s\n' "$f" "$reason" >> "$QDIR/MANIFEST.tsv"
    done < "$QDIRS"
    echo "Quarantine: $QDIR  (restore with: wp-guard undo $QDIR)" | tee -a "$STATE/heal.log"
  fi
  if [ "$CORE_RESTORE" = 1 ] && [ "$NOWP" = 0 ]; then
    loc=$(T 30 $WP eval 'echo get_locale();' 2>/dev/null)
    T 300 $WP core download --force --skip-content --version="$(T 30 $WP core version 2>/dev/null)" --locale="${loc:-en_US}" 2>&1 | tail -n 2 | tee -a "$STATE/heal.log"
  fi
  while IFS= read -r slug; do
    [ -n "$slug" ] || continue; nrei=$((nrei + 1)); [ "$nrei" -gt 5 ] && { echo "REINSTALL limited to 5 plugins per run" | tee -a "$STATE/heal.log"; break; }
    ver=$(T 30 $WP plugin get "$slug" --field=version 2>/dev/null)
    [ -n "$ver" ] && T 300 $WP plugin install "$slug" --force --version="$ver" 2>&1 | tail -n 2 | tee -a "$STATE/heal.log"
  done < "$RE"
  [ "$nw" -gt 0 ] && find . -perm -0002 ! -type l -not -path './wp-content/cache/*' -exec chmod o-w {} + 2>/dev/null
  if [ "$needhta" = 1 ]; then
    printf '\n# wp-guard: block PHP execution in uploads\n<FilesMatch "\\.(php|phtml|phar|php[0-9]?)$">\n  Require all denied\n</FilesMatch>\n' >> wp-content/uploads/.htaccess
  fi
  [ "$NOWP" = 0 ] && APPLY=1 T 120 $WP eval-file "$WPG_HOME/lib/php/heal_db.php" 2>&1 | grep -E '^(DB|SKIPPED)' >> "$STATE/heal.log"
  local moved=0; [ -f "$QDIR/MANIFEST.tsv" ] && moved=$(wc -l < "$QDIR/MANIFEST.tsv")
  {
    echo
    echo "Summary: $moved item(s) moved to quarantine | core restored: $([ "$CORE_RESTORE" = 1 ] && echo yes || echo no) | plugins reinstalled: $nrei | permissions fixed: $nw | PHP blocked in uploads: $([ "$needhta" = 1 ] && echo added || echo 'already in place')"
    [ "$moved" -gt 0 ] && echo "Undo:   wp-guard undo $QDIR"
    echo "Verify: wp-guard scan    (anything still flagged is not auto-fixable and needs a manual review)"
  } | tee -a "$STATE/heal.log"
  notify "$(printf '[wp-heal] actions applied on %s\n' "$SITE_HOST"; cat "$PLAN"; [ "$moved" -gt 0 ] && echo "Undo: wp-guard undo $QDIR")"
  return 0
}