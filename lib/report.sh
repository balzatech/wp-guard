# report.sh - presentation.
# Single responsibility: turn the findings in $TMP/all.tsv into a readable report and save it.

ORDER="Integrity|IOC|PHP signatures|JS/HTML signatures|Uploads|Structure|htaccess|wp-config|Plugins|Persistence|Other sites|Database|Public site|Exposure|Logs|Correlation"
format_section() {  # level prefix color title
  local lvl=$1 pre=$2 col=$3 title=$4
  awk -F'\t' -v l="$lvl" -v order="$ORDER" -v pre="$pre" -v col="$col" -v nc="$C_N" -v bold="$C_BOLD" -v title="$title" '
    BEGIN { n=split(order, o, "|") }
    $1==l && !seen[$0]++ { cat[$2]=cat[$2] $3 "\n"; cnt++ }
    END {
      if (!cnt) exit
      print ""; print bold col "################ " title " ################" nc
      for (i=1;i<=n;i++) if (o[i] in cat) { print bold "== " o[i] " ==" nc; emitcat(cat[o[i]]); delete cat[o[i]] }
      for (c in cat) { print bold "== " c " ==" nc; emitcat(cat[c]) }
    }
    function emitcat(s,  m,k,j,parts,x,items) {
      m=split(s, items, "\n")
      for (k=1;k<m;k++) { j=split(items[k], parts, "\037"); print col pre nc " " parts[1]; for (x=2;x<=j;x++) print parts[x] }
    }' "$TMP/all.tsv"
}
print_report() {
  local na=$1 nw=$2 ni=$3 dur=$4
  local verdict
  if [ "$na" -gt 0 ]; then verdict="${C_R}${C_BOLD}ALERT${C_N}"; elif [ "$nw" -gt 0 ]; then verdict="${C_Y}${C_BOLD}REVIEW${C_N}"; else verdict="${C_G}${C_BOLD}CLEAN${C_N}"; fi
  echo "============================================================"
  echo " WP-GUARD v$VERSION ($MODE) - $(date '+%F %H:%M')"
  echo " Site: $SITE | Path: $WP_PATH"
  echo "============================================================"
  echo " VERDICT: $verdict - $na alerts, $nw warnings, $ni info"
  echo " Duration: ${dur}s | Workers: $WORKERS | Files inventoried: $(wc -l < "$INV") | Verified by official checksum (not scanned): $(wc -l < "$TRUSTED")"
  if [ "${CACHE_ON:-0}" = 1 ]; then
    if [ "${CACHE_SKIPPED:-0}" -gt 0 ]; then echo " Incremental: $CACHE_SCANNED new/changed files read, $CACHE_SKIPPED unchanged files skipped (clean in the last scan; --full reads everything)"
    else echo " Full content scan: $CACHE_SCANNED files read (the next scan will only read what changes)"; fi
  fi
  [ "${VC_REUSED:-0}" -gt 0 ] && echo " Official checksums: $VC_REUSED unchanged units (core/plugins) not re-verified, $VC_RUN checked now"
  [ "$NOWP" = 1 ] && echo " ${C_Y}wp-cli not available: no database, no checksums, no versions${C_N}"
  if [ "$na" -gt 0 ]; then echo " Alert summary by category:"; awk -F'\t' '$1=="ALERT"{c[$2]++} END{for(k in c) printf "   - %s: %d\n", k, c[k]}' "$TMP/all.tsv" | sort; fi
  format_section ALERT "[!!]" "$C_R" "ALERTS (review now)"
  format_section WARN  "[! ]" "$C_Y" "WARNINGS (improve / confirm)"
  [ "$MODE" = full ] && format_section INFO "[i ]" "$C_B" "INFORMATION"
  if [ "$na" -gt 0 ]; then
    echo; echo "${C_BOLD}What to do next${C_N}"
    echo "  1. Make a backup first (hosting panel, or: wp db export)."
    echo "  2. Preview the safe fixes (changes nothing):   wp-guard fix"
    echo "  3. Apply them (asks first, nothing is deleted): wp-guard fix --apply"
    echo "  Alerts that fix cannot handle (e.g. infected database rows) need a manual review of the list above."
    echo "  Confirmed false positive? Add the path (or text) to $STATE/allow.txt"
  elif [ "$nw" -gt 0 ]; then
    echo; echo "No alerts. The warnings above are things to confirm or harden; nothing is urgent."
    echo "When you are sure the site is clean, save this state so future changes stand out:  wp-guard baseline"
  else
    echo; echo "${C_G}All clear.${C_N} Save this state so future changes stand out:  wp-guard baseline"
  fi
  if declare -F notify_channels >/dev/null && [ -z "$(notify_channels)" ] && [ "$MODE" != watch ]; then
    echo "${C_Y}No alert channel configured:${C_N} wp-guard cannot tell you when something happens. Run: wp-guard notify setup"
  fi
  [ -f "$FD/_timing" ] && { echo; echo "Time per worker: $(sort -k2 -rn "$FD/_timing" | awk '{printf "%s=%ss ", $1, $2}')"; }
}

# print_json NA NW NI DURATION  -> the whole scan as one JSON document on stdout (no jq needed).
# Schema: {tool, version, generated, site, path, mode, duration_seconds, verdict: alert|review|clean,
#          counts: {alert, warning, info}, findings: [{level: ALERT|WARN|INFO, category, title, count|null, items: []}]}
print_json() {
  local na=$1 nw=$2 ni=$3 dur=$4 verdict=clean
  [ "$nw" -gt 0 ] && verdict=review
  [ "$na" -gt 0 ] && verdict=alert
  local jtime; jtime=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  tr -d '\000-\010\013-\036' < "$TMP/all.tsv" \
    | J_VERSION=$VERSION J_SITE=$SITE J_PATH=$WP_PATH J_MODE=$MODE J_VERDICT=$verdict J_DUR=$dur J_NA=$na J_NW=$nw J_NI=$ni J_TIME=$jtime \
      J_INC=$([ "${CACHE_SKIPPED:-0}" -gt 0 ] && echo true || echo false) J_READ=${CACHE_SCANNED:-0} J_SKIP=${CACHE_SKIPPED:-0} \
      awk -F'\t' '
    function esc(s,   i, c, o) {
      o = ""
      for (i = 1; i <= length(s); i++) {
        c = substr(s, i, 1)
        if (c == "\\") o = o "\\\\"; else if (c == "\"") o = o "\\\""; else if (c == "\t") o = o "\\t"; else o = o c
      }
      return o
    }
    function env(k) { return esc(ENVIRON[k]) }
    BEGIN {
      printf "{\n  \"tool\": \"wp-guard\",\n  \"version\": \"%s\",\n  \"generated\": \"%s\",\n", env("J_VERSION"), env("J_TIME")
      printf "  \"site\": \"%s\",\n  \"path\": \"%s\",\n  \"mode\": \"%s\",\n  \"duration_seconds\": %d,\n", env("J_SITE"), env("J_PATH"), env("J_MODE"), ENVIRON["J_DUR"]
      printf "  \"verdict\": \"%s\",\n  \"counts\": {\"alert\": %d, \"warning\": %d, \"info\": %d},\n", env("J_VERDICT"), ENVIRON["J_NA"], ENVIRON["J_NW"], ENVIRON["J_NI"]
      printf "  \"content_scan\": {\"incremental\": %s, \"files_read\": %d, \"files_skipped\": %d},\n  \"findings\": [", ENVIRON["J_INC"], ENVIRON["J_READ"], ENVIRON["J_SKIP"]
      first = 1
    }
    !seen[$0]++ && ($1 == "ALERT" || $1 == "WARN" || $1 == "INFO") {
      n = split($3, parts, "\037"); title = parts[1]; cnt = "null"
      if (match(title, / \([0-9]+\)$/)) { cnt = substr(title, RSTART + 2, RLENGTH - 3); title = substr(title, 1, RSTART - 1) }
      items = ""
      for (i = 2; i <= n; i++) { it = parts[i]; sub(/^ +/, "", it); if (it != "") items = items (items == "" ? "" : ", ") "\"" esc(it) "\"" }
      printf "%s\n    {\"level\": \"%s\", \"category\": \"%s\", \"title\": \"%s\", \"count\": %s, \"items\": [%s]}", (first ? "" : ","), $1, esc($2), esc(title), cnt, items
      first = 0
    }
    END { printf "\n  ]\n}\n" }'
}

# report_save PLAIN_TEXT_FILE [JSON_FILE]  -> save report, findings (and JSON) with a date in $STATE/reports (keeps the latest 40 of each)
report_save() {
  local stamp; stamp=$(date +%Y%m%d_%H%M)
  REPORT="$STATE/reports/report_$stamp.txt"
  cp "$1" "$REPORT"
  cp "$TMP/all.tsv" "$STATE/reports/findings_$stamp.tsv" 2>/dev/null
  [ -n "${2:-}" ] && cp "$2" "$STATE/reports/report_$stamp.json" 2>/dev/null
  ls -1t "$STATE"/reports/report_*.txt 2>/dev/null | tail -n +41 | xargs -r rm -f
  ls -1t "$STATE"/reports/report_*.json 2>/dev/null | tail -n +41 | xargs -r rm -f
  ls -1t "$STATE"/reports/findings_* 2>/dev/null | tail -n +41 | xargs -r rm -f
}
