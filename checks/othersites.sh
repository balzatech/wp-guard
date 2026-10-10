# checks/othersites.sh
# Other sites in the same hosting account.
# Worker: launched from lib/audit.sh. Only READS; reports with emit/lines/hits.

job_othersites() {
  [ "$OTHER_SITES" = 1 ] || return 0
  local d site
  for d in "$HOME"/domains/*/public_html; do
    [ -d "$d" ] || continue
    [ "$(cd "$d" && pwd -P)" = "$WP_PATH" ] && continue
    site=$(basename "$(dirname "$d")")
    ( cd "$d" || exit 0
      find . -type f \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.phar' \) -size -8000k 2>/dev/null > "$TMP/os.$site.lst"
      load_rules "$PHP_RULES"
      local args=() i
      for i in "${!RX[@]}"; do [ "${RL[$i]}" = ALERT ] && args+=(-e "${RX[$i]}"); done
      xargs -a "$TMP/os.$site.lst" -d '\n' -r -n 250 -P "$SCAN_PAR" grep -laiE "${args[@]}" 2>/dev/null | sed "s#^\./#$site/#" | lines ALERT "Other sites" "[$site] PHP with webshell/obfuscation signatures" 15
      grep -iE '/wp-content/uploads/.*\.(php[0-9]?|phtml|phar)$' "$TMP/os.$site.lst" | grep -v '/index\.php$' | sed "s#^\./#$site/#" | lines ALERT "Other sites" "[$site] PHP inside uploads" 15
      xargs -a "$TMP/os.$site.lst" -d '\n' -r -n 250 grep -lIE -e "$IOC_RE" 2>/dev/null | sed "s#^\./#$site/#" | lines ALERT "Other sites" "[$site] known attacker markers" 15
    )
  done
}
