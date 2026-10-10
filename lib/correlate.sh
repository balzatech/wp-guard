# correlate.sh - phase 2.
# Single responsibility: cross-reference findings (evidence with sha256 and files touched in the same time window).

correlate() {
  OUT="$FD/zz_correlacion.tsv"; : > "$OUT"
  cat "$FD"/*.flagged 2>/dev/null | sed 's/ (.*//; s/^\([^ :]*\).*/\1/' | grep '^\./' | sort -u > "$TMP/flagged.lst"
  local f ev=() n=0 sz mt pm ow sh peek
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    n=$((n + 1)); [ "$n" -gt 12 ] && break
    read -r sz mt pm ow <<< "$(stat -c '%s %Y %a %U' "$f" 2>/dev/null)"
    sh=$(sha256sum "$f" 2>/dev/null | cut -c1-64)
    peek=$(head -c 400 "$f" 2>/dev/null | tr -c '[:print:]' '.' | tr -s '.' | cut -c1-110)
    ev+=("$f  [${sz}B, $(date -d "@$mt" '+%F %H:%M'), perm $pm, $ow]" "      sha256 $sh" "      start: $peek")
  done < "$TMP/flagged.lst"
  [ ${#ev[@]} -gt 0 ] && printf '%s\n' "${ev[@]}" | lines INFO Correlation "Evidence for the files flagged as ALERT (look the sha256 up on VirusTotal; do NOT open them in a browser)" 40
  # files modified in the same time window as each finding (the rest of the attacker's kit)
  n=0
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    n=$((n + 1)); [ "$n" -gt 6 ] && break
    mt=$(stat -c %Y "$f" 2>/dev/null)
    awk -F'\t' -v t="$mt" -v w="$CLUSTER_SECS" -v me="$f" '$2 >= t-w && $2 <= t+w && $1 != me {print $1}' "$INV" | grep -vxFf "$TRUSTED" | head -n 15 \
      | lines WARN Correlation "Files modified +-${CLUSTER_SECS}s around $f (often part of the same attack: review them)" 15
  done < "$TMP/flagged.lst"
  unset OUT
}
