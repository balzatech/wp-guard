# restore.sh - undo a quarantine.
# Single responsibility: put back where it was whatever heal moved (as listed in that quarantine's MANIFEST.tsv).

restore_run() {
  local dir=$1 orig rel n=0 skipped=0
  if [ -z "$dir" ] || [ ! -f "$dir/MANIFEST.tsv" ]; then
    echo "Usage: wp-guard undo DIR   (available quarantines:)"; ls -1d "$STATE"/quarantine/*/ 2>/dev/null; return 1
  fi
  dir=${dir%/}
  while IFS=$'\t' read -r orig _; do
    rel=${orig#./}
    # The manifest is data, not trusted code: refuse anything that could land outside the site.
    case "/$rel/" in
      *"/../"*|*"/./"*|//*) echo "SKIPPED (unsafe path in manifest): $orig" >&2; skipped=$((skipped + 1)); continue ;;
    esac
    case $rel in /*|"") echo "SKIPPED (unsafe path in manifest): $orig" >&2; skipped=$((skipped + 1)); continue ;; esac
    if [ -e "$dir/$rel" ]; then
      if [ -e "$WP_PATH/$rel" ]; then echo "SKIPPED (a file already exists there): $orig" >&2; skipped=$((skipped + 1)); continue; fi
      mkdir -p "$WP_PATH/$(dirname "$rel")" && mv -n "$dir/$rel" "$WP_PATH/$rel" && { echo "restored: $orig"; n=$((n + 1)); }
    fi
  done < "$dir/MANIFEST.tsv"
  echo "$n restored, $skipped skipped."
  [ "$skipped" -eq 0 ]
}
