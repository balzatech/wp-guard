# inventory.sh - phase 0.
# Single responsibility: know WHAT is on the site (a single find) and which part is verified as official
# (wp core/plugin verify-checksums). Produces INV, TRUSTED and the php_scan/js_scan/code_scan lists.

# shellcheck disable=SC1091
. "$WPG_HOME/lib/cache.sh"

# INV columns: path, mtime, size, mode, owner, ctime
build_inventory() {
  find . -type f -printf '%p\t%T@\t%s\t%m\t%u\t%C@\n' 2>/dev/null \
    | awk -F'\t' 'BEGIN{OFS="\t"} { sub(/\.[0-9]+$/,"",$2); sub(/\.[0-9]+$/,"",$6); print }' > "$INV"
}
compute_trusted() {
  : > "$TRUSTED"; : > "$TMP/core.bad"; : > "$TMP/plug.bad"; : > "$TMP/plug.trust"; : > "$TMP/plug.unver"
  CORE_OK=0
  if grep -qE "^Success: WordPress installation verifies|^Warning: .*(verify against checksum|should not exist)" "$TMP/core.vc" 2>/dev/null; then CORE_OK=1; fi
  if [ "$CORE_OK" = 1 ]; then
    grep -E '^Warning: .*(verify against checksum|should not exist)' "$TMP/core.vc" \
      | sed -E 's/^.*(checksum|exist): *//; s#^#./#' | sort -u > "$TMP/core.bad"
    awk -F'\t' '$1 ~ /^\.\/(wp-admin|wp-includes)\// {print $1}' "$INV" | grep -vxFf "$TMP/core.bad" >> "$TRUSTED"
    local f
    for f in $ROOT_CORE_PHP; do
      [ -f "./$f" ] && ! grep -qxF "./$f" "$TMP/core.bad" && echo "./$f" >> "$TRUSTED"
    done
  fi
  local vc s
  for vc in "$TMP"/pv/*.vc; do
    [ -f "$vc" ] || continue
    s=$(basename "$vc" .vc)
    if grep -qE '^[^,]+,[^,]+,(Checksum does not match|File was added|File is missing|File doesn.t exist)' "$vc"; then
      echo "$s" >> "$TMP/plug.trust"
      grep -E '^[^,]+,[^,]+,(Checksum does not match|File was added|File is missing|File doesn.t exist)' "$vc" \
        | awk -F, -v s="$s" '{print "./wp-content/plugins/" s "/" $2 "\t" $3}' >> "$TMP/plug.bad"
    elif grep -q '^Success: Verified' "$vc"; then
      echo "$s" >> "$TMP/plug.trust"
    else
      echo "$s" >> "$TMP/plug.unver"
    fi
  done
  if [ -s "$TMP/plug.trust" ]; then
    cut -f1 "$TMP/plug.bad" > "$TMP/plug.badpaths"
    awk -F'\t' 'NR==FNR{v[$1]=1; next} { n=split($1,a,"/"); if (a[2]=="wp-content" && a[3]=="plugins" && (a[4] in v)) print $1 }' \
      "$TMP/plug.trust" "$INV" | grep -vxFf "$TMP/plug.badpaths" >> "$TRUSTED"
  fi
  sort -u "$TRUSTED" -o "$TRUSTED"
}
build_lists() {
  awk -F'\t' 'tolower($1) ~ /\.(php|phtml|phar|php[0-9]|pht|phps|inc)$/ && $3 < 8000000 {print $1}' "$INV" | sort -u > "$TMP/php_all.lst"
  grep -vxFf "$TRUSTED" "$TMP/php_all.lst" > "$TMP/php_scan.lst"
  awk -F'\t' 'tolower($1) ~ /\.(js|mjs|html?|svg|xhtml)$/ && $3 < 8000000 && $1 !~ /^\.\/wp-content\/(cache|litespeed|wflogs)\// {print $1}' "$INV" | sort -u \
    | grep -vxFf "$TRUSTED" > "$TMP/js_scan.lst"
  cat "$TMP/php_scan.lst" "$TMP/js_scan.lst" | sort -u > "$TMP/code_scan.lst"
  # The same lists without the files an earlier scan found clean and that have not changed (see cache.sh).
  # Name/permission checks keep using the full lists; only content passes read these *.c.lst files.
  if [ "${WPG_CACHE:-0}" = 1 ]; then cache_init; else : > "$TMP/clean.set"; CACHE_ON=0; fi
  cache_filter "$TMP/php_scan.lst" > "$TMP/php_scan.c.lst"
  cache_filter "$TMP/js_scan.lst" > "$TMP/js_scan.c.lst"
  cat "$TMP/php_scan.c.lst" "$TMP/js_scan.c.lst" | sort -u > "$TMP/code_scan.c.lst"
  awk -F'\t' '$3 < 8000000 {print $1}' "$INV" > "$TMP/ioc.all.lst"
  cache_filter "$TMP/ioc.all.lst" > "$TMP/ioc.c.lst"
}

inventory_run() {
  progress "phase 0: inventory and official checksums"
  mkdir -p "$TMP/pv"
  local verify=0
  if [ "$NOWP" = 0 ] && { should_run integrity || should_run php; }; then
    verify=1
    ( T 120 $WP plugin list --field=name 2>/dev/null > "$TMP/plug.names" ) &
  fi
  build_inventory
  wait
  # official checksums: wp-cli runs only for the core/plugins that changed since they last verified (cache.sh)
  if [ "$verify" = 1 ]; then verify_checksums; fi
  compute_trusted
  build_lists
}
