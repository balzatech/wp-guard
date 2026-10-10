# checks/integrity.sh
# Official checksums and comparison against the baseline.
# Worker: launched from lib/audit.sh. Only READS; reports with emit/lines/hits.

job_integrity() {
  if [ "$NOWP" = 1 ]; then emit WARN Integrity "wp-cli not available: no official checksums or version baseline"; return 0; fi
  if [ "${CORE_OK:-0}" = 1 ]; then
    grep -E '^Warning: .*(verify against checksum|should not exist)' "$TMP/core.vc" | sed 's/^Warning: //' | grep -v 'llms.txt' | hits ALERT Integrity "WordPress core modified or with extra files"
  else
    emit WARN Integrity "Could not verify the core checksums (no network or unofficial version): the whole core is scanned"
  fi
  if [ -s "$TMP/plug.bad" ]; then
    awk -F'\t' '{print $1 "  <- " $2}' "$TMP/plug.bad" | hits ALERT Integrity "Official plugins modified or with extra files (checksum mismatch)"
  fi
  if [ -s "$TMP/plug.unver" ]; then
    # shellcheck disable=SC2086
    printf '%s\n' $KNOWN_MU | sed 's/\.php$//' > "$TMP/known_mu_slug.lst"   # temp file: no <(...) (CageFS has no /dev/fd)
    grep -vxF -f "$TMP/known_mu_slug.lst" "$TMP/plug.unver" | lines WARN Integrity "Plugins WITHOUT official checksums (premium, nulled or custom: cannot be verified; a 'nulled' plugin is a typical re-infection vector)"
  fi
  # baseline with version tracking
  if [ ! -f "$MAN_OLD" ] || [ ! -f "$VER_OLD" ]; then
    emit INFO Integrity "No baseline yet, so no changes were compared. When you are SURE the site is clean, run: wp-guard baseline"
    return 0
  fi
  make_manifest > "$MAN_NEW"; make_versions > "$VER_NEW"
  awk -F'  ' '
    function comp(p,  a,n) {
      n=split(p,a,"/")
      if (a[2]=="wp-content") {
        if (a[3]=="plugins" && n>=5) return "plugin|" a[4]
        if (a[3]=="themes" && n>=5) return "theme|" a[4]
        if (a[3]=="mu-plugins") return "mu|mu-plugins"
        return "other|" p
      }
      if (a[2]=="wp-admin" || a[2]=="wp-includes") return "core|wordpress"
      if (n==2 && p ~ /^\.\/(index|wp-[a-z-]+|xmlrpc)\.php$/ && p != "./wp-config.php") return "core|wordpress"
      return "other|" p
    }
    NR==FNR { old[$2]=$1; next }
    { if (!($2 in old)) st[$2]="N"; else { if (old[$2]!=$1) st[$2]="M"; delete old[$2] } }
    END {
      for (p in old) st[p]="D"
      for (p in st) { c=comp(p); if (c ~ /^other\|/) print "OTHER\t" st[p] " " p; else cnt[c]++ }
      for (c in cnt) print "COMP\t" c "\t" cnt[c]
    }' "$MAN_OLD" "$MAN_NEW" > "$TMP/diff.out"
  local kind name n ov nv
  grep '^OTHER' "$TMP/diff.out" | cut -f2 | sort | lines ALERT Integrity "Files outside plugins/themes/core that changed since the baseline (N=new M=modified D=deleted)" 40
  grep '^COMP' "$TMP/diff.out" | while IFS=$'\t' read -r _ key n; do
    kind="${key%%|*}"; name="${key#*|}"
    if [ "$kind" = mu ]; then emit WARN Integrity "mu-plugins: $n files changed (may be a host update; review)"; continue; fi
    ov=$(ver_of "$VER_OLD" "$kind" "$name"); nv=$(ver_of "$VER_NEW" "$kind" "$name")
    if [ -z "$ov" ] && [ -z "$nv" ]; then emit ALERT Integrity "$kind '$name' changed ($n files) and WordPress does not recognize it as an installed $kind"
    elif [ -z "$ov" ]; then emit ALERT Integrity "$kind NEW since the baseline: $name ($n files). If you installed it, run 'baseline' once you have reviewed it"
    elif [ -z "$nv" ]; then emit INFO Integrity "$kind removed: $name"
    elif [ "$ov" != "$nv" ]; then emit INFO Integrity "$kind $name updated $ov -> $nv ($n files changed)"
    else emit ALERT Integrity "$kind $name: $n files changed WITHOUT a version change ($ov). It may have been tampered with"; fi
  done
}
