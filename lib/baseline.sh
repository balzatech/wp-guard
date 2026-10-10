# baseline.sh - fingerprint of the "clean" site.
# Single responsibility: compute and save the hash manifest and the installed versions.

make_manifest() {
  awk -F'\t' 'tolower($1) ~ /(\.(php|phtml|phar|inc|js|html?|svg|ini)|\/\.htaccess)$/ && $1 !~ /^\.\/wp-content\/(cache|litespeed|wflogs|upgrade|languages|bcf-fonts|uploads)\// && $1 !~ /wordfence-waf\.php$/ {print $1}' "$INV" \
    | xargs -d '\n' -r -n 200 -P "$WORKERS" sha256sum 2>/dev/null | sort -k2
}
make_versions() {
  [ "$NOWP" = 1 ] && return 0
  echo "core,wordpress,$($WP core version 2>/dev/null)"
  $WP plugin list --fields=name,version --format=csv 2>/dev/null | tail -n +2 | sed 's/^/plugin,/'
  $WP theme list  --fields=name,version --format=csv 2>/dev/null | tail -n +2 | sed 's/^/theme,/'
}
ver_of() { grep -m1 "^$2,$3," "$1" 2>/dev/null | cut -d, -f3-; }

baseline_save() {
  make_manifest > "$MAN_OLD"; make_versions > "$VER_OLD"
}
