# detect.sh - WordPress discovery.
# Single responsibility: find WordPress installations on this machine and read basic facts from them
# (site URL, administrators). It never modifies anything.

# wpg_find_wp: print one WordPress root per line (directories containing wp-config.php).
# Search order: current directory and its parents, then the usual hosting layouts.
wpg_find_wp() {
  local d seen=""
  d=$PWD
  while [ "$d" != "/" ] && [ -n "$d" ]; do
    if [ -f "$d/wp-config.php" ]; then echo "$d"; seen=$d; break; fi
    d=$(dirname "$d")
  done
  for d in "$HOME"/public_html "$HOME"/domains/*/public_html "$HOME"/htdocs "$HOME"/www \
           /var/www/html /var/www/*/public_html /var/www/*/htdocs /var/www/vhosts/*/httpdocs /srv/www/*; do
    [ -f "$d/wp-config.php" ] && [ "$d" != "$seen" ] && echo "$d"
  done | awk '!s[$0]++'
}

# wpg_detect_wp_path: print the WordPress root to use; fail with a helpful message if it is ambiguous.
wpg_detect_wp_path() {
  local list n
  list=$(wpg_find_wp | awk '!s[$0]++'); n=$(printf '%s' "$list" | grep -c .)
  if [ "$n" -eq 1 ]; then printf '%s\n' "$list"; return 0; fi
  if [ "$n" -eq 0 ]; then
    echo "wp-guard: no WordPress installation found. Run it inside your site folder, pass --path DIR, or set WP_PATH." >&2
  else
    echo "wp-guard: several WordPress installations found. Pick one with --path DIR (or run 'wp-guard init'):" >&2
    printf '  %s\n' $list >&2
  fi
  return 1
}

# wpg_wp_site_url PATH: the site's public URL according to WordPress itself (empty if wp-cli is unavailable).
wpg_wp_site_url() {
  command -v wp >/dev/null 2>&1 || return 0
  if command -v timeout >/dev/null 2>&1; then
    timeout 30 wp --path="$1" --skip-plugins --skip-themes option get siteurl 2>/dev/null
  else
    wp --path="$1" --skip-plugins --skip-themes option get siteurl 2>/dev/null
  fi
}

# wpg_wp_admins PATH: logins of the current administrators, one per line.
wpg_wp_admins() {
  command -v wp >/dev/null 2>&1 || return 0
  wp --path="$1" --skip-plugins --skip-themes user list --role=administrator --field=user_login 2>/dev/null
}

# wpg_wp_admin_email PATH
wpg_wp_admin_email() {
  command -v wp >/dev/null 2>&1 || return 0
  wp --path="$1" --skip-plugins --skip-themes option get admin_email 2>/dev/null
}
