# checks/plugins.sh
# Plugins/themes: fake folders, inactive ones, pending updates.
# Worker: launched from lib/audit.sh. Only READS; reports with emit/lines/hits.

job_plugins() {
  local d n names
  names="$TMP/plug.names"
  # plugin folders without a valid header / long numbers / not recognized
  for d in wp-content/plugins/*/; do
    [ -d "$d" ] || continue
    n=$(basename "$d")
    if [ -s "$names" ] && ! grep -qxF "$n" "$names"; then
      if find "$d" -type f -name '*.php' 2>/dev/null | grep -q .; then emit ALERT Plugins "Plugin folder NOT recognized by WordPress and containing PHP: $n"
      else emit WARN Plugins "Empty plugin folder or without a valid plugin: $n"; fi
    fi
    if find "$d" -maxdepth 1 -type f -name '*.php' 2>/dev/null | grep -q . && \
       ! { find "$d" -maxdepth 1 -type f -name '*.php' -print0 2>/dev/null | xargs -0 -r head -c 8192 2>/dev/null | grep -qi 'Plugin Name:'; }; then
      emit ALERT Plugins "Plugin without a 'Plugin Name:' header (not a real plugin, like the fake wp-js-injector): $n"
    fi
    echo "$n" | grep -qE -- '-[0-9]{6,}$' && emit ALERT Plugins "Plugin whose name ends in a long number (pattern of the fake plugin): $n"
  done
  find wp-content/plugins -maxdepth 1 -type f ! -name index.php ! -name hello.php 2>/dev/null | lines WARN Plugins "Stray files inside wp-content/plugins (single-file plugins)"
  # themes
  if [ "$NOWP" = 0 ]; then
    T 120 $WP theme list --field=name 2>/dev/null | sort > "$TMP/theme.names"
    for d in wp-content/themes/*/; do
      [ -d "$d" ] || continue; n=$(basename "$d")
      if [ -s "$TMP/theme.names" ] && ! grep -qxF "$n" "$TMP/theme.names" && find "$d" -type f -name '*.php' 2>/dev/null | grep -q .; then
        emit ALERT Plugins "Theme folder NOT recognized by WordPress and containing PHP: $n"
      fi
      [ -f "$d/style.css" ] || emit WARN Plugins "Theme without style.css: $n"
    done
    T 120 $WP plugin list --status=inactive --field=name 2>/dev/null | lines WARN Plugins "INACTIVE plugins (delete the ones you do not use: they can still be exploited)"
    T 180 $WP plugin list --update=available --field=name 2>/dev/null | lines WARN Plugins "Plugins with a pending update"
    T 180 $WP theme list --update=available --field=name 2>/dev/null | lines WARN Plugins "Themes with a pending update"
    T 120 $WP core check-update --field=version 2>/dev/null | grep -E '^[0-9]' | lines WARN Plugins "WordPress update available"
    T 60 $WP theme list --status=inactive --field=name 2>/dev/null | lines INFO Plugins "Inactive themes installed"
  else
    emit WARN Plugins "wp-cli not available: plugins/themes were not compared against WordPress"
  fi
}
