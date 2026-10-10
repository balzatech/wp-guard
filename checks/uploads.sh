# checks/uploads.sh
# Executables, polyglots, SVGs with script and double extensions in uploads.
# Worker: launched from lib/audit.sh. Only READS; reports with emit/lines/hits.

job_uploads() {
  [ -d wp-content/uploads ] || return 0
  awk -F'\t' '$1 ~ /^\.\/wp-content\/uploads\// {print $1}' "$INV" > "$TMP/up.lst"
  grep -iE '\.(php[0-9]?|phtml|phar|pht|phps|inc|shtml|cgi|pl|py|sh|asp|aspx|jsp|exe|so)$' "$TMP/up.lst" | grep -vE '/index\.php$' \
    | hits ALERT Uploads "Executable files inside uploads (there should be none)"
  grep -iE '\.(php[0-9]?|phtml|phar|pht)\.[a-z0-9]{1,6}$|\.(jpe?g|png|gif|ico|bmp|webp|pdf|txt|css|js|svg)\.(php[0-9]?|phtml|phar)$' "$TMP/up.lst" \
    | hits ALERT Uploads "Double extension (.php.jpg / .jpg.php)"
  grep -E '/(\.htaccess|\.user\.ini|php\.ini)$' "$TMP/up.lst" | lines WARN Uploads "Server configuration files inside uploads"
  # content passes read only new/changed files (names above and below are always checked on the full list)
  cache_filter "$TMP/up.lst" > "$TMP/up.c.lst"
  grep -iE '\.(jpe?g|png|gif|ico|bmp|webp|avif|pdf|mp3|mp4|txt|css|woff2?|ttf|zip|svg)$' "$TMP/up.c.lst" \
    | xargs -d '\n' -r -n 250 -P "$SCAN_PAR" grep -laE '<\?php' 2>/dev/null | hits ALERT Uploads "Image/document with PHP code inside (polyglot)"
  grep -iE '\.svg$' "$TMP/up.c.lst" | xargs -d '\n' -r -n 250 grep -laiE '<script|<foreignObject' 2>/dev/null | hits ALERT Uploads "SVG with <script> inside"
  grep -iE '\.svg$' "$TMP/up.c.lst" | xargs -d '\n' -r -n 250 grep -laiE 'onload=|onerror=|javascript:' 2>/dev/null | lines WARN Uploads "SVG with event handlers / javascript:"
  grep -iE '\.(js|mjs|html?)$' "$TMP/up.lst" | grep -vE '/index\.html$' | lines WARN Uploads "JS/HTML inside uploads"
  grep -E '/\.[^/]+$' "$TMP/up.lst" | grep -vE '/\.htaccess$' | lines WARN Uploads "Hidden files inside uploads"
  if ! grep -qsiE 'Require all denied|deny from all|php_flag engine off|RemoveHandler' wp-content/uploads/.htaccess; then
    emit WARN Uploads "uploads/.htaccess does not block PHP execution (add: <FilesMatch \"\\.(php|phtml|phar)\$\"> Require all denied </FilesMatch>)"
  fi
}
