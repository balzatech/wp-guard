# checks/php.sh
# Webshell/obfuscation signatures in PHP, look-alike file names and giant lines.
# Worker: launched from lib/audit.sh. Only READS; reports with emit/lines/hits.

job_php() {
  scan_rules "$TMP/php_scan.c.lst" "PHP signatures" "$PHP_RULES"
  # giant lines (minified/obfuscated code)
  grep -vE '\.l10n\.php$' "$TMP/php_scan.c.lst" > "$TMP/php_long.lst"
  xargs -a "$TMP/php_long.lst" -d '\n' -r -n 100 -P "$SCAN_PAR" awk 'length($0) > 4000 && !s[FILENAME]++ {print FILENAME}' 2>/dev/null \
    | sort -u | lines WARN "PHP signatures" "PHP with lines of 4000+ characters (minified/obfuscated)"
  grep -iE '/(wp-vcd|wp-tmp|wp-feed|class\.theme-modules|xmrlpc|wp-conflg|wso|c99|r57|b374k|alfa|bypass|marijuana|leafmailer|indoxploit|lndex|1ndex|ind3x|0x[0-9a-f]+)\.php[0-9]?$' "$TMP/php_scan.lst" \
    | hits ALERT "PHP signatures" "Files named like a typical webshell or a WordPress look-alike"
  grep -iE '/(shell|cmd|mailer|uploader|upfile|adminer[^/]*|filemanager|tinyfilemanager|elfinder)\.php[0-9]?$' "$TMP/php_scan.lst" \
    | lines WARN "PHP signatures" "Files named like a file manager / shell (confirm they are legitimate)"
  grep -E '/\.[^/]+\.(php[0-9]?|phtml|phar|inc)$' "$TMP/php_all.lst" | grep -vE '/\.phpstorm\.meta\.php$' | hits ALERT "PHP signatures" "PHP with a hidden name (starts with a dot)"
}
