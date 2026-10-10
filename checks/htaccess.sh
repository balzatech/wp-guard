# checks/htaccess.sh
# .htaccess/.user.ini/php.ini: auto_prepend, redirects, handlers.
# Worker: launched from lib/audit.sh. Only READS; reports with emit/lines/hits.

job_htaccess() {
  find . \( -name .htaccess -o -name .user.ini -o -name php.ini -o -name .php.ini -o -name php5.ini \) -type f 2>/dev/null > "$TMP/ht.lst"
  [ -s "$TMP/ht.lst" ] || return 0
  xargs -a "$TMP/ht.lst" -d '\n' -r grep -HnEi -e 'auto_prepend_file' -e 'auto_append_file' 2>/dev/null | grep -vi 'wordfence-waf' \
    | hits ALERT htaccess "auto_prepend_file / auto_append_file (runs a PHP file before/after EVERY page)"
  xargs -a "$TMP/ht.lst" -d '\n' -r grep -HnEi -e 'RewriteCond[^#]*HTTP_REFERER[^#]*(google|bing|yahoo|yandex|duckduckgo)' -e 'ErrorDocument[[:space:]]+[0-9]+[[:space:]]+https?://' -e 'Options[^#]*ExecCGI' -e 'base64|eval\(' 2>/dev/null \
    | hits ALERT htaccess "Search-engine redirect rules / external ErrorDocument / ExecCGI / code"
  xargs -a "$TMP/ht.lst" -d '\n' -r grep -HnEi 'RewriteRule[^#]*https?://' 2>/dev/null \
    | KRE="$KNOWN_RE" awk -F: 'BEGIN{re=ENVIRON["KRE"]} { s=$0; if (match(s, /https?:\/\/[^\/ \t\]\[]+/)) { h=substr(s,RSTART,RLENGTH); sub(/^https?:\/\//,"",h); if (h ~ /^%\{/ || tolower(h) ~ re) next } print }' \
    | hits ALERT htaccess "RewriteRule to external domains"
  xargs -a "$TMP/ht.lst" -d '\n' -r grep -HnEi -e 'AddType[[:space:]]+application/x-httpd-php' -e 'AddHandler[^#]*(jpg|jpeg|png|gif|txt|ico|css|js)' -e 'SetHandler[[:space:]]+application/x-httpd-php' 2>/dev/null \
    | hits ALERT htaccess "Runs non-PHP files as PHP"
  xargs -a "$TMP/ht.lst" -d '\n' -r grep -HnEi -e 'AddHandler' -e 'SetHandler' -e 'php_value' -e 'php_flag' -e 'RewriteCond[^#]*HTTP_USER_AGENT[^#]*(google|bing|yahoo|bot|crawl|spider|mobile|android|iphone)' -e '^[[:space:]]*DirectoryIndex[[:space:]]+[^i[:space:]]' 2>/dev/null \
    | grep -vi 'wordfence-waf' | grep -viE 'SetHandler[[:space:]]+(none|default-handler)|php_flag[[:space:]]+engine[[:space:]]+off' | lines WARN htaccess "Directives worth confirming (AddHandler/SetHandler/php_value/UA/DirectoryIndex)"
  grep -E '/(uploads|cache|languages|upgrade|litespeed)/.*(\.htaccess)$' "$TMP/ht.lst" | xargs -d '\n' -r grep -LE 'LSCACHE|LiteSpeed' | xargs -d '\n' -r grep -HnEi -e 'Require all granted' -e 'Allow from all' -e 'Satisfy any' -e 'RewriteEngine' 2>/dev/null \
    | hits ALERT htaccess ".htaccess inside uploads/cache that ENABLES access or rewrites (typical way to re-enable webshells)"
  grep -vE '^\./(\.htaccess|\.user\.ini|wp-content/uploads/\.htaccess)$' "$TMP/ht.lst" | lines INFO htaccess "Other .htaccess / .user.ini / php.ini files in the site" 20
}
