# checks/probes.sh
# Exposure: sensitive files, headers, xmlrpc, sitemap.
# Worker: launched from lib/audit.sh. Only READS; reports with emit/lines/hits.

job_probes() {
  [ "$HAVE_CURL" = 1 ] || return 0
  local H="$TMP/probes"; mkdir -p "$H"
  local UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
  local n=0 blocked=0 code f
  probe() {  # path regex level description
    n=$((n + 1))
    # shellcheck disable=SC2086
    code=$(curl -s -m 15 -r 0-900 -A "$UA" $CURL_EXTRA -o "$H/p$n" -w '%{http_code}' "$SITE$1" 2>/dev/null)
    case "$code" in 403|429|503) blocked=$((blocked + 1)) ;; esac
    if [ "$code" = 200 ] || [ "$code" = 206 ]; then
      grep -aqE "$2" "$H/p$n" && emit "$3" Exposure "$SITE$1 is accessible: $4"
    fi
  }
  probe /.env '^[A-Z_]+=|DB_PASSWORD' ALERT ".env exposed"
  probe /.git/HEAD '^ref:' ALERT ".git repository exposed"
  probe /.htaccess 'RewriteEngine|<IfModule' ALERT ".htaccess readable from the internet"
  for f in wp-config.php.bak wp-config.bak wp-config.old wp-config.txt wp-config.php.save wp-config.php.orig wp-config.php~ wp-config.php.old; do
    probe "/$f" 'DB_(NAME|PASSWORD|USER)' ALERT "readable wp-config copy"
  done
  for f in phpinfo.php info.php test.php; do probe "/$f" 'phpinfo\(\)|PHP Version' ALERT "phpinfo exposed"; done
  probe /adminer.php 'Adminer|adminer' ALERT "Adminer exposed"
  for f in backup.sql db.sql dump.sql database.sql; do probe "/$f" 'CREATE TABLE|INSERT INTO|DROP TABLE' ALERT "SQL dump exposed"; done
  for f in backup.zip site.zip public_html.zip www.zip wordpress.zip; do probe "/$f" '^PK' ALERT "compressed backup exposed"; done
  probe /wp-content/debug.log 'PHP (Warning|Fatal|Notice|Deprecated)|Stack trace' WARN "debug.log readable (reveals paths and errors)"
  probe /error_log 'PHP (Warning|Fatal|Notice|Deprecated)|Stack trace' WARN "error_log readable"
  probe /wp-content/uploads/ 'Index of' WARN "directory listing is open"
  probe /wp-content/plugins/ 'Index of' WARN "directory listing is open"
  probe /readme.html 'WordPress' WARN "readme.html reveals the WordPress version"
  probe /wp-json/wp/v2/users '"slug"' WARN "the REST API lists users (lets attackers discover logins)"
  # xmlrpc
  # shellcheck disable=SC2086
  code=$(curl -s -o /dev/null -m 20 -A "$UA" $CURL_EXTRA -w '%{http_code}' "$SITE/xmlrpc.php" 2>/dev/null)
  { [ "$code" = 200 ] || [ "$code" = 405 ]; } && emit WARN Exposure "xmlrpc.php is accessible (HTTP $code): brute force/pingback"
  # author enumeration
  local fin
  # shellcheck disable=SC2086
  fin=$(curl -sL -m 20 -A "$UA" $CURL_EXTRA -o /dev/null -w '%{url_effective}' "$SITE/?author=1" 2>/dev/null)
  echo "$fin" | grep -q '/author/' && emit WARN Exposure "/?author=1 reveals the author's login ($fin)"
  # headers
  local HDRS
  # shellcheck disable=SC2086
  HDRS=$(curl -sI -m 20 -A "$UA" $CURL_EXTRA "$SITE/" 2>/dev/null)
  for f in x-content-type-options x-frame-options referrer-policy; do echo "$HDRS" | grep -qi "^$f:" || emit WARN Exposure "Missing security header $f"; done
  for f in strict-transport-security content-security-policy permissions-policy; do echo "$HDRS" | grep -qi "^$f:" || emit INFO Exposure "Missing header $f (recommended hardening)"; done
  echo "$HDRS" | grep -iE '^(x-powered-by|server):' | tr -d '\r' | lines INFO Exposure "Headers that reveal technology"
  # http -> https
  # shellcheck disable=SC2086
  code=$(curl -s -o /dev/null -m 20 -A "$UA" $CURL_EXTRA -w '%{http_code}' "http://$SITE_HOST/" 2>/dev/null)
  case "$code" in 301|302|307|308) ;; 000) ;; *) emit WARN Exposure "http://$SITE_HOST/ does not redirect to https (HTTP $code)" ;; esac
  # robots.txt: foreign sitemaps
  # shellcheck disable=SC2086
  curl -s -m 20 -A "$UA" $CURL_EXTRA "$SITE/robots.txt" 2>/dev/null | grep -iE '^sitemap:' | sed -E 's/^[Ss]itemap:[[:space:]]*//' | tr -d '\r' | while read -r s; do
    h=${s#*//}; h=${h%%/*}; [ "${h#www.}" != "${SITE_HOST#www.}" ] && emit ALERT Exposure "robots.txt points to a sitemap on ANOTHER domain: $s"
  done
  # bloated sitemap (SEO spam)
  local SM SUBS total pub s c
  # shellcheck disable=SC2086
  SM=$(curl -sL -m 20 -A "$UA" $CURL_EXTRA "$SITE/sitemap.xml" 2>/dev/null)
  SUBS=$(echo "$SM" | grep -oE '<loc>[^<]+\.xml[^<]*</loc>' | sed -E 's#</?loc>##g' | head -n 10)
  if [ -z "$SUBS" ]; then total=$(echo "$SM" | grep -c '<loc>')
  else total=0; for s in $SUBS; do
    # shellcheck disable=SC2086
    c=$(curl -sL -m 20 -A "$UA" $CURL_EXTRA "$s" 2>/dev/null | grep -o '<loc>' | wc -l); total=$((total + c)); done; fi
  [ "$NOWP" = 1 ] || pub=$(T 60 $WP post list --post_type=page,post --post_status=publish --format=count 2>/dev/null)
  emit INFO Exposure "Sitemap: ${total:-0} URLs listed | published content (pages+posts): ${pub:-?}"
  [ -n "${pub:-}" ] && [ "${total:-0}" -gt $(( pub * 2 + 10 )) ] && emit WARN Exposure "The sitemap lists many more URLs ($total) than published content ($pub): possible SEO spam"
  [ "$blocked" -gt 3 ] && emit INFO Exposure "$blocked probes received 403/429/503 (Cloudflare/WAF): results may be incomplete; set ORIGIN_IP"
}
