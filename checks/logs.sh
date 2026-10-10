# checks/logs.sh
# Access logs (if the host lets you read them over SSH).
# Worker: launched from lib/audit.sh. Only READS; reports with emit/lines/hits.

job_logs() {
  local LOGDIR="" d FILES
  for d in "$(dirname "$WP_PATH")/logs" "$HOME/logs" "$HOME/access-logs"; do [ -d "$d" ] && LOGDIR="$d" && break; done
  if [ -z "$LOGDIR" ]; then
    emit INFO Logs "No access logs found over SSH. Download them from your hosting panel to see how the attacker got in."
    return 0
  fi
  FILES=$(find "$LOGDIR" -type f \( -iname '*access*' -o -iname '*.log' -o -iname '*.gz' \) -mtime -45 2>/dev/null | head -n 60)
  if [ -z "$FILES" ]; then emit INFO Logs "Log folder $LOGDIR has no recent files."; return 0; fi
  emit INFO Logs "Logs analyzed: $(echo "$FILES" | wc -l) files in $LOGDIR (behind Cloudflare the IP will be Cloudflare's)"
  # shellcheck disable=SC2086
  zcat -f $FILES 2>/dev/null > "$TMP/access.all"
  grep -iE 'gallery-[0-9]{6,}|lndex\.php|SEO.Super.Tool|popkov|59na|swift-feeder|verifyidentitypc|js-injector' "$TMP/access.all" | head -n 15 | lines ALERT Logs "Requests to attack paths/IOCs"
  awk '$6=="\"POST" && $7 ~ /\/wp-content\/uploads\/.*\.(php|phtml|phar)/ {print $1" "$7}' "$TMP/access.all" | sort | uniq -c | sort -rn | lines ALERT Logs "POST requests to PHP files inside uploads"
  awk '($6=="\"GET" || $6=="\"POST") && $9==200 && $7 ~ /\/wp-content\/(uploads|cache|languages|upgrade)\/.*\.(php|phtml|phar)/ {print $1" "$6" "$7}' "$TMP/access.all" | sort | uniq -c | sort -rn | head -n 20 | lines ALERT Logs "200 responses from PHP in uploads/cache (webshell in use?)"
  grep -iE '(cmd|exec|shell|passwd|base64_decode|union(%20|\+)select|\.\./\.\./|etc/passwd|wget%20|curl%20)=?' "$TMP/access.all" | awk '{print $1" "$6" "$7" "$9}' | sort | uniq -c | sort -rn | head -n 15 | lines WARN Logs "Requests with injection/traversal patterns"
  awk '$6=="\"POST" && $7 ~ /\/wp-content\/(plugins|themes)\/.*\.php/ {print $7}' "$TMP/access.all" | sed 's/?.*//' | sort | uniq -c | sort -rn | lines INFO Logs "POST requests to plugin/theme PHP (most frequent; many are normal AJAX)" 10
  awk '$6=="\"POST" && $7 ~ /wp-login\.php/ && $9==302 {print $1}' "$TMP/access.all" | sort | uniq -c | sort -rn | lines INFO Logs "IPs with SUCCESSFUL login (POST wp-login.php returning 302). Do you recognize all of them?" 10
  awk '$6=="\"POST" && $7 ~ /wp-login\.php/ {print $1}' "$TMP/access.all" | sort | uniq -c | sort -rn | awk '$1 > 100' | head -n 10 | lines WARN Logs "IPs with more than 100 POSTs to wp-login.php (brute force)"
  awk '$6=="\"POST" && $7 ~ /xmlrpc\.php/ {print $1}' "$TMP/access.all" | sort | uniq -c | sort -rn | awk '$1 > 50' | head -n 10 | lines WARN Logs "IPs with more than 50 POSTs to xmlrpc.php"
}
