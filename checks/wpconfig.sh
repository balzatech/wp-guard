# checks/wpconfig.sh
# wp-config.php: injected code, security constants, permissions.
# Worker: launched from lib/audit.sh. Only READS; reports with emit/lines/hits.

job_wpconfig() {
  local f=wp-config.php k perm
  head -c 5 "$f" | grep -q '^<?php' || emit ALERT wp-config "wp-config.php does not start with <?php (there is content before it)"
  grep -nEi 'eval[[:space:]]*\(|base64_decode|gzinflate|str_rot13|\$_(GET|POST|REQUEST|COOKIE)|curl_exec|file_get_contents[[:space:]]*\([[:space:]]*.https?' "$f" | cut -c1-160 | lines ALERT wp-config "Suspicious code in wp-config.php"
  grep -nE '^[[:space:]]*(include|require)(_once)?' "$f" | grep -v 'wp-settings.php' | cut -c1-160 | lines WARN wp-config "wp-config.php includes other files (confirm which)"
  awk '/wp-settings\.php/ {f=1; next} f && NF {print NR ": " $0}' "$f" | cut -c1-160 | lines ALERT wp-config "Code AFTER loading wp-settings.php"
  grep -q 'put your unique phrase here' "$f" && emit WARN wp-config "wp-config.php still has the default keys/salts"
  grep -qE "define\([[:space:]]*['\"]WP_ALLOW_REPAIR['\"][[:space:]]*,[[:space:]]*true" "$f" && emit WARN wp-config "WP_ALLOW_REPAIR is enabled (repair.php works without login)"
  for k in DISALLOW_FILE_EDIT FORCE_SSL_ADMIN; do
    grep -qE "define\([[:space:]]*['\"]${k}['\"][[:space:]]*,[[:space:]]*true" "$f" || emit WARN wp-config "wp-config.php: $k is not enabled"
  done
  grep -qE "define\([[:space:]]*['\"]WP_DEBUG['\"][[:space:]]*,[[:space:]]*true" "$f" && emit WARN wp-config "WP_DEBUG is enabled in production"
  perm=$(stat -c %a "$f" 2>/dev/null)
  case "$perm" in 600|640|644) emit INFO wp-config "wp-config.php permissions: $perm (ideally 600/640 if the host allows it)" ;; *) emit ALERT wp-config "Unusual wp-config.php permissions: $perm" ;; esac
}
