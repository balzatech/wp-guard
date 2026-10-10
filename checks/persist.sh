# checks/persist.sh
# Persistence outside WordPress: cron, SSH keys, shell startup files, processes.
# Worker: launched from lib/audit.sh. Only READS; reports with emit/lines/hits.

job_persist() {
  local me; me=$(id -un 2>/dev/null)
  local bad='base64|eval|/tmp/|/dev/shm|nohup|python|perl|[[:space:]]nc[[:space:]]|ncat|socat|bash -i|mkfifo|xmrig|minerd'
  if command -v crontab >/dev/null 2>&1; then
    local ct; ct=$(crontab -l 2>/dev/null | grep -vE '^[[:space:]]*(#|$)')
    if [ -n "$ct" ]; then
      printf '%s\n' "$ct" | grep -iE "$bad" | hits ALERT Persistence "Cron job with suspicious commands (scheduled re-infection)"
      printf '%s\n' "$ct" | grep -iE 'curl|wget' | grep -vF "$SITE_HOST" | lines WARN Persistence "Cron job that downloads something from the internet"
      printf '%s\n' "$ct" | lines INFO Persistence "User's cron jobs (do you recognize all of them?)" 20
    fi
  fi
  if [ -f "$HOME/.ssh/authorized_keys" ]; then
    if command -v ssh-keygen >/dev/null 2>&1; then ssh-keygen -lf "$HOME/.ssh/authorized_keys" 2>/dev/null; else cut -c1-60 "$HOME/.ssh/authorized_keys"; fi \
      | lines INFO Persistence "Authorized SSH keys (do you recognize all of them? a foreign key = permanent access)"
  fi
  local rc
  for rc in .bashrc .bash_profile .profile .bash_login .bash_logout .zshrc .zprofile; do
    [ -f "$HOME/$rc" ] && grep -nEi "curl|wget|base64|eval|/tmp/|/dev/shm|python -c|perl -e|nohup|bash -i|mkfifo" "$HOME/$rc" 2>/dev/null | sed "s#^#$rc:#" | cut -c1-160 | hits ALERT Persistence "Suspicious commands in shell startup files"
  done
  local cfg
  for cfg in "$HOME/.wp-cli/config.yml" "$WP_PATH/wp-cli.yml" "$WP_PATH/wp-cli.local.yml" "$WP_PATH/../wp-cli.yml"; do
    [ -f "$cfg" ] && grep -nE '^[[:space:]]*(require|-)[[:space:]]*:?.*\.php' "$cfg" 2>/dev/null | sed "s#^#$cfg:#" | hits ALERT Persistence "wp-cli loads PHP code on every run (config)"
  done
  find "$HOME" -maxdepth 4 \( -path "$HOME/domains/*/public_html" -o -path "$HOME/.wp_auditor" -o -path "$WPG_HOME" -o -path "$HOME/.cache" -o -path "$HOME/.npm" -o -path "$HOME/.composer" -o -path "$HOME/.wp-cli/cache" -o -path "$HOME/.local" \) -prune \
    -o -type f \( -name '*.php' -o -name '*.sh' -o -name '*.pl' -o -name '*.py' -o -name '*.cgi' \) -mtime -90 -print 2>/dev/null | grep -vE "^$TMP|/\.cagefs/tmp/|/wpa\.[A-Za-z0-9]{6}/" | lines WARN Persistence "Scripts outside public_html (last 90 days)"
  local td
  for td in /tmp /var/tmp "$HOME/tmp" /dev/shm; do
    [ -d "$td" ] && find "$td" -maxdepth 2 -user "$me" -type f \( -perm -u+x -o -name '*.php' -o -name '*.sh' -o -name '*.pl' -o -name '*.py' \) ! -path "$TMP/*" 2>/dev/null
  done | lines WARN Persistence "Executables/scripts in temporary folders"
  if command -v ps >/dev/null 2>&1; then
    ps -u "$me" -o pid=,etime=,args= 2>/dev/null | awk '$2 ~ /-/ || $2 ~ /^[0-9]+:[0-9]+:[0-9]+$/' | grep -vE 'sshd|-bash|/bash|lsphp|php-fpm|lshttpd|litespeed|wp_auditor|ps -u' > "$TMP/ps.txt"
    grep -iE 'xmrig|minerd|cpuminer|kdevtmpfsi|kinsing|/tmp/|/dev/shm|[[:space:]]nc[[:space:]]|ncat|socat|bash -i' "$TMP/ps.txt" | hits ALERT Persistence "Suspicious long-running processes"
    lines INFO Persistence "Long-running processes of your user" 15 < "$TMP/ps.txt"
  fi
}
