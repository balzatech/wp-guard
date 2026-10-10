# checks/db.sh
# Database: users, roles, options, injections (SQL/PHP in lib/php/db_scan.php).
# Worker: launched from lib/audit.sh. Only READS; reports with emit/lines/hits.

job_db() {  # shard shards
  if [ "$NOWP" = 1 ]; then [ "$1" = 0 ] && emit WARN "Database" "wp-cli not available: the database was not checked"; return 0; fi
  local bad=0
  SHARD=$1 SHARDS=$2 T "$DB_TIMEOUT" $WP eval-file "$WPG_HOME/lib/php/db_scan.php" 2>&1 | while IFS=$'\t' read -r lvl txt; do
    case "$lvl" in
      ALERT|WARN|INFO) emit "$lvl" "Database" "$txt" ;;
      *) [ -n "$lvl$txt" ] && [ "$bad" -lt 5 ] && { bad=$((bad + 1)); emit WARN "Database" "Unexpected database output: $lvl $txt"; } ;;
    esac
  done
}
