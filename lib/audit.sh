# shellcheck disable=SC2034  # shared state: assigned here, read by the modules and commands that source this file
# audit.sh - phase 1 + 2.
# Single responsibility: launch the checks (checks/*.sh) as workers, wait, correlate and leave
# the aggregated result in $TMP/all.tsv with the counters NA / NW / NI.

# shellcheck disable=SC1090  # the check files are discovered at run time
for _f in "$WPG_HOME"/checks/*.sh; do . "$_f"; done; unset _f

audit_run() {
  local i START=$SECONDS
  progress "phase 1: launching workers ($WORKERS in parallel)"
  # heaviest first
  for i in $(seq 0 $((DB_SHARDS - 1))); do spawn db "db$((i + 1))" job_db "$i" "$DB_SHARDS"; done
  spawn http http job_http
  spawn php php job_php
  spawn js js job_js
  spawn ioc ioc job_ioc
  spawn probes probes job_probes
  spawn integrity integrity job_integrity
  spawn plugins plugins job_plugins
  spawn structure structure job_structure
  spawn uploads uploads job_uploads
  spawn htaccess htaccess job_htaccess
  spawn wpconfig wpconfig job_wpconfig
  spawn persist persist job_persist
  spawn othersites othersites job_othersites
  [ "$MODE" = full ] && spawn logs logs job_logs
  wait
  cache_save

  progress "phase 2: correlation"
  correlate
  cat "$FD"/*.tsv 2>/dev/null > "$TMP/all.tsv"
  NA=$(awk -F'\t' '$1=="ALERT"' "$TMP/all.tsv" | sort -u | wc -l)
  NW=$(awk -F'\t' '$1=="WARN"' "$TMP/all.tsv" | sort -u | wc -l)
  NI=$(awk -F'\t' '$1=="INFO"' "$TMP/all.tsv" | sort -u | wc -l)
  DUR=$((SECONDS - START))
}

# exit code according to what was found: 2 alerts, 1 warnings, 0 clean
audit_exit_code() { [ "$NA" -gt 0 ] && return 2; [ "$NW" -gt 0 ] && return 1; return 0; }
