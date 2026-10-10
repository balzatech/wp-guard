# checks/ioc.sh
# Known attacker markers (IOC_LIST) in contents and paths.
# Worker: launched from lib/audit.sh. Only READS; reports with emit/lines/hits.

job_ioc() {
  xargs -a "$TMP/ioc.c.lst" -d '\n' -r -n 300 -P "$SCAN_PAR" grep -lIE -e "$IOC_RE" 2>/dev/null | hits ALERT IOC "Known attacker markers in files"
  awk -F'\t' '{print $1}' "$INV" | grep -iE "$IOC_RE" | hits ALERT IOC "Paths containing attacker markers"
}
