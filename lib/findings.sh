# findings.sh - findings model and worker pool.
# Single responsibility: record findings (LEVEL<TAB>CATEGORY<TAB>message) and launch parallel jobs.

# Each worker writes to its own file ($OUT): LEVEL<TAB>CATEGORY<TAB>message
# (newlines in the message are stored as \x1f)
emit() {
  local m=${3//$'\t'/ }; m=${m//$'\n'/$'\x1f'}
  printf '%s\t%s\t%s\n' "$1" "$2" "$m" >> "${OUT:-$FD/main.tsv}"
}
filter_allow() {
  local f; f=$(cat); [ -z "$f" ] && return 0
  [ -n "$ALLOW_RE" ] && f=$(printf '%s\n' "$f" | grep -vE "$ALLOW_RE")
  [ -s "$ALLOW_FILE" ] && f=$(printf '%s\n' "$f" | grep -vFf "$ALLOW_FILE")
  [ -n "$f" ] && printf '%s\n' "$f"
  return 0
}
# lines LEVEL CATEGORY "title" [max]   <- items on stdin, grouped into one finding
lines() {
  local body n max=${4:-25}
  body=$(filter_allow)
  [ -z "$body" ] && return 0
  printf '%s\n' "$body" >> "${OUT:-$FD/main.tsv}.matched"   # every reported path: the incremental cache must never treat these files as clean
  n=$(printf '%s\n' "$body" | wc -l)
  [ "$1" = ALERT ] && [ -n "${FLAG:-}" ] && printf '%s\n' "$body" >> "${OUT:-$FD/main.tsv}.flagged"
  [ -n "${STRIP:-}" ] && body=$(printf '%s\n' "$body" | sed "s#$STRIP##")
  body=$(printf '%s\n' "$body" | head -n "$max" | cat -v | sed 's/^/      /' | paste -sd $'\x1f' -)
  [ "$n" -gt "$max" ] && body+=$'\x1f'"      ... (+$((n - max)) more)"
  emit "$1" "$2" "$3 ($n)"$'\x1f'"$body"
}
hits() { FLAG=1 lines "$@"; }   # same as lines, but keeps the paths for the evidence
should_run() {
  local g=$1
  case "$MODE" in
    quick) case $g in db|http|probes|logs) return 1 ;; esac ;;
    watch) [ "$g" = logs ] && return 1 ;;
  esac
  if [ -n "$ONLY" ]; then case ",$ONLY," in *",$g,"*) return 0 ;; esac; return 1; fi
  case ",$SKIP," in *",$g,"*) return 1 ;; esac
  return 0
}
# spawn GROUP NAME function [args]  <- launch a worker respecting the WORKERS limit
spawn() {
  local grp=$1 name=$2; shift 2
  should_run "$grp" || return 0
  while [ "$(jobs -rp | wc -l)" -ge "$WORKERS" ]; do sleep 0.2; done
  (
    OUT="$FD/$name.tsv"; : > "$OUT"; t0=$SECONDS
    "$@"
    echo "$name $((SECONDS - t0))" >> "$FD/_timing"
    progress "ok  $name ($((SECONDS - t0))s)"
  ) &
}
