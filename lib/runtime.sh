# shellcheck disable=SC2034  # shared state: assigned here, read by the modules and commands that source this file
# runtime.sh - execution environment.
# Single responsibility: check dependencies, enter the site, take the lock, create/clean the
# temp directory and prepare colors. It knows nothing about malware.

# shellcheck disable=SC1091
. "$WPG_HOME/lib/throttle.sh"

T() { if command -v timeout >/dev/null 2>&1; then timeout "$@"; else shift; "$@"; fi; }
cleanup() { throttle_stop; jobs -p 2>/dev/null | xargs -r kill 2>/dev/null; rm -rf "$TMP"; }

progress() { [ "$MODE" = full ] && echo "  $1" >&2; return 0; }

# wpg_init: gets everything ready. WPG_QUIET_LOCK=1 (cron) -> if another run is active, exit quietly with 0.
wpg_init() {
  local c
  for c in find awk grep sed sort xargs mktemp stat paste; do
    command -v "$c" >/dev/null 2>&1 || { echo "Missing command: $c" >&2; exit 1; }
  done
  NOWP=0; command -v wp >/dev/null 2>&1 || NOWP=1
  HAVE_CURL=1; command -v curl >/dev/null 2>&1 || HAVE_CURL=0
  cd "$WP_PATH" 2>/dev/null || { echo "Invalid path: $WP_PATH" >&2; exit 1; }
  [ -f wp-config.php ] || { echo "No wp-config.php in $WP_PATH" >&2; exit 1; }
  WP_PATH=$(pwd -P); export WP_PATH
  WP="wp --path=$WP_PATH --skip-plugins --skip-themes"

  # grep/awk in byte mode: without this, grep -i with long regexes is 5-20x slower (UTF-8 locale)
  export LC_ALL=C LANG=C

  # lowest priority: do not bother the host
  renice -n 19 -p $$ >/dev/null 2>&1
  command -v ionice >/dev/null 2>&1 && ionice -c3 -p $$ >/dev/null 2>&1

  # one wp-guard at a time (audit and remediation never overlap)
  if command -v flock >/dev/null 2>&1; then
    exec 9>"$STATE/lock"
    flock -n 9 || { [ "${WPG_QUIET_LOCK:-0}" = 1 ] && exit 0; echo "Another wp-guard is already running (lock: $STATE/lock)."; exit 0; }
  fi

  TMP=$(mktemp -d "${TMPDIR:-/tmp}/wpa.XXXXXX") || exit 1
  FD="$TMP/f"; mkdir -p "$FD"
  INV="$TMP/inventory.tsv"; TRUSTED="$TMP/trusted.lst"
  trap cleanup EXIT
  trap 'exit 130' INT TERM
  throttle_start

  MAN_NEW="$TMP/manifest.new"; VER_NEW="$TMP/versions.new"
  ALLOW_FILE="$TMP/allow.txt"
  [ -f "$STATE/allow.txt" ] && grep -vE '^[[:space:]]*(#|$)' "$STATE/allow.txt" > "$ALLOW_FILE" 2>/dev/null
  : >> "$ALLOW_FILE"
  export TMP INV TRUSTED

  CURL_EXTRA=""
  [ -n "$ORIGIN_IP" ] && CURL_EXTRA="--resolve ${SITE_HOST}:443:${ORIGIN_IP} --resolve ${SITE_HOST}:80:${ORIGIN_IP} -k"
  export CURL_EXTRA

  if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_R=$'\033[31m'; C_Y=$'\033[33m'; C_B=$'\033[36m'; C_G=$'\033[32m'; C_N=$'\033[0m'; C_BOLD=$'\033[1m'
  else C_R=""; C_Y=""; C_B=""; C_G=""; C_N=""; C_BOLD=""; fi
}
