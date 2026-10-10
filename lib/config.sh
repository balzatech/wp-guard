# shellcheck disable=SC2034  # shared state: assigned here, read by the modules and commands that source this file
# config.sh - parameters: command-line options, defaults and ~/.wp_auditor/config.sh.
# Single responsibility: decide WHICH PARAMETERS the run uses. It executes nothing on the site.

VERSION=$(tr -d '[:space:]' < "$WPG_HOME/VERSION" 2>/dev/null); VERSION=${VERSION:-unknown}   # single source of truth: the VERSION file

# shellcheck disable=SC1091
. "$WPG_HOME/lib/detect.sh"

# Common options. Whatever is not an option is left in WPG_ARGS. Exits with 64 on an unknown option.
wpg_parse() {
  APPLY=0; YES=${YES:-0}; WPG_ARGS=()
  FORCE_FULL=0; CLI_CPU=""; CLI_WORKERS=""; CLI_SKIP=""; CLI_ONLY=""; CLI_PATH=""; CLI_SITE=""; FORMAT=text
  while [ $# -gt 0 ]; do
    case "$1" in
      --format) FORMAT=${2:-}; shift
                case $FORMAT in text|json) ;; *) echo "Unknown format '$FORMAT' (use text or json)" >&2; exit 64 ;; esac ;;
      -w|--workers) CLI_WORKERS=${2:-}; shift ;;
      --cpu) CLI_CPU=${2:-}; shift
             case $CLI_CPU in ''|*[!0-9]*) echo "--cpu needs a number (percent of one core, 0 = no limit)" >&2; exit 64 ;; esac ;;
      --fast) CLI_CPU=0 ;;
      --full) FORCE_FULL=1 ;;
      --skip) CLI_SKIP=${2:-}; shift ;;
      --only) CLI_ONLY=${2:-}; shift ;;
      --path) CLI_PATH=${2:-}; shift ;;
      --site) CLI_SITE=${2:-}; shift ;;
      --apply) APPLY=1 ;;
      -y|--yes) YES=1 ;;
      -h|--help) wpg_usage; exit 0 ;;
      -*) echo "Unknown option: $1" >&2; wpg_usage >&2; exit 64 ;;
      *) WPG_ARGS+=("$1") ;;
    esac
    shift
  done
}

# Print the comment block of the running command (line 2 up to the first blank line)
wpg_usage() {
  sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
  cat <<'USAGE'
Common options:
  --full            re-read every file (ignore the incremental cache)
  --cpu N           CPU limit, percent of one core (default 50; 0 = unlimited)   --fast   same as --cpu 0
  -w, --workers N   parallel jobs (default 3)
  --skip a,b        skip groups        --only a,b   run only those groups
  --path DIR        site folder        --site URL   public URL
  --format FMT      text (default) or json   (scan: JSON on stdout, nothing else)
  Groups: php js ioc uploads structure htaccess wpconfig plugins integrity persist othersites db http probes logs
Configuration: environment variables or ~/.wp_auditor/config.sh   False positives: ~/.wp_auditor/allow.txt
USAGE
}

# wpg_conf_set KEY VALUE -> write KEY=VALUE (shell-quoted) into $STATE/config.sh, replacing any previous KEY.
# An empty VALUE just removes the key. Other lines of the file are kept untouched.
wpg_conf_set() {
  local f="$STATE/config.sh" t="$STATE/config.sh.tmp.$$"
  { [ -f "$f" ] && grep -v "^$1=" "$f"; [ -n "$2" ] && printf '%s=%q\n' "$1" "$2"; true; } > "$t" && mv "$t" "$f"
  chmod 600 "$f" 2>/dev/null
}

# wpg_ask "question" default -> answer in $REPLY. Non-interactive (or YES=1): takes the default.
wpg_ask() {
  if [ "${YES:-0}" = 1 ] || [ ! -t 0 ]; then REPLY=$2; return; fi
  read -r -p "$1${2:+ [$2]} " REPLY; REPLY=${REPLY:-$2}
}

wpg_load_config() {
  # cron starts with a minimal PATH: add the usual wp-cli locations
  export PATH="$PATH:/usr/local/bin:/usr/local/sbin:/opt/bin:$HOME/bin:$HOME/.local/bin:$HOME/.wp-cli/bin"
  STATE="${WPA_STATE:-$HOME/.wp_auditor}"
  mkdir -p "$STATE/reports" && chmod 700 "$STATE" 2>/dev/null
  # shellcheck disable=SC1091
  [ -f "$STATE/config.sh" ] && . "$STATE/config.sh"

  : "${WP_PATH:=}"                            # empty = auto-detect (see lib/detect.sh)
  : "${SITE:=}"                               # empty = read from WordPress (siteurl)
  : "${ALLOWED_ADMINS:=}"                     # allowed admin logins (comma/space); 'wp-guard init' fills it in
  : "${EXPECTED_ADMIN_EMAIL:=}"               # if set, alert when admin_email changes
  : "${RECENT_DAYS:=3}"                       # window for "new/modified files"
  : "${CPU_LIMIT:=50}"                        # max CPU, % of ONE core (50 = half a core, 0 = unlimited / --fast)
  : "${INCREMENTAL:=1}"                       # 1 = only read files that are new or changed since the last clean scan
  : "${FULL_SCAN_DAYS:=7}"                    # ...but re-read everything at least this often (--full forces it)
  : "${WORKERS:=3}"                           # parallel jobs
  : "${SCAN_PAR:=1}"                          # parallel grep inside each job
  : "${HTTP_PAR:=4}"                          # parallel downloads
  : "${DB_SHARDS:=2}"                         # processes used to scan the database
  : "${DB_TIMEOUT:=900}"
  : "${MIN_AGE_MIN:=30}"                      # fix: leave files newer than this alone (avoids fighting updates)
  : "${MAX_HEAL:=25}"                         # fix: if there are more targets than this, touch nothing and warn
  : "${MAX_PAGES:=40}"
  : "${CLUSTER_SECS:=120}"                    # window for "files modified together with a finding"
  : "${OTHER_SITES:=1}"                       # scan other sites of the same account
  : "${HTTP_LANG:=en-US,en;q=0.9}" "${HTTP_LANG_ALT:=es-ES,es;q=0.9}"   # Accept-Language values used by the cloaking checks
  : "${ORIGIN_IP:=}"                          # hosting IP: bypasses Cloudflare in the HTTP tests
  : "${IGNORE_LOCS:=}"                        # reviewed database rows, e.g. "wp_aioseo_notifications.content#8"
  : "${ALLOW_RE:=/wp-content/wflogs/|/pixelyoursite/modules/facebook/facebook-server-async-task\.php}"
  : "${NOTIFY_EMAIL:=}" "${TELEGRAM_BOT_TOKEN:=}" "${TELEGRAM_CHAT_ID:=}"
  : "${SLACK_WEBHOOK_URL:=}" "${DISCORD_WEBHOOK_URL:=}" "${NTFY_URL:=}" "${NTFY_TOKEN:=}"
  # legacy pair WEBHOOK_URL + WEBHOOK_KIND=slack|discord (older configs): map it onto the per-channel settings
  : "${WEBHOOK_URL:=}" "${WEBHOOK_KIND:=slack}"
  if [ -n "$WEBHOOK_URL" ]; then
    case "$WEBHOOK_KIND" in
      discord) [ -n "$DISCORD_WEBHOOK_URL" ] || DISCORD_WEBHOOK_URL=$WEBHOOK_URL ;;
      *) [ -n "$SLACK_WEBHOOK_URL" ] || SLACK_WEBHOOK_URL=$WEBHOOK_URL ;;
    esac
  fi
  : "${KNOWN_HOSTS:=google.com google-analytics.com googletagmanager.com googleapis.com gstatic.com googleusercontent.com doubleclick.net facebook.net facebook.com cloudflare.com cloudflareinsights.com youtube.com youtube-nocookie.com youtu.be vimeo.com wordpress.org w.org wp.com gravatar.com elementor.com jsdelivr.net hostinger.com w3.org schema.org instagram.com whatsapp.com wa.me linkedin.com x.com twitter.com tiktok.com}"
  : "${IOC_LIST:=popkov-01 59na.com js-injector __jsInjector rzb0JV4U verifyidentitypc}"
  : "${KNOWN_MU:=hostinger-auto-updates.php hostinger-preview-domain.php index.php}"
  : "${ROOT_CORE_PHP:=index.php wp-activate.php wp-blog-header.php wp-comments-post.php wp-cron.php wp-links-opml.php wp-load.php wp-login.php wp-mail.php wp-settings.php wp-signup.php wp-trackback.php xmlrpc.php}"
  : "${ROOT_PHP_OK:=$ROOT_CORE_PHP wp-config.php wp-config-sample.php}"

  [ -n "$CLI_CPU" ] && CPU_LIMIT=$CLI_CPU
  [ -n "$CLI_WORKERS" ] && WORKERS=$CLI_WORKERS
  [ -n "$CLI_PATH" ] && WP_PATH=$CLI_PATH
  [ -n "$CLI_SITE" ] && SITE=$CLI_SITE
  if [ -z "$WP_PATH" ]; then WP_PATH=$(wpg_detect_wp_path) || exit 1; fi
  if [ -z "$SITE" ]; then SITE=$(wpg_wp_site_url "$WP_PATH"); fi
  [ -n "$SITE" ] || { echo "wp-guard: cannot determine the site URL. Pass --site URL or set SITE in $STATE/config.sh." >&2; exit 1; }
  [ -f "$STATE/config.sh" ] || echo "wp-guard: no configuration yet. Run 'wp-guard init' for a guided setup." >&2
  SKIP=${CLI_SKIP:-${SKIP:-}}; ONLY=${CLI_ONLY:-${ONLY:-}}
  case "$WORKERS" in ''|*[!0-9]*) WORKERS=4 ;; esac
  [ "$WORKERS" -lt 1 ] && WORKERS=1
  SITE=${SITE%/}
  SITE_HOST=${SITE#*//}; SITE_HOST=${SITE_HOST%%/*}
  KNOWN_HOSTS="$KNOWN_HOSTS ${SITE_HOST#www.}"
  # shellcheck disable=SC2086
  KNOWN_RE='(^|\.)('$(printf '%s\n' $KNOWN_HOSTS | sed 's/\./\\./g' | paste -sd'|' -)')$'
  # shellcheck disable=SC2086
  IOC_RE=$(printf '%s\n' $IOC_LIST | sed 's/[][\.*^$(){}?+|/]/\\&/g' | paste -sd'|' -)
  export ALLOWED_ADMINS EXPECTED_ADMIN_EMAIL KNOWN_HOSTS IOC_LIST IGNORE_LOCS RECENT_DAYS
  export SITE_URL="$SITE" WP_PATH
  : "${RULES_DIR:=$WPG_HOME/rules}"
  PHP_RULES=$(cat "$RULES_DIR/php.rules" 2>/dev/null)
  JS_RULES=$(cat "$RULES_DIR/js.rules" 2>/dev/null)
  [ -n "$PHP_RULES" ] || { echo "No rules found in $RULES_DIR" >&2; exit 1; }
  MAN_OLD="$STATE/manifest.txt"; VER_OLD="$STATE/versions.txt"
}
