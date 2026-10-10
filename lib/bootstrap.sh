# bootstrap.sh - common entry point of the commands (bin/*).
# Single responsibility: require bash>=4, leave a useful PATH for cron and load modules with wpg_use.

if [ "${BASH_VERSINFO[0]:-0}" -lt 4 ]; then echo "bash 4 or newer is required." >&2; exit 1; fi

# cron starts with a minimal PATH: add the usual wp-cli locations
export PATH="$PATH:/usr/local/bin:/usr/local/sbin:/opt/bin:$HOME/bin:$HOME/.local/bin:$HOME/.wp-cli/bin"

# wpg_use module...   -> load lib/<module>.sh (each command declares what it depends on)
wpg_use() {
  local m
  for m in "$@"; do
    # shellcheck disable=SC1090
    . "$WPG_HOME/lib/$m.sh" || { echo "Could not load lib/$m.sh" >&2; exit 1; }
  done
}
