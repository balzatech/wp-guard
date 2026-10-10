# notify.sh - alerts.
# Single responsibility: deliver a text to every configured channel (Slack, Discord, ntfy, Telegram, email).
# Each channel has its own length limit: the text is cut by whole lines.
# After notify(): NOTIFY_SENT = channels that accepted it, NOTIFY_FAILED = channels that failed.
# A failure is printed on stderr and logged in $STATE/notify.log (never with the URL or tokens).
# NOTIFY_ONLY=slack|discord|ntfy|telegram|email restricts delivery to one channel (used by the setup wizard).

# notify_trim LIMIT <text on stdin>  -> cut at a line boundary and say so
notify_trim() {
  awk -v lim="$1" '{ if (n + length($0) + 1 > lim) { cut = 1; exit } print; n += length($0) + 1 } END { if (cut) print "... (truncated; full report on the server)" }'
}

# notify_json  -> escape stdin as the content of a JSON string (no real newlines)
notify_json() {
  tr '\t' ' ' | tr -d '\000-\010\013\014\016-\037' | sed 's/\\/\\\\/g; s/"/\\"/g' | awk '{ printf "%s\\n", $0 }'
}

# notify_log CHANNEL CODE [response]
notify_log() {
  NOTIFY_FAILED=$((NOTIFY_FAILED + 1))
  echo "wp-guard: the $1 notification FAILED (HTTP $2)" >&2
  printf '%s %s HTTP %s %s\n' "$(date '+%F %H:%M')" "$1" "$2" "${3:-}" >> "$STATE/notify.log"
}

# notify_channels -> names of the configured channels, space separated (empty = none)
notify_channels() {
  local c=""
  [ -n "${SLACK_WEBHOOK_URL:-}" ] && c="$c slack"
  [ -n "${DISCORD_WEBHOOK_URL:-}" ] && c="$c discord"
  [ -n "${NTFY_URL:-}" ] && c="$c ntfy"
  [ -n "${TELEGRAM_BOT_TOKEN:-}" ] && [ -n "${TELEGRAM_CHAT_ID:-}" ] && c="$c telegram"
  [ -n "${NOTIFY_EMAIL:-}" ] && c="$c email"
  echo "${c# }"
}

notify_want() { [ -z "${NOTIFY_ONLY:-}" ] || [ "$NOTIFY_ONLY" = "$1" ]; }

# notify_ok CHANNEL HTTP_CODE OUTFILE -> count success, or log the failure
notify_ok() {
  case "$2" in 2??) NOTIFY_SENT=$((NOTIFY_SENT + 1)) ;; *) notify_log "$1" "${2:-000}" "$(head -c 200 "$3" 2>/dev/null | tr '\n' ' ')" ;; esac
  rm -f "$3"
}

notify() {  # text
  local txt=$1 body code auth out="${TMP:-/tmp}/notify.$$" subj="[wp-guard] ALERTS on ${SITE_HOST:-your site}"
  NOTIFY_SENT=0; NOTIFY_FAILED=0
  [ -n "$(notify_channels)" ] || { echo "wp-guard: no notification channel configured - nobody was told. Run: wp-guard notify setup" >&2; return 0; }

  if [ -n "${NOTIFY_EMAIL:-}" ] && notify_want email; then
    if command -v mail >/dev/null 2>&1; then
      printf '%s\n' "$txt" | mail -s "$subj" "$NOTIFY_EMAIL" && NOTIFY_SENT=$((NOTIFY_SENT + 1)) || notify_log email "mail-failed"
    elif command -v sendmail >/dev/null 2>&1; then
      printf 'To: %s\nSubject: %s\n\n%s\n' "$NOTIFY_EMAIL" "$subj" "$txt" | sendmail -t && NOTIFY_SENT=$((NOTIFY_SENT + 1)) || notify_log email "sendmail-failed"
    else notify_log email "no-mail-program"; fi
  fi
  if [ "${HAVE_CURL:-0}" != 1 ]; then
    [ -n "$(notify_channels | sed 's/email//')" ] && echo "wp-guard: curl is required for Slack/Discord/ntfy/Telegram" >&2
    return 0
  fi
  if [ -n "${SLACK_WEBHOOK_URL:-}" ] && notify_want slack; then
    body=$(printf '%s\n' "$txt" | notify_trim 3500 | notify_json); body="{\"text\":\"$body\"}"
    code=$(curl -s -m 20 -o "$out" -w '%{http_code}' -H 'Content-Type: application/json' -d "$body" "$SLACK_WEBHOOK_URL" 2>/dev/null)
    notify_ok slack "$code" "$out"
  fi
  if [ -n "${DISCORD_WEBHOOK_URL:-}" ] && notify_want discord; then
    body=$(printf '%s\n' "$txt" | notify_trim 1900 | notify_json); body="{\"content\":\"$body\"}"
    code=$(curl -s -m 20 -o "$out" -w '%{http_code}' -H 'Content-Type: application/json' -d "$body" "$DISCORD_WEBHOOK_URL" 2>/dev/null)
    notify_ok discord "$code" "$out"
  fi
  if [ -n "${NTFY_URL:-}" ] && notify_want ntfy; then
    auth=(); [ -n "${NTFY_TOKEN:-}" ] && auth=(-H "Authorization: Bearer $NTFY_TOKEN")
    code=$(printf '%s\n' "$txt" | notify_trim 3900 | curl -s -m 20 -o "$out" -w '%{http_code}' \
      -H "Title: $subj" -H "Priority: high" -H "Tags: warning" "${auth[@]}" \
      --data-binary @- "$NTFY_URL" 2>/dev/null)
    notify_ok ntfy "$code" "$out"
  fi
  if [ -n "${TELEGRAM_BOT_TOKEN:-}" ] && [ -n "${TELEGRAM_CHAT_ID:-}" ] && notify_want telegram; then
    code=$(printf '%s\n' "$txt" | notify_trim 3900 | curl -s -m 20 -o "$out" -w '%{http_code}' "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
      --data-urlencode "chat_id=$TELEGRAM_CHAT_ID" --data-urlencode "text@-" 2>/dev/null)
    notify_ok telegram "$code" "$out"
  fi
  return 0
}
