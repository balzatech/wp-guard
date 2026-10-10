# shellcheck disable=SC2034  # shared state: assigned here, read by the modules and commands that source this file
# notify_setup.sh - interactive channel setup.
# Single responsibility: ask where alerts should go, save it in config.sh and PROVE it works by sending a
# real test message to that channel. Needs config.sh (wpg_ask, wpg_conf_set) and notify.sh.

# notify_try CHANNEL -> send a test message to that channel only; 0 if it arrived at the service
notify_try() {
  NOTIFY_ONLY=$1 notify "wp-guard: test message from ${SITE_HOST:-your site} ($(date '+%F %H:%M')). If you can read this, alerts work."
  [ "$NOTIFY_SENT" -gt 0 ] && [ "$NOTIFY_FAILED" -eq 0 ]
}

# notify_setup_one CHOICE -> configure one channel; returns 0 if it was saved and the test passed
notify_setup_one() {
  local ch=$1 var val topic srv
  case $ch in
    1|slack)
      ch=slack; var=SLACK_WEBHOOK_URL
      echo "Slack: create an Incoming Webhook at https://api.slack.com/messaging/webhooks and paste its URL."
      wpg_ask "Slack webhook URL:" "" ;;
    2|discord)
      ch=discord; var=DISCORD_WEBHOOK_URL
      echo "Discord: channel settings > Integrations > Webhooks > New Webhook > Copy URL."
      wpg_ask "Discord webhook URL:" "" ;;
    3|ntfy)
      ch=ntfy; var=NTFY_URL
      echo "ntfy: install the ntfy app (iOS/Android) and subscribe to a topic. Anyone who knows the topic can read it, so make it hard to guess."
      wpg_ask "ntfy topic:" "wpguard-$RANDOM$RANDOM$RANDOM"; topic=$REPLY
      wpg_ask "ntfy server:" "https://ntfy.sh"; srv=${REPLY%/}
      REPLY="$srv/$topic" ;;
    4|telegram)
      ch=telegram
      echo "Telegram: create a bot with @BotFather (gives the token), then send it a message and use your chat id."
      wpg_ask "Bot token:" ""; wpg_conf_set TELEGRAM_BOT_TOKEN "$REPLY"; TELEGRAM_BOT_TOKEN=$REPLY
      wpg_ask "Chat id:" ""; wpg_conf_set TELEGRAM_CHAT_ID "$REPLY"; TELEGRAM_CHAT_ID=$REPLY
      notify_try telegram; return ;;
    5|email)
      ch=email; var=NOTIFY_EMAIL
      echo "Email: note that shared hosting often delivers these to spam, or not at all."
      wpg_ask "Email address:" "" ;;
    *) return 1 ;;
  esac
  val=$REPLY
  [ -n "$val" ] || { echo "Nothing entered, skipped."; return 1; }
  case "$ch:$val" in
    slack:https://hooks.slack.com/*|discord:https://discord.com/api/webhooks/*|discord:https://discordapp.com/api/webhooks/*|ntfy:http*|email:*@*) ;;
    telegram:*) ;;
    *) echo "That does not look like a valid $ch value, but I will try it anyway." ;;
  esac
  wpg_conf_set "$var" "$val"; printf -v "$var" '%s' "$val"
  # the old WEBHOOK_URL pair would be mapped onto this channel again: drop it once a dedicated key is set
  case $ch in slack|discord) wpg_conf_set WEBHOOK_URL ""; wpg_conf_set WEBHOOK_KIND ""; WEBHOOK_URL="" ;; esac
  notify_try "$ch"
}

# notify_setup_wizard -> loop until the user has at least one working channel (or skips)
notify_setup_wizard() {
  local more=y have
  [ "${YES:-0}" = 1 ] || [ -t 0 ] || { echo "Skipping notification setup (not interactive). Run: wp-guard notify setup"; return 0; }
  [ "${YES:-0}" = 1 ] && { echo "Skipping notification setup (--yes). Run: wp-guard notify setup"; return 0; }
  HAVE_CURL=1; command -v curl >/dev/null 2>&1 || HAVE_CURL=0
  SITE_HOST=${SITE_HOST:-${SITE#*//}}; SITE_HOST=${SITE_HOST%%/*}
  NOTIFY_SENT=0; NOTIFY_FAILED=0
  have=$(notify_channels); [ -n "$have" ] && echo "Channels already configured: $have"
  while [ "$more" = y ]; do
    echo
    echo "Where should wp-guard send alerts?"
    echo "  1) Slack (recommended)   2) Discord   3) ntfy (phone push, no account)   4) Telegram   5) Email   6) Skip"
    wpg_ask "Choice" "$([ -n "$have" ] && echo 6 || echo 1)"
    [ "$REPLY" = 6 ] && break
    if notify_setup_one "$REPLY"; then
      wpg_ask "Test message sent. Did it arrive? [Y/n]" "y"
      case $REPLY in n|N) echo "Check the URL/token and try again (errors are logged in $STATE/notify.log)." ;; *) echo "Channel saved." ;; esac
    else
      echo "Could not deliver the test message (see above). Nothing was lost; choose again or skip."
    fi
    have=$(notify_channels)
    wpg_ask "Add another channel? [y/N]" "n"; case $REPLY in y|Y) more=y ;; *) more=n ;; esac
  done
  [ -n "$(notify_channels)" ] || echo "No alert channel configured: wp-guard will not tell you about problems on its own. Run later: wp-guard notify setup"
  return 0
}
