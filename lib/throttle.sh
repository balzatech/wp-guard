# throttle.sh - CPU governor.
# Single responsibility: keep the CPU used by wp-guard AND everything it launches (grep, find, wp-cli, curl...)
# under CPU_LIMIT, expressed as a percentage of ONE core (50 = half a core, 0 = no limit).
#
# How: a small background loop measures the CPU time of the whole process tree from /proc and, whenever the
# average is above the limit, pauses the tree with SIGSTOP for just long enough, then resumes it with SIGCONT
# (the same idea as the cpulimit tool, in plain bash + awk). `nice` alone is not enough on shared hosting,
# where the limit is per account, not per priority.
#
# Safety: the loop never stops the main script or itself, every pause is at most 2 s, it resumes everything
# on exit/signal, and it does nothing where /proc is unavailable.

# throttle_sample ROOT_PID GOVERNOR_PID -> "TOTAL_TICKS pid pid ..."
# TOTAL_TICKS is monotonic CPU time (user+system, including finished children) of the tree below ROOT; the
# pids are the live processes that may be paused (the governor and what it spawns are excluded).
throttle_sample() {
  awk -v root="$1" -v gov="$2" '
    {
      p = 0; for (i = length($0); i > 0; i--) if (substr($0, i, 1) == ")") { p = i; break }
      if (!p) next
      n = split(substr($0, p + 2), f, " ")
      if (n < 15) next
      pid = $1; par[pid] = f[2]; st[pid] = f[1]
      tick[pid] = f[12] + f[13] + f[14] + f[15]
    }
    END {
      total = tick[root] + 0; list = ""
      for (pid in par) {
        if (pid == root || pid == gov) continue
        q = pid; d = 0
        while (q != "" && q != root && q != gov && (q in par) && d++ < 64) q = par[q]
        if (q != root) continue
        total += tick[pid]
        if (st[pid] != "Z") list = list " " pid
      }
      printf "%d%s\n", total, list
    }' /proc/[0-9]*/stat 2>/dev/null
}

throttle_resume() {
  # shellcheck disable=SC2086
  [ -n "${THROTTLE_STOPPED:-}" ] && kill -CONT $THROTTLE_STOPPED 2>/dev/null
  THROTTLE_STOPPED=""
}

throttle_loop() {
  local root=$1 me=$BASHPID clk=$2 limit=$3 t0 t1 out u0 u1 pids pause
  THROTTLE_STOPPED=""
  trap 'throttle_resume; exit 0' TERM INT HUP
  trap throttle_resume EXIT
  read -r t0 _ < /proc/uptime
  out=$(throttle_sample "$root" "$me"); u0=${out%% *}
  while kill -0 "$root" 2>/dev/null; do
    sleep 0.3
    read -r t1 _ < /proc/uptime
    out=$(throttle_sample "$root" "$me"); u1=${out%% *}; pids=${out#"$u1"}
    # pause needed so that the average since the last baseline equals the limit (0 if already below it)
    pause=$(awk -v d="$((u1 - u0))" -v clk="$clk" -v lim="$limit" -v t0="$t0" -v t1="$t1" \
      'BEGIN { p = d * 100 / (clk * lim) - (t1 - t0); if (p < 0.03) p = 0; if (p > 2) p = 2; printf "%.2f", p }')
    if [ "$pause" != "0.00" ] && [ -n "$pids" ]; then
      THROTTLE_STOPPED=$pids
      # shellcheck disable=SC2086
      kill -STOP $pids 2>/dev/null
      sleep "$pause"
      throttle_resume
      read -r t0 _ < /proc/uptime
      u0=$u1
    else
      t0=$t1; u0=$u1
    fi
  done
}

# throttle_start: launch the governor for the current script (no-op when the limit is 0 or /proc is missing).
throttle_start() {
  THROTTLE_PID=""
  case "${CPU_LIMIT:-0}" in ''|*[!0-9]*|0) return 0 ;; esac
  [ -r /proc/uptime ] && [ -r "/proc/$$/stat" ] || return 0
  local clk; clk=$(getconf CLK_TCK 2>/dev/null); clk=${clk:-100}
  throttle_loop "$$" "$clk" "$CPU_LIMIT" &
  THROTTLE_PID=$!
  # not a job of this shell: a plain `wait` in the caller must never wait for the governor (it ends only when we do)
  disown "$THROTTLE_PID" 2>/dev/null
}

throttle_stop() {
  [ -n "${THROTTLE_PID:-}" ] || return 0
  kill "$THROTTLE_PID" 2>/dev/null
  local _; for _ in 1 2 3 4 5 6 7 8 9 10; do kill -0 "$THROTTLE_PID" 2>/dev/null || break; sleep 0.1; done   # let it resume what it paused
  THROTTLE_PID=""
}
