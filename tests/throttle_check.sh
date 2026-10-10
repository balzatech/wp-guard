#!/usr/bin/env bash
# Helper for tests/run.sh: runs two CPU-hungry processes for ~6 s under the governor and reports the result.
# usage: throttle_check.sh LIMIT   -> prints "CPU_PERCENT STOPPED_AFTER" (CPU of the burners as % of one core,
#        and how many of them were left in the stopped state after the governor exited)
WPG_HOME=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck disable=SC1091
. "$WPG_HOME/lib/throttle.sh"
CPU_LIMIT=$1
throttle_start
awk 'BEGIN { while (1) ; }' & b1=$!
awk 'BEGIN { while (1) ; }' & b2=$!
sleep 6
clk=$(getconf CLK_TCK); clk=${clk:-100}
ticks=0
for p in $b1 $b2; do
  read -r line < "/proc/$p/stat" || continue
  rest=${line##*) }; set -- $rest
  ticks=$((ticks + ${12} + ${13}))
done
throttle_stop
stopped=0
for p in $b1 $b2; do
  read -r line < "/proc/$p/stat" || continue
  rest=${line##*) }; [ "${rest%% *}" = T ] && stopped=$((stopped + 1))
done
kill $b1 $b2 2>/dev/null; wait 2>/dev/null
echo "$((ticks * 100 / (clk * 6))) $stopped"
