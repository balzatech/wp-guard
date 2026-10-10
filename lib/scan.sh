# scan.sh - pattern-search engine.
# Single responsibility: apply rules (rules/*.rules) and heuristics to file lists and turn the
# matches into findings.

# ClickFix: copy to clipboard (A) + Windows command (B) or fake-captcha text (C)
CF_A='clipboard\.writeText|navigator\.clipboard|execCommand\s*\(\s*["'"'"']copy["'"'"']'
CF_B='powershell|pwsh|mshta|cmd(\.exe)?\s*/[ck]|rundll32|regsvr32|bitsadmin|certutil|wscript|cscript|msiexec|curl\s+-[a-z]+\s|wget\s+https?|\bIEX\b|Invoke-(Expression|WebRequest)|Start-Process|bash\s+-c|/bin/(ba)?sh'
CF_C='win(dows)?\s*(key)?\s*\+\s*[rx]\b|windows\s+key|press\s+win|verify\s+you\s+are\s+human|human\s+verification|not\s+a\s+robot|cloudflare[^<]{0,80}(verif|captcha)'
EXT_RX='(<(script|iframe)[^>]{0,200}[[:space:]]src[[:space:]]*=[[:space:]]*|\.src[[:space:]]*=[[:space:]]*|window\.open\(|location(\.href)?[[:space:]]*=[[:space:]]*)["'"'"']?(https?:)?//[A-Za-z0-9.-]+'

load_rules() {
  RL=(); RI=(); RD=(); RX=(); local line rest
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    case $line in '#'*) continue ;; esac
    [ -n "${ONLY_ALERT:-}" ] && [ "${line%%@@*}" != ALERT ] && continue
    RL+=("${line%%@@*}"); rest=${line#*@@}
    RI+=("${rest%%@@*}"); rest=${rest#*@@}
    RD+=("${rest%%@@*}"); RX+=("${rest#*@@}")
  done <<< "$1"
}
# scan_rules LIST CATEGORY "RULES"  -> one pass with all rules; then classify only the candidates
scan_rules() {
  local list=$1 cat=$2 i cand="$TMP/cand.$BASHPID" args=()
  [ -s "$list" ] || return 0
  load_rules "$3"
  for i in "${!RX[@]}"; do args+=(-e "${RX[$i]}"); done
  [ ${#args[@]} -gt 0 ] || return 0
  xargs -a "$list" -d '\n' -r -n 250 -P "$SCAN_PAR" grep -laiE "${args[@]}" 2>/dev/null | sort -u > "$cand"
  [ -s "$cand" ] || { rm -f "$cand"; return 0; }
  for i in "${!RX[@]}"; do
    xargs -a "$cand" -d '\n' -r -n 250 grep -laiE -e "${RX[$i]}" 2>/dev/null | hits "${RL[$i]}" "$cat" "${RD[$i]}"
  done
  rm -f "$cand"
}
cooccur() {  # LISTA CATEGORIA
  local list=$1 cat=$2 a="$TMP/cf.$BASHPID"
  [ -s "$list" ] || return 0
  xargs -a "$list" -d '\n' -r -n 250 -P "$SCAN_PAR" grep -laiE -e "$CF_A" 2>/dev/null | sort -u > "$a"
  [ -s "$a" ] || { rm -f "$a"; return 0; }
  xargs -a "$a" -d '\n' -r -n 250 grep -laiE -e "$CF_B" 2>/dev/null | hits ALERT "$cat" "ClickFix: copies to clipboard + Windows/PowerShell command"
  xargs -a "$a" -d '\n' -r -n 250 grep -laiE -e "$CF_C" 2>/dev/null | hits ALERT "$cat" "ClickFix: copies to clipboard + fake-captcha text / Win+R"
  xargs -a "$a" -d '\n' -r -n 250 grep -LaiE -e "$CF_B|$CF_C" 2>/dev/null | lines WARN "$cat" "Uses the clipboard (check that it is a legitimate 'copy' button)"
  rm -f "$a"
}
exthosts() {  # LIST CATEGORY
  local list=$1 cat=$2 raw="$TMP/ext.$BASHPID"
  [ -s "$list" ] || return 0
  xargs -a "$list" -d '\n' -r -n 200 -P "$SCAN_PAR" grep -HoiE -m 20 -e "$EXT_RX" 2>/dev/null \
    | awk '{ f=$0; sub(/:.*/,"",f); m=$0; sub(/^[^:]*:/,"",m); n=split(m,a,"//"); print tolower(a[n]) "\t" f }' \
    | KRE="$KNOWN_RE" awk -F'\t' 'BEGIN{re=ENVIRON["KRE"]} { h=$1; if (h !~ re && h ~ /\./) print h "\t" $2 }' > "$raw"
  # the report shows one example file per domain, but the incremental cache needs EVERY file that points to one
  cut -f2 "$raw" | sort -u >> "${OUT:-$FD/main.tsv}.matched"
  awk -F'\t' '{ c[$1]++; if (!($1 in ex)) ex[$1]=$2 } END{ for (h in c) printf "%s  (%d refs, e.g.: %s)\n", h, c[h], ex[h] }' "$raw" \
    | sort | lines WARN "$cat" "References to unknown external domains (unverified code)" 30
  rm -f "$raw"
}
