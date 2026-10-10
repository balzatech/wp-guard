#!/usr/bin/env bash
# tests/run.sh - end-to-end tests for wp-guard.
#
#   bash tests/run.sh
#
# Builds a fake WordPress site in a temp folder, plants known malware samples (harmless text files), and
# drives the real commands against it with a simulated wp-cli (tests/stub/wp). Needs GNU userland
# (Linux). Never touches your real site or ~/.wp_auditor: HOME and the state folder are temporary.
#
# The malware samples are assembled at run time from fragments: a complete signature written in this file
# would make antivirus software delete the test suite itself.

set -u
ROOT=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)
T=$(mktemp -d "${TMPDIR:-/tmp}/wpg-test.XXXXXX") || exit 1
trap 'rm -rf "$T"' EXIT

export HOME="$T/home"; mkdir -p "$HOME"
export WPA_STATE="$T/state"
export NO_COLOR=1
chmod +x "$ROOT/tests/stub/wp" "$ROOT"/bin/* 2>/dev/null
export PATH="$ROOT/tests/stub:$PATH"
S="$T/site"
WPG="$ROOT/bin/wp-guard"

pass=0; fail=0
ok()  { pass=$((pass + 1)); printf '  \033[32mok\033[0m   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | head -n 12 | sed 's/^/         | /'; }
# t "description" command...   -> passes when the command succeeds
t() { local d=$1; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }
section() { printf '\n%s\n' "$1"; }
sha() { sha256sum "$1" | cut -c1-64; }

wpg() { (cd "$S" && "$WPG" "$@"); }

# --- sample builders (fragments joined at run time) ---
ev="ev""al"; b64="base64""_decode"; gz="gzinfl""ate"; sy="sys""tem"
sample_shell()  { printf '<?php @%s(%s($_POST["x"]));\n' "$ev" "$b64"; }
sample_gif()    { printf 'GIF89a<?php %s($_GET["c"]); ?>\n' "$sy"; }
sample_packed() { printf '<?php %s(%s(%s("aGVsbG8=")));\n' "$ev" "$gz" "$b64"; }
sample_ioc()    { printf '// %s injected\n' "popkov""-01"; }

make_site() {
  rm -rf "$S"; mkdir -p "$S"/{wp-admin,wp-includes,wp-content/{plugins/good-plugin,themes/t,uploads,mu-plugins}}
  echo '<?php // wp-config' > "$S/wp-config.php"; chmod 600 "$S/wp-config.php"
  echo '<?php // Silence is golden.' > "$S/index.php"
  echo '<?php $wp_version = "6.8";' > "$S/wp-includes/version.php"
  echo '<?php // Silence is golden.' > "$S/wp-content/index.php"
  echo '<?php /* Plugin Name: Good Plugin */' > "$S/wp-content/plugins/good-plugin/good-plugin.php"
  echo 'body{margin:0}' > "$S/wp-content/themes/t/style.css"
  cat > "$WPA_STATE/config.sh" <<CONF
WP_PATH=$S
SITE=https://example.test
ALLOWED_ADMINS=owner
OTHER_SITES=0
CONF
  find "$S" -exec touch -d '2 hours ago' {} +
}
plant() {
  sample_shell  > "$S/wp-content/uploads/shell.php"
  sample_gif    > "$S/wp-content/uploads/pic.gif"
  sample_packed > "$S/wp-content/plugins/good-plugin/extra.php"
  sample_ioc    > "$S/wp-content/themes/t/x.js"
  find "$S" -exec touch -d '2 hours ago' {} +
}
SCAN_SKIP="http,probes,logs"   # network checks: not testable offline

mkdir -p "$WPA_STATE"

# ---------------------------------------------------------------------------------------------------
section "Static checks"
syn=0
for f in "$ROOT"/bin/* "$ROOT"/lib/*.sh "$ROOT"/checks/*.sh "$ROOT"/tests/stub/wp; do
  bash -n "$f" 2>/dev/null || { bad "syntax error in ${f#$ROOT/}"; syn=1; }
done
[ "$syn" = 0 ] && ok "every script passes bash -n"
t "no Windows line endings (CRLF breaks bash)" bash -c "! grep -rlI \$'\\r' '$ROOT/bin' '$ROOT/lib' '$ROOT/checks' '$ROOT/rules'"
t "no process substitution <(...) (missing /dev/fd on some hosts)" bash -c "! grep -rnE '(^|[[:space:]])<\\(' '$ROOT/bin' '$ROOT/lib' '$ROOT/checks' | grep -vE '(sin|no) <\\('"
t "user-facing messages are in English (no Spanish markers left)" bash -c "! grep -rniE '\\b(archivos|carpeta|sospechos[oa]s?|desconocid[oa]s?|cuarentena|hallazgos?|simulacion|reporte|nucleo|veredicto)\\b' '$ROOT/bin' '$ROOT/lib' '$ROOT/checks' '$ROOT/rules'"
t "no personal data left in the project" bash -c "! grep -rniE 'avvacolombia|juanherrera|u237765309|gmail\\.com' '$ROOT' --include='*' --exclude-dir=.git --exclude=run.sh"
t "documentation files exist" bash -c "cd '$ROOT' && for f in README.md README.es.md SECURITY.md CONTRIBUTING.md CHANGELOG.md LICENSE docs/rules.md; do [ -s \$f ] || exit 1; done"
t "relative links in README.md point to existing files" bash -c "cd '$ROOT' && grep -oE '\\]\\(([A-Za-z][A-Za-z0-9_./-]*)\\)' README.md README.es.md | sed -E 's/.*\\(([^)]*)\\)/\\1/' | grep -vE '^https?:' | while read -r p; do [ -e \"\$p\" ] || { echo missing \$p; exit 1; }; done"

# ---------------------------------------------------------------------------------------------------
section "init (auto-detection)"
make_site; rm -f "$WPA_STATE/config.sh"
out=$(cd "$S/wp-content" && "$WPG" init --yes 2>&1)
t "init finds the site from a subfolder" grep -q "WordPress: $S" <<< "$out"
t "init writes config.sh" test -f "$WPA_STATE/config.sh"
t "init reads the URL from WordPress" grep -q 'SITE=https://example.test' "$WPA_STATE/config.sh"
t "init trusts the current administrators" grep -q 'ALLOWED_ADMINS=owner' "$WPA_STATE/config.sh"
t "config.sh is private (600)" test "$(stat -c %a "$WPA_STATE/config.sh")" = 600
(cd "$S/wp-content" && "$WPG" init --yes >/dev/null 2>&1)
t "re-running init keeps a backup of the old config" bash -c "ls '$WPA_STATE'/config.sh.bak.* >/dev/null 2>&1"

# ---------------------------------------------------------------------------------------------------
section "scan on a clean site"
make_site
out=$(wpg scan --skip "$SCAN_SKIP" 2>&1); rc=$?
if [ "$rc" -ne 2 ]; then ok "clean site: no alerts (exit code $rc)"; else bad "clean site: no alerts (exit code 2)" "$(sed -n '/ALERTS/,/WARNINGS/p' <<< "$out" | cut -c1-200)"; fi
t "report is saved" bash -c "ls '$WPA_STATE'/reports/report_*.txt >/dev/null 2>&1"
t "fix has nothing to do on a clean site" bash -c "! (cd '$S' && '$WPG' fix 2>&1 | grep -q QUARANTINE)"

# ---------------------------------------------------------------------------------------------------
section "scan on an infected site"
make_site; plant
out=$(wpg scan --skip "$SCAN_SKIP" 2>&1); rc=$?
t "infected: exit code is 2 (alerts)" test "$rc" -eq 2
t "detects an encoded-eval webshell in uploads" grep -q 'shell.php' <<< "$out"
t "detects PHP hidden inside an image" grep -q 'pic.gif' <<< "$out"
t "detects the attacker marker (IOC)" grep -q 'x.js' <<< "$out"
t "report suggests the next step (wp-guard fix)" grep -q 'wp-guard fix' <<< "$out"

# ---------------------------------------------------------------------------------------------------
section "CPU governor"
if [ -r /proc/uptime ]; then
  gres=$(bash "$ROOT/tests/throttle_check.sh" 25)
  gcpu=${gres%% *}; gstop=${gres##* }
  t "two busy processes stay far below 2 cores with --cpu 25 (measured ${gcpu}%)" test "${gcpu:-999}" -lt 70
  t "nothing is left paused after the governor stops" test "$gstop" = 0
  nres=$(bash "$ROOT/tests/throttle_check.sh" 0)
  t "--cpu 0 disables the limit (measured ${nres%% *}%)" test "${nres%% *}" -ge 60
fi
t "--cpu rejects a non-number (exit 64)" bash -c "(cd '$S' && '$WPG' scan --cpu abc >/dev/null 2>&1); [ \$? -eq 64 ]"

# ---------------------------------------------------------------------------------------------------
section "scan --format json"
sample_shell > "$S/wp-content/uploads/q\"uo\\te.php"; touch -d '2 hours ago' "$S/wp-content/uploads/q\"uo\\te.php"   # hostile file name
jout=$(wpg scan --skip "$SCAN_SKIP" --format json 2>/dev/null); jrc=$?
[ -n "${WPG_TEST_JSON_OUT:-}" ] && printf '%s' "$jout" > "$WPG_TEST_JSON_OUT"   # debugging aid: keep a copy to validate with an external parser
t "json: stdout starts with { and ends with }" bash -c "[ \"\$(printf '%s' \"\$1\" | head -c1)\" = '{' ] && [ \"\$(printf '%s' \"\$1\" | tail -c2 | tr -d '\\n')\" = '}' ]" _ "$jout"
t "json: exit code is still 2 on alerts" test "$jrc" -eq 2
t "json: verdict is alert" grep -q '"verdict": "alert"' <<< "$jout"
t "json: contains the finding with its category" grep -q '"category": "Uploads"' <<< "$jout"
t "json: lists the infected file as an item" grep -q 'shell.php' <<< "$jout"
t "json: counts are present" grep -q '"counts": {"alert": [1-9]' <<< "$jout"
t "json: hostile file name is escaped" grep -qF 'q\"uo\\te.php' <<< "$jout"
if command -v python3 >/dev/null 2>&1; then
  t "json: parses with python3 (json.load)" bash -c "printf '%s' \"\$1\" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d[\"tool\"]==\"wp-guard\" and d[\"findings\"]'" _ "$jout"
elif command -v jq >/dev/null 2>&1; then
  t "json: parses with jq" bash -c "printf '%s' \"\$1\" | jq -e '.findings | length > 0'" _ "$jout"
fi
t "json: a JSON copy is saved with the report" bash -c "ls '$WPA_STATE'/reports/report_*.json >/dev/null 2>&1"
t "json: unknown --format is rejected (exit 64)" bash -c "(cd '$S' && '$WPG' scan --format xml >/dev/null 2>&1); [ \$? -eq 64 ]"
rm -f "$S/wp-content/uploads/q\"uo\\te.php"

# ---------------------------------------------------------------------------------------------------
section "fix: preview, apply, undo"
before_shell=$(sha "$S/wp-content/uploads/shell.php")
out=$(wpg fix 2>&1)
t "preview lists the webshell" grep -q 'shell.php' <<< "$out"
t "preview lists the polyglot image" grep -q 'pic.gif' <<< "$out"
t "preview lists the extra file in an official plugin" grep -q 'extra.php' <<< "$out"
t "preview numbers the items" grep -q '\[1\]' <<< "$out"
t "preview changes nothing" test -f "$S/wp-content/uploads/shell.php"

out=$(MAX_HEAL=1 wpg fix --apply 2>&1 </dev/null)
t "MAX_HEAL safety stop touches nothing" test -f "$S/wp-content/uploads/shell.php"
t "MAX_HEAL safety stop explains itself" grep -q 'MAX_HEAL' <<< "$out"

out=$(wpg fix --apply 2>&1 </dev/null)
t "apply (non-interactive, as cron) quarantines the webshell" test ! -e "$S/wp-content/uploads/shell.php"
t "apply quarantines the polyglot image" test ! -e "$S/wp-content/uploads/pic.gif"
t "apply quarantines the plugin intruder" test ! -e "$S/wp-content/plugins/good-plugin/extra.php"
t "apply leaves legitimate files alone" test -f "$S/wp-content/plugins/good-plugin/good-plugin.php"
t "apply prints a summary with the undo command" grep -q 'Undo:   wp-guard undo' <<< "$out"
Q=$(ls -dt "$WPA_STATE"/quarantine/*/ 2>/dev/null | head -n 1)
t "quarantine has a MANIFEST" test -s "${Q}MANIFEST.tsv"
t "MANIFEST records the original sha256" grep -q "$before_shell" "${Q}MANIFEST.tsv"
t "quarantined files are not executable" test -z "$(find "$Q" -type f -perm /111 2>/dev/null)"
t "uploads/.htaccess now blocks PHP" grep -q 'Require all denied' "$S/wp-content/uploads/.htaccess"

wpg undo "$Q" >/dev/null 2>&1
t "undo restores the file in place" test -f "$S/wp-content/uploads/shell.php"
t "undo restores the exact content (sha256)" test "$(sha "$S/wp-content/uploads/shell.php")" = "$before_shell"

# undo must not trust the manifest blindly: a path that climbs out of the site is refused
QX="$WPA_STATE/quarantine/evil"; mkdir -p "$QX"; echo data > "$WPA_STATE/escape.txt"
printf './../../escape.txt\t-\ttest\n' > "$QX/MANIFEST.tsv"
out=$(wpg undo "$QX" 2>&1); rc=$?
t "undo refuses a manifest path that escapes the site" grep -q 'SKIPPED (unsafe path' <<< "$out"
t "undo leaves the escaping file where it was" test -f "$WPA_STATE/escape.txt" -a ! -e "$T/escape.txt"
t "undo reports failure when something was skipped" test "$rc" -ne 0

# files younger than MIN_AGE_MIN are left alone (do not fight a plugin update in progress)
make_site; sample_shell > "$S/wp-content/uploads/fresh.php"
wpg fix --apply >/dev/null 2>&1 </dev/null
t "brand-new files are not touched (MIN_AGE_MIN)" test -f "$S/wp-content/uploads/fresh.php"

# an unauthorized admin goes into the plan only when the database says so
make_site
out=$(STUB_BAD_ADMIN=1 wpg fix 2>&1)
t "unauthorized admin appears in the plan" grep -q 'hacker' <<< "$out"

# ---------------------------------------------------------------------------------------------------
section "incremental scanning"
make_site; rm -f "$WPA_STATE/scan_cache.tsv"
victim="$S/wp-content/themes/t/inc.php"; ref="$T/mtime.ref"
n=$(sample_shell | wc -c)
{ printf '<?php // '; head -c $((n - 10)) /dev/zero | tr '\0' 'x'; printf '\n'; } > "$victim"   # harmless, same byte size as the sample
touch -d '2 hours ago' "$victim"; touch -r "$victim" "$ref"
out1=$(wpg scan --skip "$SCAN_SKIP" 2>&1)
t "first scan reads every file and says so" grep -q 'Full content scan' <<< "$out1"
t "the cache file is private (600)" test "$(stat -c %a "$WPA_STATE/scan_cache.tsv")" = 600
out2=$(wpg scan --skip "$SCAN_SKIP" 2>&1)
t "second scan skips unchanged clean files" grep -q 'Incremental: .*unchanged files skipped' <<< "$out2"
# the attack the cache must survive: same size, forged mtime, different content
sample_shell > "$victim"; touch -r "$ref" "$victim"
out3=$(wpg scan --skip "$SCAN_SKIP" 2>&1)
t "a file swapped for malware (same size, forged mtime) is detected" grep -q 'themes/t/inc.php' <<< "$out3"
out4=$(wpg scan --skip "$SCAN_SKIP" 2>&1)
t "an infected file is reported again on the next scan" grep -q 'themes/t/inc.php' <<< "$out4"
# a new file is read even though everything else is skipped
sample_shell > "$S/wp-content/themes/t/new.php"; touch -d '2 hours ago' "$S/wp-content/themes/t/new.php"
t "a brand-new infected file is detected" bash -c "cd '$S' && '$WPG' scan --skip '$SCAN_SKIP' 2>&1 | grep -q 'themes/t/new.php'"
rm -f "$S/wp-content/themes/t/new.php" "$victim"
wpg scan --skip "$SCAN_SKIP" >/dev/null 2>&1
t "--full ignores the cache" bash -c "cd '$S' && '$WPG' scan --full --skip '$SCAN_SKIP' 2>&1 | grep -q 'Full content scan'"
t "changing the matching configuration (IOC_LIST) invalidates the cache" bash -c "cd '$S' && IOC_LIST='popkov-01 extra-marker' '$WPG' scan --skip '$SCAN_SKIP' 2>&1 | grep -q 'Full content scan'"
t "INCREMENTAL=0 turns it off" bash -c "cd '$S' && ! INCREMENTAL=0 '$WPG' scan --skip '$SCAN_SKIP' 2>&1 | grep -qE 'Incremental:|Full content scan'"
before=$(sha "$WPA_STATE/scan_cache.tsv")
wpg scan --only php >/dev/null 2>&1
t "a scan limited with --only does not touch the cache" test "$before" = "$(sha "$WPA_STATE/scan_cache.tsv")"
wpg scan --skip "$SCAN_SKIP" >/dev/null 2>&1   # rebuild the cache with the normal configuration
t "JSON reports how many files were read and skipped" bash -c "cd '$S' && '$WPG' scan --format json --skip '$SCAN_SKIP' 2>/dev/null | grep -q '\"content_scan\": {\"incremental\": true'"

# ---------------------------------------------------------------------------------------------------
section "verification cache (wp-cli is not restarted for unchanged plugins)"
make_site; rm -f "$WPA_STATE/scan_cache.tsv" "$WPA_STATE/verify_cache.tsv"
export STUB_LOG="$T/stub.log"; : > "$STUB_LOG"
calls() { grep -c "$1" "$STUB_LOG"; }
wpg scan --skip "$SCAN_SKIP" >/dev/null 2>&1
t "first scan verifies the core and the plugin" test "$(calls 'core verify-checksums')" = 1 -a "$(calls 'plugin verify-checksums good-plugin')" = 1
t "the verification cache is private (600)" test "$(stat -c %a "$WPA_STATE/verify_cache.tsv")" = 600
: > "$STUB_LOG"
out=$(wpg scan --skip "$SCAN_SKIP" 2>&1)
t "second scan does not re-verify the unchanged core and plugin" test "$(calls 'core verify-checksums')" = 0 -a "$(calls 'plugin verify-checksums good-plugin')" = 0
t "the report says how many were skipped" grep -q 'Official checksums: 2 unchanged units' <<< "$out"
# a file added to an official plugin must be caught even though the plugin verified last time
sample_packed > "$S/wp-content/plugins/good-plugin/extra.php"; touch -d '2 hours ago' "$S/wp-content/plugins/good-plugin/extra.php"
: > "$STUB_LOG"
out=$(wpg scan --skip "$SCAN_SKIP" 2>&1)
t "a file added to a cached plugin triggers a new verification" test "$(calls 'plugin verify-checksums good-plugin')" = 1
t "...and is reported" grep -q 'good-plugin/extra.php' <<< "$out"
t "core was not re-verified (it did not change)" test "$(calls 'core verify-checksums')" = 0
rm -f "$S/wp-content/plugins/good-plugin/extra.php"
# modifying an existing plugin file with the same size and a forged mtime still counts as a change
wpg scan --skip "$SCAN_SKIP" >/dev/null 2>&1   # verifies again and caches the clean state
ref2="$T/plugin.ref"; touch -r "$S/wp-content/plugins/good-plugin/good-plugin.php" "$ref2"
sed -i 's/Good Plugin/Good Plugi!/' "$S/wp-content/plugins/good-plugin/good-plugin.php"; touch -r "$ref2" "$S/wp-content/plugins/good-plugin/good-plugin.php"
: > "$STUB_LOG"
wpg scan --skip "$SCAN_SKIP" >/dev/null 2>&1
t "an edited plugin file (same size, forged mtime) is re-verified" test "$(calls 'plugin verify-checksums good-plugin')" = 1
: > "$STUB_LOG"
wpg scan --full --skip "$SCAN_SKIP" >/dev/null 2>&1
t "--full verifies everything again" test "$(calls 'core verify-checksums')" = 1 -a "$(calls 'plugin verify-checksums good-plugin')" = 1
unset STUB_LOG

# ---------------------------------------------------------------------------------------------------
section "notifications"
make_site
out=$(wpg notify 2>&1); rc=$?
t "no channel: notify says so" grep -q 'No alert channel' <<< "$out"
t "no channel: notify exits non-zero" test "$rc" -ne 0
printf 'WEBHOOK_URL=https://discord.com/api/webhooks/1/x\nWEBHOOK_KIND=discord\n' >> "$WPA_STATE/config.sh"
t "legacy WEBHOOK_URL+KIND is understood as discord" bash -c "(cd '$S' && '$WPG' notify status 2>&1) | grep -q 'discord'"
: > "$WPA_STATE/notify.log"
printf 'NTFY_URL=http://127.0.0.1:9/nope\n' >> "$WPA_STATE/config.sh"
sed -i '/^WEBHOOK_/d' "$WPA_STATE/config.sh"
(cd "$S" && "$WPG" notify >/dev/null 2>&1); rc=$?
t "a failing channel makes notify exit non-zero" test "$rc" -ne 0
t "a failing channel is logged" grep -q 'ntfy' "$WPA_STATE/notify.log"
t "the log never contains the channel URL" bash -c "! grep -q '127.0.0.1' '$WPA_STATE/notify.log'"

# config helper keeps other keys, quotes values, drops empty ones
printf 'KEEP=1\nSLACK_WEBHOOK_URL=old\n' > "$WPA_STATE/config.sh"
bash -c "WPG_HOME='$ROOT'; STATE='$WPA_STATE'; . '$ROOT/lib/config.sh'; wpg_conf_set SLACK_WEBHOOK_URL 'https://x/a b'; wpg_conf_set GONE ''"
t "wpg_conf_set keeps unrelated keys" grep -q '^KEEP=1' "$WPA_STATE/config.sh"
t "wpg_conf_set replaces the key (no duplicates)" test "$(grep -c '^SLACK_WEBHOOK_URL=' "$WPA_STATE/config.sh")" = 1
t "wpg_conf_set shell-quotes values" bash -c ". '$WPA_STATE/config.sh'; [ \"\$SLACK_WEBHOOK_URL\" = 'https://x/a b' ]"
t "wpg_conf_set keeps config.sh private (600)" test "$(stat -c %a "$WPA_STATE/config.sh")" = 600

# ---------------------------------------------------------------------------------------------------
section "packaging"
t "VERSION is a semantic version" grep -qE '^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.]+)?$' "$ROOT/VERSION"
t "wp-guard --version prints it" bash -c "[ \"\$('$WPG' --version)\" = \"wp-guard \$(cat '$ROOT/VERSION')\" ]"
t "CHANGELOG mentions the current version" grep -qF "[$(tr -d '[:space:]' < "$ROOT/VERSION")]" "$ROOT/CHANGELOG.md"
t "LICENSE is GPL-3" grep -q 'GNU GENERAL PUBLIC LICENSE' "$ROOT/LICENSE"
PFX="$T/prefix"
out=$(PREFIX="$PFX" bash "$ROOT/install.sh" 2>&1)
t "install.sh installs and links the command" test -L "$PFX/bin/wp-guard" -a -f "$PFX/share/wp-guard/bin/wp-guard"
# run through bash: some hosts mount /tmp noexec
t "installed command runs (symlink resolves to its own files)" bash -c "[ \"\$(bash '$PFX/bin/wp-guard' --version)\" = \"wp-guard \$(cat '$ROOT/VERSION')\" ]"
t "install.sh --help does not install anything" bash -c "PREFIX='$T/p2' bash '$ROOT/install.sh' --help >/dev/null 2>&1; [ ! -e '$T/p2' ]"
t "install.sh tells the user what to run next" grep -q 'wp-guard init' <<< "$out"
PREFIX="$PFX" bash "$ROOT/install.sh" --uninstall >/dev/null 2>&1
t "install.sh --uninstall removes everything it installed" test ! -e "$PFX/bin/wp-guard" -a ! -d "$PFX/share/wp-guard"

# ---------------------------------------------------------------------------------------------------
printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
