# checks/js.sh
# JS/HTML: ClickFix, fake captcha, redirects, external domains.
# Worker: launched from lib/audit.sh. Only READS; reports with emit/lines/hits.

job_js() {
  scan_rules "$TMP/js_scan.c.lst" "JS/HTML signatures" "$JS_RULES"
  cooccur "$TMP/code_scan.c.lst" "JS/HTML signatures"
  exthosts "$TMP/code_scan.c.lst" "JS/HTML signatures"
}
