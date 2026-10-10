# checks/http.sh
# Public site: cloaking by device/search engine/bot, external scripts downloaded and scanned.
# Worker: launched from lib/audit.sh. Only READS; reports with emit/lines/hits.

fetch_one() {  # fields separated by \x1f (not tab: an empty tab collapses): name ua ref lang url output
  local name ua ref lang url out
  IFS=$'\x1f' read -r name ua ref lang url out <<< "$1"
  case "$out" in "$TMP"/*) ;; *) return 1 ;; esac   # read-only: never write outside the temp directory
  local args=(-sL -m 25 --max-redirs 8 --compressed --max-filesize 4000000 -A "$ua" -o "$out" -w '%{http_code} %{size_download} %{num_redirects} %{url_effective}')
  [ -n "$ref" ] && args+=(-e "$ref"); [ -n "$lang" ] && args+=(-H "Accept-Language: $lang")
  # shellcheck disable=SC2086
  curl "${args[@]}" $CURL_EXTRA "$url" > "$out.meta" 2>/dev/null || echo "000 0 0 $url" > "$out.meta"
  : "$name"
}
slug() { printf '%s__%s' "$1" "$(printf '%s' "$2" | sed 's#[^A-Za-z0-9]#_#g' | cut -c1-90)"; }
hosts_of() { grep -oiE "(src|action|data-src)[[:space:]]*=[[:space:]]*[\"']?(https?:)?//[A-Za-z0-9.-]+" "$1" 2>/dev/null | sed -E 's#.*//##' | tr 'A-Z' 'a-z' | sort -u | grep -vE "$KNOWN_RE"; }
job_http() {
  [ "$HAVE_CURL" = 1 ] || { emit WARN "Public site" "curl not available"; return 0; }
  local H="$TMP/http" jobs="$TMP/http/jobs.tsv" name ua ref lang url out
  mkdir -p "$H/a"; : > "$jobs"
  local UA_D="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
  local UA_M="Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Mobile Safari/537.36"
  local UA_G="Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
  local UA_X="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15"
  local G="https://www.google.com/" B="https://www.bing.com/"
  add() { printf '%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\n' "$1" "$2" "$3" "$4" "$5" "$H/$(slug "$1" "$5")" >> "$jobs"; }
  { [ "$NOWP" = 1 ] || T 60 $WP post list --post_type=page,post --post_status=publish --field=url 2>/dev/null; echo "$SITE/wp-login.php"; } | sort -u | head -n "$MAX_PAGES" > "$H/urls.txt"
  # front page with many variants (cloaking by device, search engine, language, bot)
  add desk "$UA_D" "" "$HTTP_LANG" "$SITE/"
  add desk-google "$UA_D" "$G" "$HTTP_LANG" "$SITE/"
  add desk-bing "$UA_D" "$B" "$HTTP_LANG" "$SITE/"
  add desk-lang2 "$UA_D" "$G" "$HTTP_LANG_ALT" "$SITE/"
  add mobile-google "$UA_M" "$G" "$HTTP_LANG" "$SITE/"
  add mac-google "$UA_X" "$G" "$HTTP_LANG" "$SITE/"
  add googlebot "$UA_G" "" "" "$SITE/"
  while read -r url; do
    [ "$url" = "$SITE/" ] && continue
    add desk "$UA_D" "" "$HTTP_LANG" "$url"
    add mobile-google "$UA_M" "$G" "$HTTP_LANG" "$url"
  done < "$H/urls.txt"
  add desk "$UA_D" "" "" "$SITE/zz-no-existe-$RANDOM-$RANDOM/"
  xargs -a "$jobs" -d '\n' -r -P "$HTTP_PAR" -I{} bash -c 'fetch_one "$1"' _ {}

  # ---- analysis
  local all_unk="$H/all.unk" code size redirs final fh sh d b
  : > "$all_unk"; : > "$H/pages.lst"
  sh=${SITE_HOST#www.}
  local fail=0 total=0
  while IFS=$'\x1f' read -r name ua ref lang url out; do
    [ -f "$out.meta" ] || continue
    read -r code size redirs final < "$out.meta"
    total=$((total + 1))
    if [ "$code" = 000 ] || [ ! -s "$out" ]; then fail=$((fail + 1)); continue; fi
    case "$url" in */zz-no-existe-*) [ "$code" = 200 ] && emit WARN "Public site" "Non-existent URL answers 200 (soft-404; SEO spam often creates ghost pages)"; continue ;; esac
    fh=${final#*//}; fh=${fh%%/*}; fh=${fh#www.}
    [ "$fh" != "$sh" ] && emit ALERT "Public site" "Variant '$name' of $url ends up on ANOTHER domain ($final, $redirs redirects)"
    [ "$name" = desk ] && echo "$out" >> "$H/pages.lst"
    grep -qiE "$IOC_RE" "$out" && emit ALERT "Public site" "The HTML of '$name' at $url contains attacker markers: THE INFECTION IS VISIBLE"
    grep -qiE '<meta[^>]+http-equiv=["'"'"']?refresh' "$out" && emit WARN "Public site" "Meta refresh (redirect) at $url [$name]"
    if [ "$name" = desk ]; then hosts_of "$out" >> "$all_unk"
    else
      b="$H/$(slug desk "$url")"   # compared against the normal version of THAT SAME page
      if [ -s "$b" ]; then
        hosts_of "$b" > "$H/base.hosts"   # temp file: no <(...) (CageFS has no /dev/fd)
        d=$(hosts_of "$out" | comm -13 "$H/base.hosts" - 2>/dev/null)
        # shellcheck disable=SC2086
        [ -n "$d" ] && emit ALERT "Public site" "CLOAKING: variant '$name' of $url loads domains that the normal one does not: $(echo $d | tr ' ' ',')"
      fi
    fi
  done < "$jobs"
  [ "$fail" -gt 0 ] && emit INFO "Public site" "$fail of $total downloads failed or came back empty (Cloudflare may challenge bots; try ORIGIN_IP)"
  sort -u "$all_unk" | lines WARN "Public site" "Scripts/iframes/forms pointing to unknown domains (real HTML)"
  emit INFO "Public site" "Public pages checked: $(wc -l < "$H/urls.txt") (x variants)"
  # front page size per variant
  local bsz; bsz=$(awk '{print $2}' "$H/$(slug desk "$SITE/").meta" 2>/dev/null)
  while IFS=$'\x1f' read -r name ua ref lang url out; do
    [ "$url" = "$SITE/" ] && [ "$name" != desk ] || continue
    read -r code size _ < "$out.meta" 2>/dev/null || continue
    if [ "$code" = 200 ] && [ "${bsz:-0}" -gt 0 ] && [ "${size:-0}" -gt 0 ]; then
      d=$(( (size > bsz ? size - bsz : bsz - size) * 100 / bsz ))
      [ "$d" -gt 25 ] && emit WARN "Public site" "The front page has a different size for '$name' ($size vs $bsz bytes, $d%): possible cloaking"
    fi
  done < "$jobs"
  # rules on the rendered HTML (ALERT level only: real HTML carries GTM, iframes, etc.)
  ONLY_ALERT=1 STRIP="$H/" scan_rules "$H/pages.lst" "Public site" "$JS_RULES"
  STRIP="$H/" cooccur "$H/pages.lst" "Public site"

  # ---- scripts the page loads (own and external): download and scan
  xargs -a "$H/pages.lst" -d '\n' -r grep -ohiE '<script[^>]*[[:space:]]src=["'"'"']?[^"'"'"' >]+' 2>/dev/null \
    | sed -E "s/.*[sS][rR][cC]=[\"']?//; s/&#038;/\&/g; s/&amp;/\&/g" | awk '!s[$0]++' \
    | awk -v site="$SITE" '/^data:/ {next} /^\/\// {print "https:" $0; next} /^https?:/ {print; next} /^\// {print site $0; next} {print site "/" $0}' | head -n 80 > "$H/assets.txt"
  : > "$H/assets.jobs"; : > "$H/assets.lst"
  while read -r url; do
    out="$H/a/$(slug asset "$url")"
    printf 'asset\x1f%s\x1f\x1f\x1f%s\x1f%s\n' "$UA_D" "$url" "$out" >> "$H/assets.jobs"; echo "$out" >> "$H/assets.lst"
  done < "$H/assets.txt"
  xargs -a "$H/assets.jobs" -d '\n' -r -P "$HTTP_PAR" -I{} bash -c 'fetch_one "$1"' _ {}
  local ah
  while read -r url; do
    ah=${url#*//}; ah=${ah%%/*}; ah=$(echo "$ah" | tr 'A-Z' 'a-z')
    echo "$ah" | grep -qE "$KNOWN_RE" || echo "$url"
  done < "$H/assets.txt" | lines WARN "Public site" "Scripts loaded from unknown domains (downloaded and scanned below)" 20
  find "$H/a" -type f -size +0 ! -name '*.meta' > "$H/assets.ok"
  xargs -a "$H/assets.ok" -d '\n' -r -n 100 grep -lIiE -e "$IOC_RE" 2>/dev/null | STRIP="$H/a/" lines ALERT "Public site" "Public JS with attacker markers"
  STRIP="$H/a/" scan_rules "$H/assets.ok" "Public site" "$JS_RULES"
  STRIP="$H/a/" cooccur "$H/assets.ok" "Public site"
}
export -f fetch_one
