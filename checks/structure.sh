# checks/structure.sh
# Structure/permissions: PHP where it should not be, drop-ins, ELF binaries, symlinks, recent and exposed files.
# Worker: launched from lib/audit.sh. Only READS; reports with emit/lines/hits.

job_structure() {
  local now since; now=$(date +%s); since=$((now - RECENT_DAYS * 86400))
  # bloated "Silence is golden" index.php files
  awk -F'\t' '($1 ~ /^\.\/wp-content\/((plugins|themes|mu-plugins)\/)?index\.php$/ || $1 ~ /^\.\/wp-content\/uploads\/(.*\/)?index\.php$/) && $3 > 150 {print $1 " (" $3 " bytes)"}' "$INV" \
    | hits ALERT Structure "index.php 'Silence is golden' with abnormal size (replaced by a backdoor?)"
  # stray PHP in the web root that is not WordPress core
  : > "$TMP/rootphp.benign"
  awk -F'\t' -v ok=" $ROOT_PHP_OK " '$1 ~ /^\.\/[^\/]+\.(php[0-9]?|phtml|phar)$/ { f=substr($1,3); if (index(ok," " f " ")==0) print $1 }' "$INV" \
    | while IFS= read -r f; do if grep -qs '<?' "$f"; then echo "$f"; else echo "$f" >> "$TMP/rootphp.benign"; fi; done \
    | hits ALERT Structure "PHP in the web root that does not belong to WordPress"
  lines WARN Structure ".php file in the web root WITHOUT PHP code inside (probably HTML, like a host's default page; confirm)" < "$TMP/rootphp.benign"
  # PHP where there should be none
  grep -E '^\./wp-content/(languages|upgrade|fonts|bcf-fonts)/' "$TMP/php_all.lst" | grep -vE '\.l10n\.php$|/index\.php$' \
    | hits ALERT Structure "PHP in languages/upgrade/fonts (there should be none)"
  grep -E '^\./wp-content/(cache|litespeed|wflogs)/' "$TMP/php_all.lst" | grep -vE '/index\.php$' \
    | lines WARN Structure "PHP inside cache/log folders (review)"
  # stray files and mu-plugins
  find wp-content -maxdepth 1 -type f ! -name index.php 2>/dev/null | lines ALERT Structure "Stray files in wp-content"
  if [ -d wp-content/mu-plugins ]; then
    # shellcheck disable=SC2086
    printf '%s\n' $KNOWN_MU > "$TMP/known_mu.lst"   # temp file: no <(...) (CageFS has no /dev/fd)
    find wp-content/mu-plugins -mindepth 1 -maxdepth 1 -printf '%f\n' 2>/dev/null | grep -vxF -f "$TMP/known_mu.lst" | hits ALERT Structure "Unknown mu-plugins (always loaded, not visible in the admin panel)"
  fi
  # drop-ins (loaded automatically before everything else)
  local d
  for d in advanced-cache.php object-cache.php db.php db-error.php install.php maintenance.php sunrise.php fatal-error-handler.php php-error.php blog-deleted.php blog-inactive.php blog-suspended.php; do
    [ -f "wp-content/$d" ] && emit WARN Structure "Drop-in present: wp-content/$d (loaded automatically; confirm who installed it)"
  done
  find . -maxdepth 3 -type d \( -name .tmb -o -name .quarantine \) 2>/dev/null | lines WARN Structure "Typical elFinder/File Manager folders (.tmb/.quarantine): that plugin had critical flaws allowing PHP uploads without login; confirm whether you ever had it"
  # odd files in the web root
  awk -F'\t' '$1 ~ /^\.\/[^\/]+$/ {print substr($1,3)}' "$INV" \
    | grep -viE '^(index\.php|wp-[a-z-]+\.php|xmlrpc\.php|license\.txt|readme\.html|robots\.txt|ads\.txt|llms\.txt|humans\.txt|sitemap[^/]*\.xml|favicon\.(ico|png)|\.htaccess|\.user\.ini|\.litespeed_flag|google[0-9a-f]+\.html|BingSiteAuth\.xml|[^/]*\.(ico|png|jpg|webmanifest))$' \
    | lines WARN Structure "Files in the web root that are not WordPress (copies, backups, verification files)"
  # execute bit + ELF binaries
  awk -F'\t' '$1 ~ /^\.\/wp-content\// && $1 !~ /\/(vendor\/bin|node_modules|bin)\// { p=$4; l=substr(p,length(p)-2); if (l ~ /[1357]/) print $1 }' "$INV" | grep -vxFf "$TRUSTED" \
    | lines WARN Structure "Files with the execute bit inside wp-content"
  awk -F'\t' '$1 ~ /^\.\/wp-content\// && $1 !~ /\/[^\/]*\.[^\/.]+$/ && $3 > 1000 {print $1}' "$INV" | head -n 3000 \
    | xargs -d '\n' -r -n 1 -P "$SCAN_PAR" sh -c 'head -c4 "$1" 2>/dev/null | grep -q "^.ELF" && echo "$1"' _ \
    | hits ALERT Structure "ELF binaries inside the site (miners, reverse shells)"
  # permissions
  awk -F'\t' '{ p=$4; l=substr(p,length(p)); if (l ~ /[2367]/) print $1 " (" p ")" }' "$INV" | hits ALERT Structure "World-writable files"
  find . -type d -perm -0002 ! -type l -not -path './wp-content/cache/*' 2>/dev/null | lines ALERT Structure "World-writable folders"
  # symbolic links
  find . -type l -printf '%p -> %l\n' 2>/dev/null | grep -vE '^\./wp-content/cache/' > "$TMP/links.txt"
  grep -E -- '-> /' "$TMP/links.txt" | grep -vF -- "-> $WP_PATH" | hits ALERT Structure "Symbolic links that point outside the site"
  grep -vE -- '-> /' "$TMP/links.txt" | lines WARN Structure "Symbolic links"
  # names with control characters or trailing spaces
  find . \( -name '*[[:cntrl:]]*' -o -name '* ' -o -name '.. *' -o -name '...*' \) 2>/dev/null | hits ALERT Structure "File names with control characters / trailing spaces"
  # hidden files
  find . -mindepth 1 -maxdepth 4 -name '.*' -not -name .htaccess -not -name .user.ini -not -name .well-known -not -name .private -not -name .htpasswd \
    -not -path '*/.well-known/*' -not -path '*/.private/*' -not -path './wp-content/cache/*' 2>/dev/null | lines WARN Structure "Hidden files/folders"
  # exposed files
  awk -F'\t' 'tolower($1) ~ /\.(sql|sql\.gz|sql\.zip|dump)$/ || tolower($1) ~ /\/(\.env[^\/]*|phpinfo\.php|adminer[^\/]*\.php|id_rsa|id_dsa)$/ || tolower($1) ~ /\/wp-config\.(php\.|php~|bak|old|orig|save|swp|txt|backup|copy)/ || tolower($1) ~ /\/wp-config\.php[~.]./ {print $1}' "$INV" \
    | grep -vE '^\./wp-content/(plugins|themes)/' | hits ALERT Structure "Accessible sensitive files (SQL, .env, wp-config copies, phpinfo, adminer)"
  awk -F'\t' 'tolower($1) ~ /\.(zip|tar|tar\.gz|tgz|gz|rar|7z|bz2|bak|old|orig|save|swp|copy|backup)$/ || tolower($1) ~ /\/(error_log|debug\.log)$/ || $1 ~ /~$/ {print $1}' "$INV" \
    | grep -vE '^\./wp-content/(plugins|themes)/' | lines WARN Structure "Copies, archives and logs inside public_html"
  find . -maxdepth 3 \( -name .git -o -name .svn -o -name .idea \) 2>/dev/null | lines WARN Structure "Exposed repository/IDE folder (.git .svn .idea)"
  # recent files (unverified)
  local flt='tolower($1) ~ /\.(php[0-9]?|phtml|phar|inc|js|mjs|html?|svg|ini)$/ || tolower($1) ~ /\/\.htaccess$/'
  awk -F'\t' -v since="$since" "NR==FNR{t[\$0]=1;next} !(\$1 in t) && \$2>=since && ($flt) && \$1 !~ /^\.\/wp-content\/(cache|litespeed|wflogs|upgrade|languages|uploads)\// && \$1 !~ /^\.\/wp-content\/(plugins|themes)\// {print \$2 \"\t\" \$1}" "$TRUSTED" "$INV" \
    | sort -rn | head -n 60 | while IFS=$'\t' read -r ts p; do printf '%s  %s\n' "$(date -d "@$ts" '+%F %H:%M')" "$p"; done \
    | lines WARN Structure "New/modified files in the last $RECENT_DAYS days (outside plugins/themes)" 40
  awk -F'\t' -v since="$since" "NR==FNR{t[\$0]=1;next} !(\$1 in t) && \$2>=since && ($flt) && \$1 ~ /^\.\/wp-content\/(plugins|themes)\// {print \$2 \"\t\" \$1}" "$TRUSTED" "$INV" \
    | sort -rn | head -n 60 | while IFS=$'\t' read -r ts p; do printf '%s  %s\n' "$(date -d "@$ts" '+%F %H:%M')" "$p"; done \
    | lines WARN Structure "Files modified in the last $RECENT_DAYS days inside plugins/themes WITHOUT checksum verification" 40
  awk -F'\t' -v lim="$((now + 86400))" '$2 > lim {print $1}' "$INV" | lines WARN Structure "Files with a modification date in the future (tampered timestamp)"
  awk -F'\t' 'NR==FNR{t[$0]=1;next} !($1 in t) && tolower($1) ~ /\.(php[0-9]?|phtml|phar|inc|js|html?)$/ && $1 !~ /^\.\/wp-content\/(cache|litespeed|wflogs|upgrade|uploads)\// {print $2 "\t" $1}' "$TRUSTED" "$INV" \
    | sort -rn | head -n 12 | while IFS=$'\t' read -r ts p; do printf '%s  %s\n' "$(date -d "@$ts" '+%F %H:%M')" "$p"; done \
    | lines INFO Structure "Most recently modified code files (timeline)" 12
}
