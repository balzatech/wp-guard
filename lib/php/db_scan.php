<?php
@ini_set('memory_limit', '768M'); @set_time_limit(0);
global $wpdb; $p = $wpdb->prefix;
$shard = (int) getenv('SHARD'); $shards = max(1, (int) getenv('SHARDS'));
function out($l, $t) { echo $l."\t".str_replace(array("\r", "\n", "\t"), ' ', $t)."\n"; }
function envlist($k) { return array_values(array_filter(preg_split('/[\s,]+/', (string) getenv($k)))); }
$allowed = envlist('ALLOWED_ADMINS'); $known = envlist('KNOWN_HOSTS'); $iocs = envlist('IOC_LIST'); $ignore = envlist('IGNORE_LOCS');
$site = (string) getenv('SITE_URL'); $expMail = (string) getenv('EXPECTED_ADMIN_EMAIL');
function is_known($h, $known) {
  $h = strtolower($h);
  foreach ($known as $k) { if ($h === $k || substr($h, -strlen($k) - 1) === '.'.$k) return true; }
  return false;
}
$wpdb->suppress_errors(true); $wpdb->query('SET SESSION MAX_EXECUTION_TIME=120000'); $wpdb->suppress_errors(false);

if ($shard === 0) {
  // ---- Users and roles
  $high = array('manage_options','edit_plugins','install_plugins','activate_plugins','edit_themes','install_themes','update_core','switch_themes','unfiltered_upload','edit_files');
  $med  = array('edit_users','create_users','promote_users','delete_users');
  $roles = wp_roles()->roles;
  foreach (get_users() as $u) {
    out('INFO', "User {$u->ID} {$u->user_login} [".implode(',', $u->roles)."] registered {$u->user_registered}");
    $ok = in_array($u->user_login, $allowed, true);
    if (in_array('administrator', $u->roles, true) && !$ok)
      out('ALERT', "UNAUTHORIZED ADMIN: {$u->ID} | {$u->user_login} | {$u->user_email} | {$u->user_registered}");
    foreach ((array) $u->caps as $cap => $v) {
      if ($v && !isset($roles[$cap]) && !$ok && in_array($cap, array_merge($high, $med), true))
        out('ALERT', "User {$u->user_login} has a stray capability '$cap' (outside their role)");
    }
    if (strtotime($u->user_registered) > time() - 14 * 86400)
      out('WARN', "User created in the last 14 days: {$u->user_login} [".implode(',', $u->roles)."] {$u->user_registered}");
  }
  foreach ($roles as $slug => $r) {
    if ($slug === 'administrator') continue;
    $caps = array_keys(array_filter((array) $r['capabilities']));
    $b = array_intersect($high, $caps); if ($b) out('ALERT', "Role '$slug' has administrator capabilities: ".implode(',', $b));
    $b = array_intersect($med, $caps);  if ($b) out('WARN',  "Role '$slug' can manage users: ".implode(',', $b));
  }
  $n = $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->usermeta} WHERE meta_key='_application_passwords'");
  if ($n > 0) out('WARN', "$n user(s) have application passwords (API access). Review them in the user profile.");

  // ---- Dangerous options
  if (get_option('users_can_register')) out('ALERT', "User registration is OPEN (users_can_register=1)");
  if (get_option('default_role') !== 'subscriber') out('ALERT', "default_role is '".get_option('default_role')."' (it should be subscriber)");
  foreach (array('siteurl', 'home') as $o) {
    if (rtrim(get_option($o), '/') !== rtrim($site, '/')) out('ALERT', "$o changed: ".get_option($o));
  }
  if ($expMail !== '' && strcasecmp(get_option('admin_email'), $expMail) !== 0) out('ALERT', "admin_email changed: ".get_option('admin_email'));
  foreach (array('ihaf_insert_header', 'ihaf_insert_body', 'ihaf_insert_footer') as $o) {
    $v = get_option($o); if (!empty($v)) out('ALERT', "Header/footer injection option has content: $o (".strlen($v)." characters)");
  }
  out('INFO', "Administrator email: ".get_option('admin_email')." | visible to search engines: ".(get_option('blog_public') ? 'yes' : 'no'));
  foreach (array('template', 'stylesheet') as $o) {
    $t = get_option($o); if ($t && !wp_get_theme($t)->exists()) out('WARN', "Option $o points to a theme that does not exist: $t");
  }
  foreach ((array) get_option('active_plugins', array()) as $pl) {
    if (strpos($pl, '..') !== false) out('ALERT', "Active plugin with a strange path: $pl");
    elseif (!file_exists(WP_PLUGIN_DIR.'/'.$pl)) out('WARN', "Active plugin whose file does not exist: $pl (if someone uploads that folder again it activates itself; remove it from the active_plugins option)");
  }
  $rows = $wpdb->get_results("SELECT option_name AS n, LEFT(option_value, 700) AS v, LENGTH(option_value) AS l FROM {$p}options WHERE LENGTH(option_value) > 700 AND option_name NOT LIKE '\\_transient%' AND option_name NOT LIKE '\\_site\\_transient%' LIMIT 3000");
  foreach ($rows as $r) {
    if (preg_match('/^[A-Za-z0-9+\/=\s]{690,}$/', substr($r->v, 0, 700))) out('WARN', "Option with a base64-like blob: {$r->n} ({$r->l} bytes)");
  }

  // ---- Suspicious posts by title
  foreach ($wpdb->get_results("SELECT ID, post_status, post_date, post_title FROM {$p}posts WHERE post_title LIKE '%SEO Super Tool%' OR post_title LIKE '%Probe %'") as $r)
    out('ALERT', "Suspicious post ID {$r->ID} [{$r->post_status}] {$r->post_date}: {$r->post_title}");

  // ---- SEO spam
  $spam = array('viagra','cialis','casino','porn','payday','escort','sbobet','gacor','togel','slot online','replica watch','bandar judi');
  foreach ($spam as $s) {
    $l = '%'.$wpdb->esc_like($s).'%';
    $ids = $wpdb->get_col($wpdb->prepare("SELECT ID FROM {$p}posts WHERE post_status='publish' AND post_type IN ('post','page') AND (post_content LIKE %s OR post_title LIKE %s) LIMIT 10", $l, $l));
    if ($ids) out('WARN', "Possible '$s' spam in published content: IDs ".implode(',', $ids));
  }
  $ids = $wpdb->get_col("SELECT ID FROM {$p}posts WHERE post_status='publish' AND post_type IN ('post','page') AND post_content LIKE '%<a %' AND (post_content LIKE '%left:-9999%' OR post_content LIKE '%text-indent:-9999%') LIMIT 30");
  if ($ids) out('WARN', "Links hidden off-screen (SEO spam) in IDs: ".implode(',', $ids));
  $hosts = array();
  foreach ($wpdb->get_results("SELECT ID, post_content FROM {$p}posts WHERE post_status='publish' AND post_type IN ('post','page') LIMIT 3000") as $r) {
    if (preg_match_all('#href\s*=\s*["\']https?://([a-z0-9.-]+)#i', $r->post_content, $m)) {
      foreach (array_unique($m[1]) as $h) { if (!is_known($h, $known)) { $hosts[$h] = (isset($hosts[$h]) ? $hosts[$h] : 0) + 1; } }
    }
  }
  if ($hosts) { arsort($hosts); $o = array(); foreach (array_slice($hosts, 0, 15, true) as $h => $c) $o[] = "$h x$c";
    out('WARN', "External links in published content (unknown domains): ".implode(', ', $o)); }

  // ---- Cron hooks that are not recognized
  $pre = array('wp_','action_scheduler','litespeed','monsterinsights','wpseo','aioseo','elementor','googlesitekit','hostinger','puc_',
    'recovery_mode','delete_expired','wordfence','wf','pbb_','run_weekly','wpcode','gutenkit','kadence','essential','eael','pys','pixelyoursite',
    'duracell','gtm4wp','wpur','cimo','wpcf7','jetpack','woocommerce','wpforms','popup');
  $odd = array(); $cron = _get_cron_array();
  if (is_array($cron)) foreach ($cron as $ts => $evs) { if (!is_array($evs)) continue; foreach ($evs as $h => $x) {
    $ok = false; foreach ($pre as $pf) { if (strpos($h, $pf) === 0) { $ok = true; break; } } if (!$ok) $odd[$h] = 1; } }
  if ($odd) out('WARN', "Unrecognized cron hooks: ".implode(', ', array_slice(array_keys($odd), 0, 15)));

  // ---- Tables outside the prefix
  $foreign = array();
  foreach ($wpdb->get_col('SHOW TABLES') as $t) { if (strpos($t, $p) !== 0) $foreign[] = $t; }
  if ($foreign) out('INFO', "Tables that do not use the prefix $p: ".implode(', ', array_slice($foreign, 0, 15)));

  // ---- Database size
  $tot = $wpdb->get_var($wpdb->prepare("SELECT ROUND(SUM(data_length+index_length)/1048576,2) FROM information_schema.tables WHERE table_schema=%s", DB_NAME));
  out('INFO', "DATABASE: $tot MB in total");
  $tb = array();
  foreach ($wpdb->get_results($wpdb->prepare("SELECT table_name AS n, ROUND((data_length+index_length)/1048576,2) AS mb, table_rows AS r FROM information_schema.tables WHERE table_schema=%s ORDER BY (data_length+index_length) DESC LIMIT 10", DB_NAME)) as $r)
    $tb[] = "{$r->n}: {$r->mb} MB (~{$r->r} rows)";
  out('INFO', "Largest tables -> ".implode(' | ', $tb));
  $mk = array();
  foreach ($wpdb->get_results("SELECT meta_key AS k, COUNT(*) AS c, ROUND(SUM(LENGTH(meta_value))/1048576,2) AS mb FROM {$p}postmeta GROUP BY meta_key ORDER BY SUM(LENGTH(meta_value)) DESC LIMIT 5") as $r)
    $mk[] = "{$r->k}: {$r->mb} MB in {$r->c} rows";
  out('INFO', "Largest postmeta keys -> ".implode(' | ', $mk));
  $ok = array();
  foreach ($wpdb->get_results("SELECT option_name AS n, ROUND(LENGTH(option_value)/1024) AS kb FROM {$p}options ORDER BY LENGTH(option_value) DESC LIMIT 6") as $r)
    $ok[] = "{$r->n}: {$r->kb} KB";
  out('INFO', "Largest options -> ".implode(' | ', $ok));
  out('INFO', "Accumulated content -> revisions: ".$wpdb->get_var("SELECT COUNT(*) FROM {$p}posts WHERE post_type='revision'")
    ." | trash: ".$wpdb->get_var("SELECT COUNT(*) FROM {$p}posts WHERE post_status='trash'")
    ." | auto-drafts: ".$wpdb->get_var("SELECT COUNT(*) FROM {$p}posts WHERE post_status='auto-draft'")
    ." | transients: ".$wpdb->get_var("SELECT COUNT(*) FROM {$p}options WHERE option_name LIKE '\\_transient%' OR option_name LIKE '\\_site\\_transient%'")
    ." | autoloaded options: ".round($wpdb->get_var("SELECT SUM(LENGTH(option_value)) FROM {$p}options WHERE autoload IN ('yes','on','auto','auto-on')")/1024)." KB");
  if ($wpdb->get_var("SHOW TABLES LIKE '{$p}actionscheduler_actions'"))
    out('INFO', "Action Scheduler -> actions: ".$wpdb->get_var("SELECT COUNT(*) FROM {$p}actionscheduler_actions")." | logs: ".$wpdb->get_var("SELECT COUNT(*) FROM {$p}actionscheduler_logs"));
  foreach ($wpdb->get_results("SELECT ID, post_type, post_status, post_modified, LEFT(post_title,40) AS t FROM {$p}posts WHERE post_modified >= DATE_SUB(NOW(), INTERVAL 45 DAY) AND post_type NOT IN ('revision','nav_menu_item','customize_changeset','oembed_cache') ORDER BY post_modified DESC LIMIT 25") as $r)
    out('INFO', "Recent change: {$r->post_modified} | {$r->post_type} | {$r->post_status} | ID {$r->ID} | {$r->t}");
}

// ---- Deep scan of ALL tables (spread across the shards by size)
$likes = array('<script', 'u003cscript', 'javascript:', 'onerror=', 'onload=', '<iframe', '<?php', 'base64_decode(', 'document.write',
               'fromcharcode', 'atob(', 'clipboard', 'mshta', 'powershell');
foreach ($iocs as $i) $likes[] = $i;
$generic = array('clipboard.writeText', "execCommand('copy')", 'atob(', 'fromCharCode', 'eval(', 'document.write(', 'mshta', 'powershell',
                 'verify you are human', '<?php', 'base64_decode(');
$tables = $wpdb->get_col($wpdb->prepare("SELECT table_name FROM information_schema.tables WHERE table_schema=%s ORDER BY (data_length+index_length) DESC", DB_NAME));
$scanned = 0; $rowsWithScript = 0; $i = 0;
foreach ($tables as $t) {
  if ($i++ % $shards !== $shard) continue;
  if (strpos($t, $p.'wf') === 0) continue;                    // Wordfence logs (they store attacks)
  $pkr = $wpdb->get_row("SHOW KEYS FROM `$t` WHERE Key_name='PRIMARY'");
  $pkc = $pkr ? $pkr->Column_name : null;
  foreach ($wpdb->get_results("SHOW COLUMNS FROM `$t`") as $c) {
    if (!preg_match('/char|text|blob|json/i', $c->Type)) continue;
    $col = $c->Field; $scanned++;
    $parts = array(); foreach ($likes as $lk) { $parts[] = $wpdb->prepare("`$col` LIKE %s", '%'.$wpdb->esc_like($lk).'%'); }
    $sel = $pkc ? "`$pkc` AS pk" : "NULL AS pk";
    $rows = $wpdb->get_results("SELECT $sel, `$col` AS v FROM `$t` WHERE ".implode(' OR ', $parts)." LIMIT 500");
    if (!$rows) continue;
    foreach ($rows as $r) {
      $loc = "$t.$col#".$r->pk;
      if (in_array($loc, $ignore, true)) continue;
      $rowsWithScript++;
      $v = str_replace(array('\\u003c', '\\u003e', '\\u0026', '\\/'), array('<', '>', '&', '/'), (string) $r->v);
      $weird = array();
      if (preg_match_all('#<script\b([^>]*)>(.*?)</script>#is', $v, $m, PREG_SET_ORDER)) foreach ($m as $s) {
        if (preg_match('#src\s*=\s*["\']?((?:https?:)?//[^"\'\s>]+)#i', $s[1], $sm)) {
          $h = parse_url((strpos($sm[1], '//') === 0 ? 'https:' : '').$sm[1], PHP_URL_HOST);
          if ($h && !is_known($h, $known)) $weird[] = "src:$h";
        }
        if (preg_match_all('#https?://([a-z0-9.-]+)#i', $s[2], $um)) foreach (array_unique($um[1]) as $h) {
          if (!is_known($h, $known)) $weird[] = "inline:$h";
        }
      }
      if (preg_match_all('#<iframe\b[^>]*\bsrc\s*=\s*["\']?((?:https?:)?//[^"\'\s>]+)#i', $v, $im)) foreach ($im[1] as $u) {
        $h = parse_url((strpos($u, '//') === 0 ? 'https:' : '').$u, PHP_URL_HOST);
        if ($h && !is_known($h, $known)) $weird[] = "iframe:$h";
      }
      $hit = array(); foreach ($iocs as $k) { if (stripos($v, $k) !== false) $hit[] = $k; }
      $gen = array(); foreach ($generic as $k) { if (stripos($v, $k) !== false) $gen[] = $k; }
      if ($hit) out('ALERT', "KNOWN INJECTION in $loc | markers: ".implode(',', $hit)." | others: ".implode(',', $gen)." | domains: ".implode(',', array_unique($weird)));
      elseif ($weird) out('WARN', "Script/iframe with an unknown domain in $loc | ".implode(',', array_unique($weird)));
      elseif ($gen) out('WARN', "Content with risky functions in $loc | ".implode(',', $gen));
    }
  }
}
out('INFO', "Deep scan (shard ".($shard + 1)."/$shards): $scanned text columns checked, $rowsWithScript rows with scripts/handlers.");
