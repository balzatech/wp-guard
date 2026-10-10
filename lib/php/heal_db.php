<?php
$apply = getenv('APPLY') === '1';
$allowed = preg_split('/[\s,]+/', (string) getenv('ALLOWED_ADMINS'), -1, PREG_SPLIT_NO_EMPTY);
$admins = get_users(array('role' => 'administrator')); $okcount = 0;
foreach ($admins as $u) { if (in_array($u->user_login, $allowed, true)) $okcount++; }
foreach ($admins as $u) {
  if (in_array($u->user_login, $allowed, true)) continue;
  if ($okcount === 0) { echo "SKIPPED: no administrator matches ALLOWED_ADMINS (misconfigured?), nobody will be demoted\n"; break; }
  echo "DB           unauthorized admin {$u->user_login} (ID {$u->ID}): demote to subscriber and end their sessions\n";
  if ($apply) { $u->set_role('subscriber'); WP_Session_Tokens::get_instance($u->ID)->destroy_all(); }
}
if (get_option('users_can_register')) { echo "DB           user registration is open: close it\n"; if ($apply) update_option('users_can_register', 0); }
if (get_option('default_role') !== 'subscriber') { echo "DB           default_role is not subscriber: fix it\n"; if ($apply) update_option('default_role', 'subscriber'); }
$a = (array) get_option('active_plugins', array());
$b = array_values(array_filter($a, function ($p) { return file_exists(WP_PLUGIN_DIR . '/' . $p); }));
if (count($a) !== count($b)) { echo "DB           remove active plugins that do not exist: " . implode(',', array_diff($a, $b)) . "\n"; if ($apply) update_option('active_plugins', $b); }
