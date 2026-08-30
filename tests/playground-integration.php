<?php
/**
 * WordPress Playground integration smoke test.
 *
 * Run with the plugin mounted at /wordpress/wp-content/plugins/enterprise-login-defense.
 */

require_once '/wordpress/wp-load.php';

if (!defined('ABSPATH')) {
    throw new RuntimeException('WordPress was not bootstrapped.');
}

require_once ABSPATH . 'wp-admin/includes/plugin.php';

$plugin_dir = basename(dirname(__DIR__));
$plugin_file = $plugin_dir . '/inkfire-login-styler.php';
if (!is_plugin_active($plugin_file)) {
    $result = activate_plugin($plugin_file);
    if (is_wp_error($result)) {
        throw new RuntimeException($result->get_error_message());
    }
}

function ifls_playground_assert($condition, $message) {
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

ifls_playground_assert(class_exists('IFLS_Enterprise_Security'), 'Security class did not load.');
ifls_playground_assert(get_option('ifls_events_db_version') === IFLS_Event_Log::DB_VERSION, 'Event table schema was not installed on activation.');
ifls_playground_assert((bool) wp_next_scheduled('ifls_prune_events'), 'Prune cron was not scheduled on activation.');
ifls_playground_assert((bool) wp_next_scheduled('ifls_dispatch_incidents'), 'Incident cron was not scheduled on activation.');

$security_checks = IFLS_Security_Status::checks();
ifls_playground_assert('green' === $security_checks['application']['tone'], 'The dashboard did not detect the application throttle.');
ifls_playground_assert('amber' === $security_checks['overall']['tone'], 'An unverified external layer must report application-only amber.');

update_option(IFLS_Security_Status::OPTION, [
    'edge' => [
        'host' => IFLS_Security_Status::site_host(),
        'verified_at' => time(),
        'verified_by' => 1,
    ],
], false);
$security_checks = IFLS_Security_Status::checks();
ifls_playground_assert('current' === $security_checks['edge']['state'], 'A current hostname-bound edge verification was not recognised.');
ifls_playground_assert('green' === $security_checks['overall']['tone'], 'A current edge verification did not produce layered green status.');

update_option(IFLS_Security_Status::OPTION, [
    'edge' => [
        'host' => 'copied-database.invalid',
        'verified_at' => time(),
        'verified_by' => 1,
    ],
], false);
ifls_playground_assert('none' === IFLS_Security_Status::verification_status('edge'), 'A verification copied from another hostname was trusted.');
delete_option(IFLS_Security_Status::OPTION);

$diagnostic_settings = ifls_diag_defaults();
$diagnostic_settings['logging_enabled'] = false;
update_option('ifls_diagnostics_settings', $diagnostic_settings, false);
$security_checks = IFLS_Security_Status::checks();
ifls_playground_assert(false === $security_checks['telemetry']['foundation_logging'], 'Disabled Foundation logging was reported as active.');
ifls_playground_assert('red' === $security_checks['telemetry']['tone'], 'A site with no active failed-login logger must report red.');
delete_option('ifls_diagnostics_settings');

$ip = '203.0.113.77';
$username = 'playground-rate-limit-user';
$_SERVER['REMOTE_ADDR'] = $ip;
$_SERVER['REQUEST_METHOD'] = 'POST';

$security = IFLS_Enterprise_Security::get_instance();
$security->clear_attempts_for($username, $ip);

$captured_status = null;
add_filter('status_header', function($status, $code) use (&$captured_status) {
    $captured_status = (int) $code;
    return $status;
}, 999, 2);

for ($i = 0; $i < IFLS_MAX_LOGIN_ATTEMPTS; $i++) {
    do_action('wp_login_failed', $username, new WP_Error('incorrect_password', 'Invalid credentials.'));
}

ifls_playground_assert(IFLS_MAX_LOGIN_ATTEMPTS === $security->get_attempts_for($username, $ip), 'wp_login_failed did not increment the Foundation identity counter.');
$result = $security->check_login_attempts(null, $username, 'invalid-password');
ifls_playground_assert(is_wp_error($result) && 'too_many_attempts' === $result->get_error_code(), 'Authentication was not rejected at the identity threshold.');
ifls_playground_assert(429 === $captured_status, 'The integration path did not emit HTTP 429.');

// WordPress emits wp_login_failed for a WP_Error authentication result. The
// request-local throttle flag must keep this from producing another failure or
// lockout row.
do_action('wp_login_failed', $username, $result);
$rows = IFLS_Event_Log::query(['search' => $username, 'limit' => 100]);
$events = array_count_values(array_map(function($row) { return $row->event; }, $rows));
ifls_playground_assert(IFLS_MAX_LOGIN_ATTEMPTS === ($events['login_failed'] ?? 0), 'Throttled request created a duplicate failed-login row.');
ifls_playground_assert(1 === ($events['lockout'] ?? 0), 'Lockout sampling did not produce exactly one row.');

echo "WordPress Playground integration passed.\n";
