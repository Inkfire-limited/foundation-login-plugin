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

// wp_die otherwise renders an error page and exits successfully under this CLI.
add_filter('wp_die_handler', static function () {
    return static function ($message) {
        throw new RuntimeException(is_scalar($message) ? (string) $message : 'WordPress terminated the integration test.');
    };
});

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

// Exercise the real options table and WP hooks. All transport calls are intercepted.
IFLS_Incident_Reporter::clear();
foreach (['first', 'second', 'third'] as $kind) {
    IFLS_Incident_Reporter::raise($kind, 'Test alert');
}
$deliveries = 0;
$transport = static function () use (&$deliveries) {
    ++$deliveries;
    IFLS_Incident_Reporter::raise('third', 'Test alert'); // Simulate new evidence while transport is in flight.
    do_action('wp_mail_failed', new WP_Error('test', 'Synthetic diagnostic failure'));
    IFLS_Incident_Reporter::dispatch(); // A second runner must not take another batch.
    return false;
};
add_filter('pre_wp_mail', $transport);
do_action('shutdown');
IFLS_Incident_Reporter::dispatch();
ifls_playground_assert(0 === $deliveries, 'Ordinary shutdown or direct dispatch sent incident mail.');
add_filter('wp_doing_cron', '__return_true');
add_filter('ifls_allow_incident_email_dispatch', '__return_false');
IFLS_Incident_Reporter::dispatch();
ifls_playground_assert(0 === $deliveries, 'The site mail pause was ignored.');
remove_filter('ifls_allow_incident_email_dispatch', '__return_false');
IFLS_Incident_Reporter::dispatch();
$incidents = IFLS_Incident_Reporter::incidents();
ifls_playground_assert(2 === $deliveries && 3 === count($incidents), 'The first cron batch exceeded its limit or recursed through wp_mail_failed.');
IFLS_Incident_Reporter::dispatch();
ifls_playground_assert(2 === $deliveries, 'The same dispatch window was reused.');

// Advance simulated time in storage, without relying on sleep.
function ifls_test_next_window() {
    global $wpdb;
    $wpdb->update($wpdb->options, ['option_value' => '0'], ['option_name' => IFLS_Incident_Reporter::DISPATCH_WINDOW]);
}
ifls_test_next_window();
IFLS_Incident_Reporter::dispatch();
ifls_playground_assert(3 === $deliveries, 'Backoff did not leave only the third alert due.');
$rows = IFLS_Incident_Reporter::incidents();
$rows = [$rows[0]];
$rows[0]['next_attempt'] = 0;
update_option(IFLS_Incident_Reporter::OPTION, $rows, false);
for ($attempt = 2; $attempt <= 3; $attempt++) {
    ifls_test_next_window();
    IFLS_Incident_Reporter::dispatch();
    $rows = IFLS_Incident_Reporter::incidents();
    ifls_playground_assert($attempt === $rows[0]['attempts'], 'Retry count was not persisted.');
    $rows[0]['next_attempt'] = 0;
    $rows[0]['first_seen'] = time() - DAY_IN_SECONDS;
    update_option(IFLS_Incident_Reporter::OPTION, $rows, false);
}
IFLS_Incident_Reporter::raise($rows[0]['type'], 'Test alert');
ifls_test_next_window();
IFLS_Incident_Reporter::dispatch();
ifls_playground_assert(5 === $deliveries, 'An exhausted incident was rearmed or retried.');
$rows = IFLS_Incident_Reporter::incidents();
unset($rows[0]['attempts'], $rows[0]['next_attempt']);
update_option(IFLS_Incident_Reporter::OPTION, $rows, false);
IFLS_Incident_Reporter::dispatch();
ifls_playground_assert(5 === $deliveries, 'A legacy failed incident with unknown attempt count was replayed.');

remove_filter('pre_wp_mail', $transport);
add_filter('pre_wp_mail', '__return_true');
IFLS_Incident_Reporter::raise('healthy', 'Successful synthetic delivery');
IFLS_Incident_Reporter::dispatch();
$rows = IFLS_Incident_Reporter::incidents();
ifls_playground_assert('sent' === $rows[0]['status'] && 1 === $rows[0]['attempts'], 'A successful alert was not marked sent.');
remove_filter('pre_wp_mail', '__return_true');
remove_filter('wp_doing_cron', '__return_true');
do_action('wp_mail_failed', new WP_Error('test', 'An unrelated mail failure'));
$rows = IFLS_Incident_Reporter::incidents();
ifls_playground_assert('mail_failure' === $rows[0]['type'], 'Unrelated transport failures stopped reaching Diagnostics.');

$reset_mail = 0;
$capture_reset = static function () use (&$reset_mail) {
    ++$reset_mail;
    return true;
};
add_filter('pre_wp_mail', $capture_reset);
$_POST['ifls_form_nonce'] = wp_create_nonce('ifls_form_action');
$user = wp_insert_user(['user_login' => 'ifls_reset_fixture', 'user_pass' => wp_generate_password(), 'user_email' => 'fixture@example.invalid']);
ifls_playground_assert(!is_wp_error($user) && true === retrieve_password('ifls_reset_fixture'), 'WordPress account recovery failed.');
ifls_playground_assert(1 === $reset_mail, 'Core account recovery did not reach the intercepted mail transport exactly once.');
remove_filter('pre_wp_mail', $capture_reset);

echo "WordPress Playground integration passed.\n";
