<?php
/**
 * Isolated regression tests for the authentication throttle.
 *
 * These tests intentionally load only IFLS_Enterprise_Security from the main
 * plugin file. The small WordPress shim makes the security state machine run
 * on every supported CI PHP version without requiring a database or web server.
 */

define('ABSPATH', __DIR__ . '/');
define('IFLS_MAX_LOGIN_ATTEMPTS', 5);
define('IFLS_LOCKOUT_TIME', 900);
define('IFLS_MAX_IP_ATTEMPTS', 20);
define('IFLS_IP_LOCKOUT_TIME', 900);
define('IFLS_AUTH_TELEMETRY_OWNER', 'foundation');

$ifls_test_transients = [];
$ifls_test_hooks = [];
$ifls_test_status = null;

function add_action($hook, $callback, $priority = 10, $accepted_args = 1) {
    global $ifls_test_hooks;
    $ifls_test_hooks[] = ['action', $hook, $callback, $priority, $accepted_args];
}

function add_filter($hook, $callback, $priority = 10, $accepted_args = 1) {
    global $ifls_test_hooks;
    $ifls_test_hooks[] = ['filter', $hook, $callback, $priority, $accepted_args];
}

function get_transient($key) {
    global $ifls_test_transients;
    return array_key_exists($key, $ifls_test_transients) ? $ifls_test_transients[$key] : false;
}

function set_transient($key, $value, $expiration = 0) {
    global $ifls_test_transients;
    $ifls_test_transients[$key] = $value;
    return true;
}

function delete_transient($key) {
    global $ifls_test_transients;
    unset($ifls_test_transients[$key]);
    return true;
}

function wp_salt($scheme = 'auth') {
    return 'test-only-key-' . $scheme;
}

function wp_unslash($value) {
    return $value;
}

function absint($value) {
    return abs((int) $value);
}

function __($text, $domain = 'default') {
    return $text;
}

function status_header($code) {
    global $ifls_test_status;
    $ifls_test_status = (int) $code;
}

function nocache_headers() {
    return null;
}

function is_wp_error($value) {
    return $value instanceof WP_Error;
}

function wp_nonce_field($action, $name) {}
function is_admin() { return false; }
function is_user_logged_in() { return false; }
function wp_doing_ajax() { return false; }
function current_user_can($capability, ...$args) { return false; }
function sanitize_key($value) { return preg_replace('/[^a-z0-9_\-]/', '', strtolower((string) $value)); }
function wp_verify_nonce($nonce, $action) { return true; }
function current_action() { return 'test'; }
function wp_die($message = '', $title = '', $args = []) { throw new RuntimeException((string) $message); }
function get_userdata($user_id) { return false; }

class WP_Error {
    public $code;
    public $message;

    public function __construct($code = '', $message = '') {
        $this->code = $code;
        $this->message = $message;
    }
}

class IFLS_Event_Log {
    public static $events = [];

    public static function record($event, array $args = []) {
        self::$events[] = [$event, $args];
    }
}

function ifls_test_assert($condition, $message) {
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function ifls_test_reset() {
    global $ifls_test_transients, $ifls_test_status;
    $ifls_test_transients = [];
    $ifls_test_status = null;
    IFLS_Event_Log::$events = [];
    unset($GLOBALS['ifls_login_throttled'], $GLOBALS['ifls_inline_login_honeypot_blocked']);
    $_POST = [];
    $_REQUEST = [];
    $_SERVER = [
        'REMOTE_ADDR' => '203.0.113.10',
        'REQUEST_METHOD' => 'POST',
    ];
}

// Load the exact production class while avoiding bootstrap side effects.
$plugin = file_get_contents(dirname(__DIR__) . '/inkfire-login-styler.php');
$start = strpos($plugin, 'class IFLS_Enterprise_Security');
$end = strpos($plugin, 'IFLS_Enterprise_Security::get_instance();', $start);
if (false === $start || false === $end) {
    throw new RuntimeException('Unable to locate IFLS_Enterprise_Security in the plugin bootstrap.');
}
eval(substr($plugin, $start, $end - $start));

$security = IFLS_Enterprise_Security::get_instance();

// The AIOS compatibility filter must receive all five documented arguments.
$aios_hooks = array_values(array_filter($ifls_test_hooks, function($hook) {
    return 'filter' === $hook[0] && 'aios_audit_log_record_event' === $hook[1];
}));
ifls_test_assert(1 === count($aios_hooks), 'AIOS compatibility filter was not registered exactly once.');
ifls_test_assert(5 === $aios_hooks[0][4], 'AIOS compatibility filter must accept five arguments.');

// Foundation-owned telemetry suppresses only AIOS failed-login duplication.
ifls_test_assert(false === $security->filter_aios_auth_event(true, 'failed_login', [], 'warning', 'bot'), 'Duplicate AIOS failed-login telemetry was not suppressed.');
ifls_test_assert(true === $security->filter_aios_auth_event(true, 'plugin_updated', [], 'info', 'admin'), 'Non-authentication AIOS telemetry must be preserved.');

// Forwarded headers are attacker-controlled unless the origin has established
// a trusted proxy boundary. They must not influence the transient identity.
ifls_test_reset();
$_SERVER['HTTP_X_FORWARDED_FOR'] = '198.51.100.1';
$security->log_failed_attempt('admin');
$first_keys = array_keys($ifls_test_transients);
$_SERVER['HTTP_X_FORWARDED_FOR'] = '198.51.100.2';
$security->log_failed_attempt('admin');
$second_keys = array_keys($ifls_test_transients);
sort($first_keys);
sort($second_keys);
ifls_test_assert($first_keys === $second_keys, 'Spoofed forwarded headers changed the rate-limit identity.');
foreach ($second_keys as $key) {
    ifls_test_assert(false === strpos($key, 'admin') && false === strpos($key, '203.0.113.10'), 'Transient keys exposed raw authentication identifiers.');
}

// A missing trustworthy address must fail open. Treating every non-HTTP or
// malformed request as 0.0.0.0 would let WP-CLI and cron share one global ban.
ifls_test_reset();
unset($_SERVER['REMOTE_ADDR']);
for ($i = 0; $i < IFLS_MAX_IP_ATTEMPTS + 1; $i++) {
    $security->log_failed_attempt('no-address-' . $i);
}
ifls_test_assert([] === $ifls_test_transients, 'A request without a trustworthy address created throttle state.');
ifls_test_assert(null === $security->check_login_attempts(null, 'no-address', 'wrong'), 'A request without a trustworthy address was blocked.');

// Five failed attempts lock the identity. Repeated blocked POSTs produce one
// sampled log row and a 429 response instead of amplifying database writes.
ifls_test_reset();
for ($i = 0; $i < IFLS_MAX_LOGIN_ATTEMPTS; $i++) {
    $security->log_failed_attempt('admin');
}
$blocked = $security->check_login_attempts(null, 'admin', 'wrong');
ifls_test_assert($blocked instanceof WP_Error && 'too_many_attempts' === $blocked->code, 'Identity threshold did not block authentication.');
ifls_test_assert(429 === $ifls_test_status, 'Throttled authentication did not set HTTP 429.');
$security->check_login_attempts(null, 'admin', 'wrong-again');
$lockouts = array_values(array_filter(IFLS_Event_Log::$events, function($event) { return 'lockout' === $event[0]; }));
ifls_test_assert(1 === count($lockouts), 'Repeated blocked requests created duplicate lockout log rows.');

// Rotating usernames from one address still trips the IP-wide threshold.
ifls_test_reset();
for ($i = 0; $i < IFLS_MAX_IP_ATTEMPTS; $i++) {
    $security->log_failed_attempt('rotating-user-' . $i);
}
$blocked = $security->check_login_attempts(null, 'new-username', 'wrong');
ifls_test_assert($blocked instanceof WP_Error, 'IP-wide threshold was bypassed by rotating usernames.');
$lockouts = array_values(array_filter(IFLS_Event_Log::$events, function($event) { return 'lockout' === $event[0]; }));
ifls_test_assert('ip' === $lockouts[0][1]['detail']['scope'], 'IP-wide lockout was not classified correctly.');

// The branded form honeypot blocks without consuming a legitimate allowance.
ifls_test_reset();
$_POST['ifls_login_form'] = 'inline';
$_POST['ifls_login_website'] = 'https://spam.example';
$blocked = $security->reject_inline_login_honeypot(null, 'bot', 'wrong');
ifls_test_assert($blocked instanceof WP_Error && 'ifls_login_honeypot' === $blocked->code, 'Inline honeypot did not reject a populated trap.');
$security->log_failed_attempt('bot');
ifls_test_assert(1 === count(IFLS_Event_Log::$events), 'Honeypot traffic consumed the normal failed-login allowance.');

echo "Security regression tests passed.\n";
