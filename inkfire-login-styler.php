<?php
/**
 * Plugin Name:       Foundation - Inkfire Login
 * Plugin URI:        https://github.com/Inkfire-limited/foundation-login-plugin/
 * Description:       Enterprise-grade login customizer. Secure, responsive, and branded.
 * Version:           2.0.28
 * Author:            Sonny x Inkfire
 * Author URI:        https://inkfire.co.uk/
 * Text Domain:       inkfire-login-styler
 * Requires PHP:      7.4
 * Requires at least: 6.0
 * Update URI:        https://github.com/Inkfire-limited/foundation-login-plugin/
 */

if (!defined('ABSPATH')) {
    exit;
}

/* ==========================================================================
   Constants
   ========================================================================== */

if (!defined('INKFIRE_LOGIN_BG'))   define('INKFIRE_LOGIN_BG',   plugins_url('assets/inkfire_background.png', __FILE__));
if (!defined('INKFIRE_LOGIN_LOGO')) define('INKFIRE_LOGIN_LOGO', plugins_url('assets/inkfire_logo.png', __FILE__));
if (!defined('INKFIRE_LOGIN_ICON')) define('INKFIRE_LOGIN_ICON', plugins_url('assets/inkfire_icon.png', __FILE__));
if (!defined('IFLS_VERSION'))       define('IFLS_VERSION',       '2.0.28');

// Brand colors
if (!defined('IF_TEAL'))   define('IF_TEAL',   '#32797e');
if (!defined('IF_TEAL2'))  define('IF_TEAL2',  '#1e6167');
if (!defined('IF_PILL'))   define('IF_PILL',   '#fbccbf');
if (!defined('IF_TEXT'))   define('IF_TEXT',   '#111111');
if (!defined('IF_ORANGE')) define('IF_ORANGE', '#e27200');

// Security settings
if (!defined('IFLS_MAX_LOGIN_ATTEMPTS')) define('IFLS_MAX_LOGIN_ATTEMPTS', 5);
if (!defined('IFLS_LOCKOUT_TIME')) define('IFLS_LOCKOUT_TIME', 900); 

/* ==========================================================================
   Updater Check
   ========================================================================== */
$updater_file = __DIR__ . '/inc/ifls-updater.php';
if (file_exists($updater_file)) {
    require_once $updater_file;
}

/* ==========================================================================
   Diagnostics
   ========================================================================== */
require_once __DIR__ . '/inc/ifls-diagnostics-settings.php';
require_once __DIR__ . '/inc/class-ifls-event-log.php';
require_once __DIR__ . '/inc/class-ifls-incident-reporter.php';

// A five-minute schedule for threshold evaluation and queued dispatch.
add_filter('cron_schedules', function($schedules) {
    if (!isset($schedules['ifls_five_minutes'])) {
        $schedules['ifls_five_minutes'] = [
            'interval' => 300,
            'display'  => __('Every 5 minutes (Inkfire diagnostics)', 'inkfire-login-styler'),
        ];
    }
    return $schedules;
});

// Mail failures - the class of problem that started all this.
add_action('wp_mail_failed', function($error) {
    IFLS_Incident_Reporter::raise(
        'mail_failure',
        is_wp_error($error) ? $error->get_error_message() : 'unknown mail error'
    );
});

add_action('ifls_dispatch_incidents', function() {
    IFLS_Incident_Reporter::check_thresholds();
    IFLS_Incident_Reporter::dispatch();
});

// Opportunistic flush so alerts arrive promptly without waiting for cron -
// but NEVER on wp-login.php, because an SMTP call there would block logins.
add_action('shutdown', function() {
    if (isset($GLOBALS['pagenow']) && 'wp-login.php' === $GLOBALS['pagenow']) {
        return;
    }

    if (defined('DOING_CRON') && DOING_CRON) {
        return; // The cron hook above already handles this.
    }

    IFLS_Incident_Reporter::dispatch();
}, 1000);

// Catch fatals originating inside this plugin. Kept deliberately minimal: this
// runs during a crash and must not allocate or fail itself.
register_shutdown_function(function() {
    $error = error_get_last();

    if (!$error || !in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) {
        return;
    }

    if (!isset($error['file']) || false === strpos($error['file'], 'foundation-inkfire-login-styler')) {
        return;
    }

    IFLS_Incident_Reporter::raise(
        'plugin_fatal',
        sprintf('%s in %s:%d', $error['message'], basename($error['file']), $error['line'])
    );
});

// Create/upgrade the event table and ensure the prune job exists. Activation
// hooks do not fire on plugin UPDATE, so the schema version is checked on every
// load rather than relying on activation alone.
add_action('plugins_loaded', function() {
    if (!ifls_diag_enabled()) {
        return;
    }

    if (get_option('ifls_events_db_version') !== IFLS_Event_Log::DB_VERSION) {
        IFLS_Event_Log::install();
    }

    if (!wp_next_scheduled('ifls_prune_events')) {
        wp_schedule_event(time() + HOUR_IN_SECONDS, 'daily', 'ifls_prune_events');
    }

    if (!wp_next_scheduled('ifls_dispatch_incidents')) {
        wp_schedule_event(time() + 300, 'ifls_five_minutes', 'ifls_dispatch_incidents');
    }
}, 20);

add_action('ifls_prune_events', ['IFLS_Event_Log', 'prune']);

/* ==========================================================================
   CONFIRM ADMIN EMAIL FIXES
   ========================================================================== */

/**
 * Hook into the confirm_admin_email action early to handle it before Elementor crashes
 */
add_action('login_init', 'ifls_handle_confirm_admin_email', 1);
function ifls_handle_confirm_admin_email() {
    // Only process if this is the confirm_admin_email action
    if (!isset($_REQUEST['action']) || $_REQUEST['action'] !== 'confirm_admin_email') {
        return;
    }
    
    // Check if form was submitted
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['confirm_admin_email'])) {
        // Verify the WordPress nonce
        if (!isset($_POST['_wpnonce']) || !wp_verify_nonce($_POST['_wpnonce'], 'confirm_admin_email')) {
            wp_die('Security check failed.');
        }
        
        // FIX: Update the timestamp to 6 MONTHS IN THE FUTURE.
        // Setting it to time() caused it to expire immediately, triggering the loop.
        $interval = (defined('MONTH_IN_SECONDS') ? MONTH_IN_SECONDS : 2592000) * 6;
        update_option('admin_email_lifespan', time() + $interval);
        
        // Get redirect URL
        $redirect_to = admin_url();
        if (!empty($_POST['redirect_to'])) {
            $redirect_to = $_POST['redirect_to'];
            // Ensure it's not pointing back to confirm_admin_email
            if (strpos($redirect_to, 'confirm_admin_email') !== false) {
                $redirect_to = admin_url();
            }
        }
        
        // Force immediate redirect to prevent Elementor from crashing
        wp_safe_redirect($redirect_to);
        exit;
    }
}

/* ==========================================================================
   Enterprise Security Layer
   ========================================================================== */

class IFLS_Enterprise_Security {
    private static $instance = null;
    private $transient_prefix = 'ifls_lock_';
    
    public static function get_instance() {
        if (null === self::$instance) self::$instance = new self();
        return self::$instance;
    }
    
    private function __construct() {
        add_filter('authenticate', [$this, 'check_login_attempts'], 5, 3);
        add_action('wp_login_failed', [$this, 'log_failed_attempt']);
        add_action('wp_login', [$this, 'clear_attempts_on_success']);
        
        foreach (['login_form', 'login_form_lostpassword', 'login_form_register', 'login_form_rp', 'login_form_resetpass'] as $action) {
            add_action($action, [$this, 'add_csrf_tokens']);
        }
        
        foreach (['lostpassword_post', 'register_post', 'resetpass_post'] as $action) {
            add_action($action, [$this, 'verify_csrf_token']);
        }

        $this->register_event_capture();

        // Email validation hook
        add_filter('registration_errors', function($errors, $sanitized_user_login, $user_email) {
            if (!filter_var($user_email, FILTER_VALIDATE_EMAIL)) {
                $errors->add('email_invalid', __('Please enter a valid email address.', 'inkfire-login-styler'));
            }
            return $errors;
        }, 10, 3);
    }

    /**
     * Observe authentication events for the on-site audit log.
     *
     * Every callback runs AFTER the action it observes, and
     * IFLS_Event_Log::record() swallows its own errors, so nothing here can
     * interrupt or slow down authentication.
     */
    private function register_event_capture() {
        add_action('wp_login', function($user_login, $user) {
            IFLS_Event_Log::record('login_success', [
                'username' => $user_login,
                'user_id'  => isset($user->ID) ? $user->ID : 0,
            ]);
        }, 10, 2);

        add_action('wp_login_failed', function($username) {
            IFLS_Event_Log::record('login_failed', ['username' => $username]);
        });

        add_action('wp_logout', function($user_id) {
            IFLS_Event_Log::record('logout', ['user_id' => $user_id]);
        });

        // Fires inside get_password_reset_key(), so this records that a reset
        // key was genuinely issued rather than merely requested.
        add_action('retrieve_password', function($user_login) {
            IFLS_Event_Log::record('reset_requested', ['username' => $user_login]);
        });

        add_action('after_password_reset', function($user) {
            // The second argument is the new password. Deliberately not captured.
            IFLS_Event_Log::record('reset_completed', [
                'username' => isset($user->user_login) ? $user->user_login : '',
                'user_id'  => isset($user->ID) ? $user->ID : 0,
            ]);
        });

        add_action('register_post', function($login) {
            IFLS_Event_Log::record('registration', ['username' => $login]);
        });

        // A failed reset key redirects to lostpassword&error=invalidkey. This is
        // the exact signature the 2.0.28 bug emitted for seven months.
        add_action('login_init', function() {
            if (!isset($_GET['error']) || 'invalidkey' !== $_GET['error']) {
                return;
            }

            if (!isset($_GET['action']) || 'lostpassword' !== $_GET['action']) {
                return;
            }

            IFLS_Event_Log::record('reset_failed', [
                'detail' => ['reason' => 'invalidkey'],
            ]);
        }, 5);
    }

    private function parse_forwarded_ip_header($value) {
        if (!is_string($value) || '' === $value) {
            return '';
        }

        foreach (explode(',', $value) as $candidate) {
            $candidate = trim($candidate);
            if (filter_var($candidate, FILTER_VALIDATE_IP)) {
                return $candidate;
            }
        }

        return '';
    }

    private function get_client_ip() {
        $remote_addr = isset($_SERVER['REMOTE_ADDR']) ? trim((string) wp_unslash($_SERVER['REMOTE_ADDR'])) : '';
        if (filter_var($remote_addr, FILTER_VALIDATE_IP)) {
            return $remote_addr;
        }

        foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_CLIENT_IP'] as $key) {
            if (!isset($_SERVER[$key])) {
                continue;
            }

            $ip = $this->parse_forwarded_ip_header((string) wp_unslash($_SERVER[$key]));
            if ($ip) {
                return $ip;
            }
        }

        return '0.0.0.0';
    }

    private function get_lockout_key($username) {
        return $this->transient_prefix . md5((string) $username . $this->get_client_ip());
    }

    private function get_lockout_expiry_key($username) {
        return $this->get_lockout_key($username) . '_expires';
    }

    private function get_lockout_time_left($username) {
        $expires_at = (int) get_transient($this->get_lockout_expiry_key($username));
        if ($expires_at > time()) {
            return $expires_at - time();
        }

        return IFLS_LOCKOUT_TIME;
    }
    
    public function check_login_attempts($user, $username, $password) {
        if (empty($username)) return $user;
        $key = $this->get_lockout_key($username);
        $attempts = get_transient($key) ?: 0;
        if ($attempts >= IFLS_MAX_LOGIN_ATTEMPTS) {
            $time_left = max(1, $this->get_lockout_time_left($username));
            IFLS_Event_Log::record('lockout', ['username' => $username]);
            return new WP_Error('too_many_attempts', sprintf(__('Too many failed attempts. Try again in %d minutes.', 'inkfire-login-styler'), ceil($time_left / 60)));
        }
        return $user;
    }
    
    public function log_failed_attempt($username) {
        if (empty($username)) return;
        $key = $this->get_lockout_key($username);
        $attempts = (int) (get_transient($key) ?: 0);
        $attempts++;

        set_transient($key, $attempts, IFLS_LOCKOUT_TIME);

        if ($attempts >= IFLS_MAX_LOGIN_ATTEMPTS) {
            set_transient($this->get_lockout_expiry_key($username), time() + IFLS_LOCKOUT_TIME, IFLS_LOCKOUT_TIME);
        }
    }
    
    public function clear_attempts_on_success($username) {
        $key = $this->get_lockout_key($username);
        delete_transient($key);
        delete_transient($this->get_lockout_expiry_key($username));
    }
    
    public function add_csrf_tokens() { wp_nonce_field('ifls_form_action', 'ifls_form_nonce'); }
    
    /**
     * Whether this is one of WordPress core's own admin password-reset tools.
     *
     * retrieve_password() fires `lostpassword_post` for the admin tools as well
     * as the front-end form, but those tools never render the nonce field this
     * class adds, because that field only exists on the wp-login.php forms:
     *
     *   - user-edit.php "Send Reset Link"  -> wp_ajax_send_password_reset()
     *   - users.php "Send password reset"  -> wp-admin/users.php bulk action
     *
     * Core already gates both with their own nonce plus an `edit_user`
     * capability check, so re-applying the front-end nonce check here only
     * breaks them. The capability checks below mirror core's exactly.
     *
     * is_admin() alone is not sufficient: it is also true for anonymous
     * requests to admin-ajax.php, so an authenticated, capable user is
     * required before any request is exempted.
     *
     * @return bool
     */
    private function is_core_admin_reset_request() {
        if (!is_admin() || !is_user_logged_in()) {
            return false;
        }

        // The bulk dropdown at the foot of users.php posts `action2`.
        $actions = [];
        foreach (['action', 'action2'] as $key) {
            if (isset($_REQUEST[$key])) {
                $actions[] = sanitize_key(wp_unslash($_REQUEST[$key]));
            }
        }

        // user-edit.php "Send Reset Link" (admin-ajax.php).
        if (wp_doing_ajax() && in_array('send-password-reset', $actions, true)) {
            $target_id = isset($_POST['user_id']) ? absint($_POST['user_id']) : 0;
            return $target_id > 0 && current_user_can('edit_user', $target_id);
        }

        // users.php "Send password reset" bulk action.
        if (in_array('resetpassword', $actions, true)) {
            return current_user_can('list_users');
        }

        return false;
    }

    public function verify_csrf_token() {
        if (defined('WP_CLI') && WP_CLI) {
            return;
        }

        // WooCommerce uses its own lost-password nonce and does not include the
        // custom IFLS field on the My Account reset form.
        if (isset($_POST['woocommerce-lost-password-nonce'])) {
            return;
        }

        // Core's admin-side reset tools carry their own nonce, not ours.
        if ($this->is_core_admin_reset_request()) {
            return;
        }

        if (!isset($_POST['ifls_form_nonce']) || !wp_verify_nonce($_POST['ifls_form_nonce'], 'ifls_form_action')) {
            // Recorded before dying: a burst of these is what the 2.0.27 bug
            // looked like from the outside, and is what now raises an alert.
            IFLS_Event_Log::record('csrf_blocked', [
                'detail' => ['hook' => current_action()],
            ]);

            wp_die(__('Security check failed.', 'inkfire-login-styler'), __('Error', 'inkfire-login-styler'), ['response' => 403]);
        }
    }
}
IFLS_Enterprise_Security::get_instance();

/* ==========================================================================
   Asset Manager
   ========================================================================== */

class IFLS_Asset_Manager {
    
    public static function get_asset_url($type) {
        switch ($type) {
            case 'bg': return INKFIRE_LOGIN_BG;
            case 'logo': return INKFIRE_LOGIN_LOGO;
            case 'icon': return INKFIRE_LOGIN_ICON;
            case 'css': return plugins_url('assets/inkfire-login.css', __FILE__);
            case 'js': return plugins_url('assets/inkfire-login.js', __FILE__);
            default: return '';
        }
    }
    
    public static function enqueue_assets() {
        wp_dequeue_style('login');

        $css_path = plugin_dir_path(__FILE__) . 'assets/inkfire-login.css';
        $js_path  = plugin_dir_path(__FILE__) . 'assets/inkfire-login.js';
        
        $css_ver = file_exists($css_path) ? filemtime($css_path) : IFLS_VERSION;
        $js_ver  = file_exists($js_path) ? filemtime($js_path) : IFLS_VERSION;
        
        wp_enqueue_style('inkfire-login', self::get_asset_url('css'), [], $css_ver);
        
        // CRITICAL FIX: Don't load ANY JavaScript on confirm_admin_email page
        $action = isset($_REQUEST['action']) ? sanitize_key($_REQUEST['action']) : '';
        if ($action !== 'confirm_admin_email') {
            wp_enqueue_script('inkfire-login-js', self::get_asset_url('js'), [], $js_ver, true);
            
            wp_localize_script('inkfire-login-js', 'ifls_vars', [
                'ajax_url' => admin_url('admin-ajax.php'),
                'nonce' => wp_create_nonce('ifls_js_nonce'),
                'is_rtl' => is_rtl(),
                'color_scheme' => 'light',
                'plugin_url' => plugin_dir_url(__FILE__)
            ]);
        }
        
        wp_add_inline_style('inkfire-login', self::generate_css_variables());
    }
    
    public static function generate_css_variables() {
        return '
        :root {
            --if-teal: ' . IF_TEAL . ';
            --if-teal-dark: ' . IF_TEAL2 . ';
            --if-pill: ' . IF_PILL . ';
            --if-text: ' . IF_TEXT . ';
            --if-orange: ' . IF_ORANGE . ';
            --if-bg-image: url("' . esc_url(INKFIRE_LOGIN_BG) . '");
            --if-bg-overlay: rgba(255, 255, 255, 0.95);
        }';
    }
}

/* ==========================================================================
   Core Functions
   ========================================================================== */

/**
 * Inline brand icon markup.
 *
 * Replaces the Font Awesome CDN stylesheet, which pulled a large third-party
 * bundle onto every login page for five icons and disclosed every visitor's IP
 * address to an external host. Paths are the Font Awesome 6 free brand glyphs
 * (CC BY 4.0, fontawesome.com/license/free).
 *
 * @param string $network facebook|instagram|linkedin|x|tiktok
 * @return string SVG markup, or '' for an unknown network.
 */
function ifls_social_icon($network) {
    $paths = [
        'facebook'  => 'M80 299.3V512h116V299.3h86.5l18-97.8H196v-33.3c0-51.6 20.2-71.8 72.5-71.8 16.3 0 29.4.4 37 1.2V9.8C291.4 3.3 273.2 0 255.6 0c-107 0-156.5 50.5-156.5 158.4v43.8H24v97.8h56v-.7z',
        'instagram' => 'M224.1 141c-63.6 0-114.9 51.3-114.9 114.9s51.3 114.9 114.9 114.9S339 319.5 339 255.9 287.7 141 224.1 141zm0 189.6c-41.1 0-74.7-33.5-74.7-74.7s33.5-74.7 74.7-74.7 74.7 33.5 74.7 74.7-33.6 74.7-74.7 74.7zm146.4-194.3c0 14.9-12 26.8-26.8 26.8-14.9 0-26.8-12-26.8-26.8s12-26.8 26.8-26.8 26.8 12 26.8 26.8zm76.1 27.2c-1.7-35.9-9.9-67.7-36.2-93.9-26.2-26.2-58-34.4-93.9-36.2-37-2.1-147.9-2.1-184.9 0-35.8 1.7-67.6 9.9-93.9 36.1s-34.4 58-36.2 93.9c-2.1 37-2.1 147.9 0 184.9 1.7 35.9 9.9 67.7 36.2 93.9s58 34.4 93.9 36.2c37 2.1 147.9 2.1 184.9 0 35.9-1.7 67.7-9.9 93.9-36.2 26.2-26.2 34.4-58 36.2-93.9 2.1-37 2.1-147.8 0-184.8zM398.8 388c-7.8 19.6-22.9 34.7-42.6 42.6-29.5 11.7-99.5 9-132.1 9s-102.7 2.6-132.1-9c-19.6-7.8-34.7-22.9-42.6-42.6-11.7-29.5-9-99.5-9-132.1s-2.6-102.7 9-132.1c7.8-19.6 22.9-34.7 42.6-42.6 29.5-11.7 99.5-9 132.1-9s102.7-2.6 132.1 9c19.6 7.8 34.7 22.9 42.6 42.6 11.7 29.5 9 99.5 9 132.1s2.7 102.7-9 132.1z',
        'linkedin'  => 'M100.3 448H7.4V148.9h92.9V448zM53.8 108.1C24.1 108.1 0 83.5 0 53.8a53.8 53.8 0 0 1 107.6 0c0 29.7-24.1 54.3-53.8 54.3zM447.9 448h-92.7V302.4c0-34.7-.7-79.2-48.3-79.2-48.3 0-55.7 37.7-55.7 76.7V448h-92.8V148.9h89.1v40.8h1.3c12.4-23.5 42.7-48.3 87.9-48.3 94 0 111.3 61.9 111.3 142.3V448z',
        'x'         => 'M389.2 48h70.6L305.6 224.2 487 464H345L233.7 318.6 106.5 464H35.8L200.7 275.5 26.8 48H172.4L272.9 180.9 389.2 48zM364.4 421.8h39.1L151.1 88h-42l255.3 333.8z',
        'tiktok'    => 'M448 209.9a210.1 210.1 0 0 1-122.8-39.3v178.8A162.6 162.6 0 1 1 185 188.3v89.9a74.6 74.6 0 1 0 52.2 71.2V0h88a121.2 121.2 0 0 0 1.9 22.2 122.2 122.2 0 0 0 53.9 80.2 121.4 121.4 0 0 0 67 20.1z',
    ];

    if (!isset($paths[$network])) {
        return '';
    }

    return '<svg class="if-social-icon" viewBox="0 0 448 512" width="18" height="18" fill="currentColor" aria-hidden="true" focusable="false"><path d="' . esc_attr($paths[$network]) . '"/></svg>';
}

function ifls_login_header_url() { return home_url('/'); }
function ifls_login_header_text() { return get_bloginfo('name'); }

function ifls_login_body_class($classes) {
    $action = isset($_REQUEST['action']) ? sanitize_key($_REQUEST['action']) : 'login';
    $classes[] = 'inkfire-login';
    $inline_actions = ['login', 'lostpassword', 'retrievepassword', 'rp', 'resetpass', 'register', 'confirm_admin_email', 'checkemail', 'loggedout', 'logout', 'interim-login', 'reauth', 'postpass'];
    if (in_array($action, $inline_actions, true)) $classes[] = 'inkfire-inline-form';
    return $classes;
}

function ifls_secure_login_redirect($redirect_to, $requested_redirect_to, $user) {
    if (is_wp_error($user) || !is_a($user, 'WP_User')) return $redirect_to;
    if (!empty($requested_redirect_to)) {
        $validated = wp_validate_redirect($requested_redirect_to, '');
        if ($validated) return $validated;
    }
    return admin_url() ? admin_url() : home_url('/');
}

function ifls_heading_text($default_label) {
    $site_title = get_bloginfo('name');
    if (is_multisite()) {
        $network = get_network();
        if (!empty($network->site_name)) $site_title = $network->site_name;
    }
    $default = sprintf(__('%1$s %2$s', 'inkfire-login-styler'), $default_label, $site_title);
    if (defined('INKFIRE_LOGIN_HEADING') && INKFIRE_LOGIN_HEADING) return INKFIRE_LOGIN_HEADING;
    return apply_filters('inkfire_login_heading', $default, $site_title);
}

function ifls_sanitize_request($key) {
    if (!isset($_REQUEST[$key])) return '';
    return sanitize_text_field(wp_unslash($_REQUEST[$key]));
}

/**
 * Resolve the password-reset login/key pair the way wp-login.php does.
 *
 * On `action=rp` the key arrives in the query string, but core immediately
 * moves it into the `wp-resetpass-<COOKIEHASH>` cookie, strips it from the URL
 * and redirects to `action=resetpass`. By the time this form is rendered the
 * request no longer carries the key, so reading it from $_REQUEST produces an
 * empty hidden field -- and core's
 *
 *     hash_equals( $rp_key, $_POST['rp_key'] )
 *
 * check in wp-login.php then fails, bouncing the user to
 * `lostpassword&error=invalidkey` without ever changing the password.
 *
 * Read the cookie first, exactly as core does, and fall back to the request for
 * the initial `action=rp` render before the cookie exists.
 *
 * @return array{0:string,1:string} [ $rp_login, $rp_key ]
 */
function ifls_get_reset_credentials() {
    $rp_cookie = 'wp-resetpass-' . COOKIEHASH;

    if (isset($_COOKIE[$rp_cookie]) && is_string($_COOKIE[$rp_cookie])) {
        $raw = wp_unslash($_COOKIE[$rp_cookie]);
        if (0 < strpos($raw, ':')) {
            list($rp_login, $rp_key) = explode(':', $raw, 2);
            // $rp_key is compared with hash_equals(), so it must not be altered.
            return [sanitize_user($rp_login), $rp_key];
        }
    }

    return [ifls_sanitize_request('login'), ifls_sanitize_request('key')];
}

function ifls_wrap_notice_markup($html, $type = 'info', $id = '') {
    if ($html === '') return '';
    $classes = $type === 'error' ? 'error' : 'message info';
    $id_attr = $id !== '' ? ' id="' . esc_attr($id) . '"' : '';
    return '<div' . $id_attr . ' class="' . esc_attr($classes) . '">' . $html . '</div>';
}

function ifls_get_login_notice_html() {
    global $error, $errors;

    $legacy_notice_html = '';
    if (function_exists('login_messages')) {
        $legacy_notice_html .= (string) login_messages();
    }
    if (function_exists('login_errors')) {
        $legacy_notice_html .= (string) login_errors();
    }
    if ($legacy_notice_html !== '') {
        return $legacy_notice_html;
    }

    $wp_error = is_wp_error($errors) ? $errors : new WP_Error();

    if (!empty($error)) {
        $wp_error->add('error', $error);
    }

    if (!$wp_error->has_errors()) {
        return '';
    }

    $error_list = [];
    $message_html = '';

    foreach ($wp_error->get_error_codes() as $code) {
        $severity = $wp_error->get_error_data($code);
        foreach ($wp_error->get_error_messages($code) as $error_message) {
            if ($severity === 'message') {
                $message_html .= '<p>' . $error_message . '</p>';
            } else {
                $error_list[] = $error_message;
            }
        }
    }

    $notice_html = '';

    if (!empty($error_list)) {
        $error_html = count($error_list) > 1
            ? '<ul class="login-error-list"><li>' . implode('</li><li>', $error_list) . '</li></ul>'
            : '<p>' . $error_list[0] . '</p>';
        $error_html = apply_filters('login_errors', $error_html);
        $notice_html .= ifls_wrap_notice_markup($error_html, 'error', 'login_error');
    }

    if ($message_html !== '') {
        $message_html = apply_filters('login_messages', $message_html);
        $notice_html .= ifls_wrap_notice_markup($message_html, 'info', 'login-message');
    }

    return $notice_html;
}

function ifls_render_inline_form($action) {
    $action = $action === '' ? 'login' : $action;
    
    // LOGIN
    if ($action === 'login') {
        $redirect = ifls_sanitize_request('redirect_to');
        $form_html = wp_login_form([
            'echo' => false,
            'redirect' => $redirect ?: admin_url(),
            'remember' => true,
            'form_id' => 'if_card_loginform',
            'label_username' => __('Username or Email', 'inkfire-login-styler'),
            'label_password' => __('Password', 'inkfire-login-styler'),
            'label_log_in' => __('Log In', 'inkfire-login-styler'),
            'id_username' => 'if_user_login',
            'id_password' => 'if_user_pass',
            'id_remember' => 'if_rememberme',
            'id_submit' => 'if_wp_submit',
        ]);
        $form_html = str_replace(
            '</form>',
            '<input type="hidden" name="testcookie" value="1" /></form>',
            $form_html
        );
        $heading = '<h2 class="if-card-title">' . esc_html(ifls_heading_text(__('Sign in to', 'inkfire-login-styler'))) . '</h2>';
        $message = ifls_get_login_notice_html();
        return $heading . $message . $form_html;
    }
    
    // CHECK EMAIL
    if ($action === 'checkemail') {
        ob_start(); ?>
        <h2 class="if-card-title"><?php echo esc_html(__('Check your email', 'inkfire-login-styler')); ?></h2>
        <p class="message info"><?php echo 'registered' === ifls_sanitize_request('checkemail') ? 'Registration successful. Check your email.' : 'Check your email for the confirmation link.'; ?></p>
        <p class="submit"><a href="<?php echo esc_url(wp_login_url()); ?>" class="button button-primary">Back to Login</a></p>
        <?php return ob_get_clean();
    }
    
    // LOST PASSWORD
    if ($action === 'lostpassword' || $action === 'retrievepassword') {
        ob_start(); ?>
        <h2 class="if-card-title"><?php echo esc_html(__('Reset your password', 'inkfire-login-styler')); ?></h2>
        <form name="lostpasswordform" id="if_lostpasswordform" action="<?php echo esc_url(site_url('wp-login.php?action=lostpassword', 'login_post')); ?>" method="post">
            <?php wp_nonce_field('ifls_form_action', 'ifls_form_nonce'); ?>
            <p><label for="if_user_login_lp"><?php esc_html_e('Username or Email', 'inkfire-login-styler'); ?></label>
            <input type="text" name="user_login" id="if_user_login_lp" class="input" size="20" required></p>
            <?php do_action('lostpassword_form'); ?>
            <p class="submit"><input type="submit" name="wp-submit" class="button button-primary" value="Get New Password"></p>
        </form>
        <?php return ob_get_clean();
    }
    
    // RESET PASSWORD
    if ($action === 'rp' || $action === 'resetpass') {
        list($rp_login, $rp_key) = ifls_get_reset_credentials();
        ob_start(); ?>
        <h2 class="if-card-title"><?php echo esc_html(__('New password', 'inkfire-login-styler')); ?></h2>
        <form name="resetpassform" id="if_resetpassform" action="<?php echo esc_url(site_url('wp-login.php?action=resetpass', 'login_post')); ?>" method="post" autocomplete="off">
            <?php wp_nonce_field('ifls_form_action', 'ifls_form_nonce'); ?>
            <div class="if-password-strength-wrapper">
                <p><label for="if_pass1">New password</label><input type="password" name="pass1" id="if_pass1" class="input" size="20" autocomplete="new-password" required data-strength-meter="true"></p>
                <p><label for="if_pass2">Confirm new password</label><input type="password" name="pass2" id="if_pass2" class="input" size="20" autocomplete="new-password" required></p>
            </div>
            <?php do_action('resetpass_form'); ?>
            <input type="hidden" name="rp_key" value="<?php echo esc_attr($rp_key); ?>">
            <input type="hidden" name="rp_login" value="<?php echo esc_attr($rp_login); ?>">
            <p class="submit"><input type="submit" name="wp-submit" class="button button-primary" value="Save Password"></p>
        </form>
        <?php return ob_get_clean();
    }
    
    // REGISTER
    if ($action === 'register' && get_option('users_can_register')) {
        $redirect = ifls_sanitize_request('redirect_to');
        ob_start(); ?>
        <h2 class="if-card-title"><?php echo esc_html(__('Create an account', 'inkfire-login-styler')); ?></h2>
        <form name="registerform" id="if_registerform" action="<?php echo esc_url(site_url('wp-login.php?action=register', 'login_post')); ?>" method="post" autocomplete="off">
            <?php wp_nonce_field('ifls_form_action', 'ifls_form_nonce'); ?>
            <p>
                <label for="if_user_login_reg">Username</label>
                <input type="text" name="user_login" id="if_user_login_reg" class="input" size="20" 
                       pattern="[a-zA-Z0-9_.-]{3,60}" 
                       title="<?php esc_attr_e('3-60 characters: letters, numbers, _, ., -', 'inkfire-login-styler'); ?>"
                       required>
            </p>
            <p><label for="if_user_email_reg">Email</label><input type="email" name="user_email" id="if_user_email_reg" class="input" size="25" required></p>
            <?php do_action('register_form'); ?>
            <input type="hidden" name="redirect_to" value="<?php echo esc_attr($redirect); ?>">
            <p class="submit"><input type="submit" name="wp-submit" class="button button-primary" value="Register"></p>
        </form>
        <?php return ob_get_clean();
    }
    
    // CONFIRM ADMIN EMAIL - SIMPLIFIED VERSION
    if ($action === 'confirm_admin_email') {
        $admin_email = get_option('admin_email');
        $redirect = ifls_sanitize_request('redirect_to');
        // Ensure redirect doesn't point back to this page
        if (empty($redirect) || strpos($redirect, 'confirm_admin_email') !== false) {
            $redirect = admin_url();
        }
        
        ob_start(); ?>
        <h2 class="if-card-title"><?php echo esc_html(__('Verify Admin Email', 'inkfire-login-styler')); ?></h2>
        <form name="confirm-admin-email-form" id="if_confirm_email_form" action="<?php echo esc_url(site_url('wp-login.php?action=confirm_admin_email', 'login_post')); ?>" method="post">
            <?php wp_nonce_field('confirm_admin_email'); ?>
            <?php wp_nonce_field('ifls_form_action', 'ifls_form_nonce'); ?>
            <p style="margin-bottom:8px"><?php printf(__('Current admin email: %s', 'inkfire-login-styler'), '<strong>' . esc_html($admin_email) . '</strong>'); ?></p>
            <p style="margin-bottom:20px; font-size:0.95em; opacity:0.8;">Please verify this address is correct.</p>
            <p class="submit" style="display:flex; flex-direction:column; gap:12px;">
                <input type="submit" name="confirm_admin_email" id="if_confirm_email_btn" class="button button-primary" value="The email is correct">
                <a href="<?php echo esc_url(admin_url('options-general.php')); ?>" style="text-align:center; font-size:0.9em; text-decoration:none; color:inherit;">Update Email</a>
            </p>
            <input type="hidden" name="redirect_to" value="<?php echo esc_attr($redirect); ?>">
        </form>
        <?php return ob_get_clean();
    }

    // LOGGED OUT
    if ($action === 'loggedout') {
        ob_start(); ?>
        <h2 class="if-card-title"><?php echo esc_html(__('Signed out', 'inkfire-login-styler')); ?></h2>
        <p class="message info" style="margin-top:0;">You have been successfully logged out.</p>
        <p class="submit"><a href="<?php echo esc_url(wp_login_url()); ?>" class="button button-primary">Log Back In</a></p>
        <?php return ob_get_clean();
    }

    // POST PASSWORD
    if ($action === 'postpass') {
        ob_start(); ?>
        <h2 class="if-card-title"><?php echo esc_html(__('Enter Password', 'inkfire-login-styler')); ?></h2>
        <p><?php esc_html_e( 'This content is password protected.', 'inkfire-login-styler' ); ?></p>
        <form action="<?php echo esc_url( site_url( 'wp-login.php?action=postpass', 'login_post' ) ); ?>" method="post">
            <?php wp_nonce_field('ifls_form_action', 'ifls_form_nonce'); ?>
            <p><label for="post_password">Password</label><input type="password" name="post_password" id="post_password" class="input" size="20" /></p>
            <p class="submit"><input type="submit" name="wp-submit" class="button button-primary" value="Enter" /></p>
        </form>
        <?php return ob_get_clean();
    }
    
    return '';
}

function ifls_render_login_layout() {
    $action = ifls_sanitize_request('action') ?: 'login';
    $site_name = get_bloginfo('name');
    $home_url = home_url('/');
    $lost_url = wp_lostpassword_url();
    $policy_url = function_exists('get_privacy_policy_url') ? get_privacy_policy_url() : '';

    $lang_selector = '';
    if (function_exists('wp_login_language_selector')) {
        ob_start();
        wp_login_language_selector();
        $lang_html = trim(ob_get_clean());
        if ($lang_html) {
            $lang_selector = preg_replace(['/id=("|\')language-switcher(\1)/', '/for=("|\')language-switcher-locales(\1)/', '/id=("|\')language-switcher-locales(\1)/'], ['id="if-language-switcher"', 'for="if-language-switcher-locales"', 'id="if-language-switcher-locales"'], $lang_html);
        }
    }
    ?>
    <div class="if-full-bg">
        <div class="if-shell" role="region" aria-label="Login">
            <main class="if-right" role="main">
                <div class="if-logo-wrap"><img class="if-logo" src="<?php echo esc_url(INKFIRE_LOGIN_LOGO); ?>" alt="Logo" /></div>
                <section class="if-teal">
                    <div class="if-cta-row"><div class="if-cta-cell"><div class="if-card" id="if-login-card"><?php echo ifls_render_inline_form($action); ?></div></div></div>
                    <nav class="if-aux">
                        <div class="if-aux-links">
                            <?php if ($action !== 'register' && get_option('users_can_register')) : ?>
                                <a class="if-aux-link" href="<?php echo esc_url(wp_registration_url()); ?>">Create account</a><span class="sep">•</span>
                            <?php elseif ($action === 'register') : ?>
                                <a class="if-aux-link" href="<?php echo esc_url(wp_login_url()); ?>">Back to Login</a><span class="sep">•</span>
                            <?php endif; ?>
                            <a class="if-aux-link" href="<?php echo esc_url($lost_url); ?>">Lost password?</a><span class="sep">•</span>
                            <a class="if-aux-link" href="<?php echo esc_url($home_url); ?>">Back to <?php echo esc_html($site_name); ?></a>
                            <?php if ($policy_url) : ?><span class="sep">•</span><a class="if-aux-link" href="<?php echo esc_url($policy_url); ?>">Privacy Policy</a><?php endif; ?>
                        </div>
                    </nav>
                </section>
            </main>
            <aside class="if-left" role="complementary">
                <div class="if-left-block"><img class="if-icon" src="<?php echo esc_url(INKFIRE_LOGIN_ICON); ?>" alt="" /><h3>Stay in touch</h3><p><a class="if-accent" href="mailto:hello@inkfire.co.uk">hello@inkfire.co.uk</a><br><a class="if-accent" href="tel:+443336134653">+44 (0)333 613 4653</a><br><a class="if-accent" href="https://inkfire.co.uk/" target="_blank" rel="noopener noreferrer">inkfire.co.uk</a></p></div>
                <div class="if-left-block"><h4>Opening Times</h4><p>Monday – Friday<br><strong>9am – 5pm GMT</strong></p></div>
                <div class="if-left-block"><h4>Follow Us</h4><div class="if-socials"><a href="https://facebook.com/inkfirelimited" target="_blank" rel="noopener noreferrer" aria-label="<?php esc_attr_e('Inkfire on Facebook', 'inkfire-login-styler'); ?>"><?php echo ifls_social_icon('facebook'); ?></a><a href="https://www.instagram.com/inkfirelimited/" target="_blank" rel="noopener noreferrer" aria-label="<?php esc_attr_e('Inkfire on Instagram', 'inkfire-login-styler'); ?>"><?php echo ifls_social_icon('instagram'); ?></a><a href="https://uk.linkedin.com/company/inkfire" target="_blank" rel="noopener noreferrer" aria-label="<?php esc_attr_e('Inkfire on LinkedIn', 'inkfire-login-styler'); ?>"><?php echo ifls_social_icon('linkedin'); ?></a><a href="https://twitter.com/Inkfirelimited" target="_blank" rel="noopener noreferrer" aria-label="<?php esc_attr_e('Inkfire on X', 'inkfire-login-styler'); ?>"><?php echo ifls_social_icon('x'); ?></a><a href="https://www.tiktok.com/@inkfirelimited" target="_blank" rel="noopener noreferrer" aria-label="<?php esc_attr_e('Inkfire on TikTok', 'inkfire-login-styler'); ?>"><?php echo ifls_social_icon('tiktok'); ?></a></div></div>
                <div class="if-left-block if-legal"><p class="if-legal-small">Company Number: 15153305<br>VAT Number: GB483189752</p></div>
                <?php if ($lang_selector) : ?><div class="if-left-block if-lang-left"><?php echo $lang_selector; ?></div><?php endif; ?>
            </aside>
        </div>
    </div>
    <?php
}

function ifls_plugin_row_meta($links, $file) {
    if (plugin_basename(__FILE__) === $file) $links[] = '<strong>Enterprise Gold v' . esc_html(IFLS_VERSION) . '</strong>';
    return $links;
}

/* ==========================================================================
   Foundation Admin Shell
   ========================================================================== */

function ifls_get_admin_shell_config() {
    return [
        'plugin' => 'login-styler',
        'rootId' => 'foundation-admin-app',
        'eyebrow' => __('Foundation command centre', 'inkfire-login-styler'),
        'title' => __('Foundation: Inkfire Login', 'inkfire-login-styler'),
        'description' => __('This read-only dashboard brings the login styler into the shared Foundation admin pattern without changing the hardened login runtime.', 'inkfire-login-styler'),
        'badge' => 'v' . IFLS_VERSION,
        'themeStorageKey' => 'foundation-login-styler-theme',
        'actions' => [
            [
                'label' => __('Open login page', 'inkfire-login-styler'),
                'href' => wp_login_url(),
                'target' => '_blank',
                'variant' => 'solid',
            ],
            [
                'label' => __('GitHub backup', 'inkfire-login-styler'),
                'href' => 'https://github.com/Inkfire-limited/foundation-login-plugin',
                'target' => '_blank',
                'variant' => 'ghost',
            ],
        ],
        'metrics' => [
            [
                'label' => __('Plugin status', 'inkfire-login-styler'),
                'value' => __('Active', 'inkfire-login-styler'),
                'meta' => sprintf(__('Running version %s.', 'inkfire-login-styler'), IFLS_VERSION),
            ],
            [
                'label' => __('Lockout policy', 'inkfire-login-styler'),
                'value' => sprintf(__('%d tries', 'inkfire-login-styler'), IFLS_MAX_LOGIN_ATTEMPTS),
                'meta' => sprintf(__('Lockout lasts %d minutes.', 'inkfire-login-styler'), (int) (IFLS_LOCKOUT_TIME / 60)),
            ],
            [
                'label' => __('Brand mode', 'inkfire-login-styler'),
                'value' => __('Gold master', 'inkfire-login-styler'),
                'meta' => __('Brand assets remain intentionally code-controlled.', 'inkfire-login-styler'),
                'tone' => 'accent',
            ],
        ],
        'sections' => [
            [
                'id' => 'login-styler-status',
                'navLabel' => __('Status', 'inkfire-login-styler'),
                'eyebrow' => __('Read-only dashboard', 'inkfire-login-styler'),
                'title' => __('Login runtime status', 'inkfire-login-styler'),
                'description' => __('There are no settings to migrate here. The shell gives the plugin a Foundation admin home while the login screen stays zero-configuration.', 'inkfire-login-styler'),
                'templateId' => 'foundation-login-styler-status',
            ],
        ],
    ];
}

function ifls_register_foundation_admin_menu() {
    global $admin_page_hooks;

    $parent_slug = 'foundation-by-inkfire';

    if (empty($admin_page_hooks[$parent_slug])) {
        add_menu_page(
            __('Foundation', 'inkfire-login-styler'),
            __('Foundation', 'inkfire-login-styler'),
            'manage_options',
            $parent_slug,
            'ifls_render_admin_page',
            'dashicons-hammer',
            30
        );
    }

    add_submenu_page(
        $parent_slug,
        __('Inkfire Login', 'inkfire-login-styler'),
        __('Inkfire Login', 'inkfire-login-styler'),
        'manage_options',
        'foundation-login-styler',
        'ifls_render_admin_page'
    );

    remove_submenu_page($parent_slug, $parent_slug);
}
add_action('admin_menu', 'ifls_register_foundation_admin_menu', 20);

function ifls_enqueue_admin_shell($hook) {
    if (false === strpos((string) $hook, 'foundation-login-styler')) {
        return;
    }

    $asset_base = plugin_dir_url(__FILE__) . 'assets/admin/';
    wp_enqueue_style('foundation-admin-shell', $asset_base . 'foundation-admin-shell.css', [], IFLS_VERSION);
    wp_enqueue_script('foundation-admin-shell', $asset_base . 'foundation-admin-shell.js', ['wp-element'], IFLS_VERSION, true);
    wp_add_inline_script(
        'foundation-admin-shell',
        'window.foundationAdminShellData = ' . wp_json_encode(ifls_get_admin_shell_config()) . ';',
        'before'
    );
}
add_action('admin_enqueue_scripts', 'ifls_enqueue_admin_shell');

function ifls_render_admin_page() {
    if (!current_user_can('manage_options')) {
        wp_die(__('You do not have permission to access this page.', 'inkfire-login-styler'));
    }

    ob_start();
    ?>
    <div class="fp-card">
        <h2><?php esc_html_e('Login styling is active', 'inkfire-login-styler'); ?></h2>
        <p class="description"><?php esc_html_e('This plugin intentionally remains zero-configuration. Branding, CSRF protection, brute-force lockouts, and WordPress login notice compatibility continue to run from the existing login hooks.', 'inkfire-login-styler'); ?></p>
        <div class="foundation-shell-actions">
            <a class="button button-primary" href="<?php echo esc_url(wp_login_url()); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e('Preview login page', 'inkfire-login-styler'); ?></a>
            <a class="button" href="<?php echo esc_url(admin_url('plugins.php')); ?>"><?php esc_html_e('Open plugins screen', 'inkfire-login-styler'); ?></a>
        </div>
    </div>
    <?php
    $status_markup = ob_get_clean();
    ?>
    <div class="wrap foundation-admin-wrap">
        <div id="foundation-admin-app">
            <p><?php esc_html_e('Loading Foundation shell...', 'inkfire-login-styler'); ?></p>
        </div>
        <template id="foundation-login-styler-status"><?php echo $status_markup; ?></template>
    </div>
    <?php
}

/**
 * Add Plugin Icon to Plugins Page
 * Injects a small CSS snippet to display your icon next to the plugin name.
 */
function ifls_add_plugin_icon() {
    $icon_url = INKFIRE_LOGIN_ICON;
    // Target the specific row for this plugin based on its directory name
    // Assumes folder name is 'foundation-inkfire-login-styler'
    ?>
    <style>
        /* Target the plugin row by its data-slug attribute */
        tr[data-slug="foundation-inkfire-login-styler"] .plugin-title strong {
            position: relative;
            padding-left: 36px;
            display: inline-block;
        }
        tr[data-slug="foundation-inkfire-login-styler"] .plugin-title strong::before {
            content: "";
            position: absolute;
            left: 0;
            top: 50%;
            transform: translateY(-50%);
            width: 28px;
            height: 28px;
            background-image: url('<?php echo esc_url($icon_url); ?>');
            background-size: contain;
            background-repeat: no-repeat;
            background-position: center;
        }
    </style>
    <?php
}
add_action('admin_head', 'ifls_add_plugin_icon');

/**
 * Load the login stylesheet on this plugin's own admin screens only.
 *
 * This was previously enqueued on EVERY wp-admin page, which is wasted weight
 * on every admin request and risks the login styles bleeding into unrelated
 * screens. A named function rather than a closure so it can be tested directly
 * and unhooked by a site that needs to.
 *
 * @param string $hook Current admin page hook suffix.
 */
function ifls_enqueue_admin_assets($hook) {
    if (false === strpos((string) $hook, 'foundation-login-styler')) {
        return;
    }

    $css_path = plugin_dir_path(__FILE__) . 'assets/inkfire-login.css';
    $css_ver  = file_exists($css_path) ? filemtime($css_path) : IFLS_VERSION;

    wp_enqueue_style('inkfire-login', plugins_url('assets/inkfire-login.css', __FILE__), [], $css_ver);
    wp_add_inline_style('inkfire-login', IFLS_Asset_Manager::generate_css_variables());
}
add_action('admin_enqueue_scripts', 'ifls_enqueue_admin_assets');

register_activation_hook(__FILE__, function() { add_option('ifls_installed_version', IFLS_VERSION); });

add_filter('login_headerurl', 'ifls_login_header_url');
add_filter('login_headertext', 'ifls_login_header_text');
add_filter('login_body_class', 'ifls_login_body_class');
add_action('login_header', 'ifls_render_login_layout');
add_action('login_enqueue_scripts', ['IFLS_Asset_Manager', 'enqueue_assets']);
add_filter('login_redirect', 'ifls_secure_login_redirect', 10, 3);
add_filter('plugin_row_meta', 'ifls_plugin_row_meta', 10, 2);
