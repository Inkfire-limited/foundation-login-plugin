<?php
/**
 * Plugin Name:       Foundation - Inkfire Login
 * Plugin URI:        https://github.com/hawks010/foundation-login-plugin/
 * Description:       Enterprise-grade login customizer. Secure, responsive, and branded.
 * Version:           2.0.24
 * Author:            Sonny x Inkfire
 * Author URI:        https://inkfire.co.uk/
 * Text Domain:       inkfire-login-styler
 * Requires PHP:      7.4
 * Requires at least: 6.0
 * Update URI:        https://github.com/hawks010/foundation-login-plugin/
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

        // Email validation hook
        add_filter('registration_errors', function($errors, $sanitized_user_login, $user_email) {
            if (!filter_var($user_email, FILTER_VALIDATE_EMAIL)) {
                $errors->add('email_invalid', __('Please enter a valid email address.', 'inkfire-login-styler'));
            }
            return $errors;
        }, 10, 3);
    }

    private function get_client_ip() {
        $keys = ['HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'];
        foreach ($keys as $key) {
            if (isset($_SERVER[$key])) {
                $ip = filter_var($_SERVER[$key], FILTER_VALIDATE_IP);
                if ($ip) return $ip;
            }
        }
        return '0.0.0.0';
    }
    
    public function check_login_attempts($user, $username, $password) {
        if (empty($username)) return $user;
        $key = $this->transient_prefix . md5($username . $this->get_client_ip());
        $attempts = get_transient($key) ?: 0;
        if ($attempts >= IFLS_MAX_LOGIN_ATTEMPTS) {
            $time_left = get_option("_transient_timeout_{$key}") - time();
            return new WP_Error('too_many_attempts', sprintf(__('Too many failed attempts. Try again in %d minutes.', 'inkfire-login-styler'), ceil($time_left / 60)));
        }
        return $user;
    }
    
    public function log_failed_attempt($username) {
        if (empty($username)) return;
        $key = $this->transient_prefix . md5($username . $this->get_client_ip());
        $attempts = get_transient($key) ?: 0;
        set_transient($key, $attempts + 1, IFLS_LOCKOUT_TIME);
    }
    
    public function clear_attempts_on_success($username) {
        $key = $this->transient_prefix . md5($username . $this->get_client_ip());
        delete_transient($key);
    }
    
    public function add_csrf_tokens() { wp_nonce_field('ifls_form_action', 'ifls_form_nonce'); }
    
    public function verify_csrf_token() {
        if (defined('WP_CLI') && WP_CLI) {
            return;
        }

        // WooCommerce uses its own lost-password nonce and does not include the
        // custom IFLS field on the My Account reset form.
        if (isset($_POST['woocommerce-lost-password-nonce'])) {
            return;
        }

        if (!isset($_POST['ifls_form_nonce']) || !wp_verify_nonce($_POST['ifls_form_nonce'], 'ifls_form_action')) {
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
            case 'fa': return 'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css';
            default: return '';
        }
    }
    
    public static function enqueue_assets() {
        wp_dequeue_style('login');
        
        wp_enqueue_style('if-fa', self::get_asset_url('fa'), [], '6.5.2');
        
        $css_path = plugin_dir_path(__FILE__) . 'assets/inkfire-login.css';
        $js_path  = plugin_dir_path(__FILE__) . 'assets/inkfire-login.js';
        
        $css_ver = file_exists($css_path) ? filemtime($css_path) : '2.0.24';
        $js_ver  = file_exists($js_path) ? filemtime($js_path) : '2.0.24';
        
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
        $rp_key = ifls_sanitize_request('key');
        $rp_login = ifls_sanitize_request('login');
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
                <div class="if-left-block"><img class="if-icon" src="<?php echo esc_url(INKFIRE_LOGIN_ICON); ?>" alt="" /><h3>Stay in touch</h3><p><a class="if-accent" href="mailto:hello@inkfire.co.uk">hello@inkfire.co.uk</a><br><a class="if-accent" href="tel:+443336134653">+44 (0)333 613 4653</a><br><a class="if-accent" href="https://inkfire.co.uk/" target="_blank">inkfire.co.uk</a></p></div>
                <div class="if-left-block"><h4>Opening Times</h4><p>Monday – Friday<br><strong>9am – 5pm GMT</strong></p></div>
                <div class="if-left-block"><h4>Follow Us</h4><div class="if-socials"><a href="https://facebook.com/inkfirelimited" target="_blank"><i class="fa-brands fa-facebook-f"></i></a><a href="https://www.instagram.com/inkfirelimited/" target="_blank"><i class="fa-brands fa-instagram"></i></a><a href="https://uk.linkedin.com/company/inkfire" target="_blank"><i class="fa-brands fa-linkedin-in"></i></a><a href="https://twitter.com/Inkfirelimited" target="_blank"><i class="fa-brands fa-x-twitter"></i></a><a href="https://www.tiktok.com/@inkfirelimited" target="_blank"><i class="fa-brands fa-tiktok"></i></a></div></div>
                <div class="if-left-block if-legal"><p class="if-legal-small">Company Number: 15153305<br>VAT Number: GB483189752</p></div>
                <?php if ($lang_selector) : ?><div class="if-left-block if-lang-left"><?php echo $lang_selector; ?></div><?php endif; ?>
            </aside>
        </div>
    </div>
    <?php
}

function ifls_plugin_row_meta($links, $file) {
    if (plugin_basename(__FILE__) === $file) $links[] = '<strong>Enterprise Gold v2.0.24</strong>';
    return $links;
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

add_action('admin_enqueue_scripts', function() {
    $css_path = plugin_dir_path(__FILE__) . 'assets/inkfire-login.css';
    $css_ver = file_exists($css_path) ? filemtime($css_path) : '2.0.24';
    wp_enqueue_style('inkfire-login', plugins_url('assets/inkfire-login.css', __FILE__), [], $css_ver);
    wp_add_inline_style('inkfire-login', IFLS_Asset_Manager::generate_css_variables());
});

register_activation_hook(__FILE__, function() { add_option('ifls_installed_version', '2.0.24'); });

add_filter('login_headerurl', 'ifls_login_header_url');
add_filter('login_headertext', 'ifls_login_header_text');
add_filter('login_body_class', 'ifls_login_body_class');
add_action('login_header', 'ifls_render_login_layout');
add_action('login_enqueue_scripts', ['IFLS_Asset_Manager', 'enqueue_assets']);
add_action('login_footer', '__return_null');
add_filter('login_redirect', 'ifls_secure_login_redirect', 10, 3);
add_filter('plugin_row_meta', 'ifls_plugin_row_meta', 10, 2);
