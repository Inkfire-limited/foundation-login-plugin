<?php
/**
 * Plugin Name:       Foundation Inkfire Login
 * Plugin URI:        https://github.com/hawks010/foundation-login-plugin/
 * Description:       Replaces the WordPress login screen with the Inkfire two‑column layout (contact panel + login card). Fully responsive, accessible, and supports Login, Lost Password, Reset Password, and Register flows inline. Language switcher under socials. Core #login output is hidden for these actions to avoid duplicate markup/IDs.
 * Version:           1.8.2
 * Author:            Inkfire
 * Author URI:        https://inkfire.co.uk/
 * Text Domain:       inkfire-login-styler
 * Requires PHP:      7.4
 * Requires at least: 5.8
 */

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly.
}

/* ==========================================================================
   Constants
   ========================================================================== */

if (!defined('INKFIRE_LOGIN_BG'))   define('INKFIRE_LOGIN_BG',   plugins_url('assets/inkfire_background.png', __FILE__));
if (!defined('INKFIRE_LOGIN_LOGO')) define('INKFIRE_LOGIN_LOGO', plugins_url('assets/inkfire_logo.png', __FILE__));
if (!defined('INKFIRE_LOGIN_ICON')) define('INKFIRE_LOGIN_ICON', plugins_url('assets/inkfire_icon.png', __FILE__));

/* Brand colours */
if (!defined('IF_TEAL'))   define('IF_TEAL',   '#32797e');
if (!defined('IF_TEAL2'))  define('IF_TEAL2',  '#1e6167');
if (!defined('IF_PILL'))   define('IF_PILL',   '#fbccbf');  // salmon pill (primary button + title pill)
if (!defined('IF_TEXT'))   define('IF_TEXT',   '#111111');
if (!defined('IF_ORANGE')) define('IF_ORANGE', '#e27200');  // pill hover


/* ==========================================================================
   Initialize Updater
   ========================================================================== */

// Load the self-hosted updater from the inc folder.
require_once( __DIR__ . '/inc/ifls-updater.php' );


/* ==========================================================================
   Core Plugin Functions
   ========================================================================== */

/**
 * Sets the login logo link URL to the site's homepage.
 *
 * @since 1.0.0
 * @return string The site's home URL.
 */
function ifls_login_header_url() {
    return home_url('/');
}

/**
 * Sets the login logo link title attribute to the site's name.
 *
 * @since 1.0.0
 * @return string The site's name.
 */
function ifls_login_header_text() {
    return get_bloginfo('name');
}

/**
 * Adds custom classes to the login body tag for styling purposes.
 *
 * @since 1.4.0
 * @param array $classes An array of body classes.
 * @return array The modified array of body classes.
 */
function ifls_login_body_class($classes) {
    $action = isset($_REQUEST['action']) ? sanitize_key($_REQUEST['action']) : 'login';
    $classes[] = 'inkfire-login';

    // Add a helper class for actions where we render the form inside our custom card.
    // This is used to hide the default WordPress form.
    $inline_actions = [
        'login',
        'lostpassword',
        'retrievepassword',
        'rp',
        'resetpass',
        'register',
        'confirm_admin_email',
        'checkemail',
        'loggedout',
        'logout',
        'interim-login',
        'reauth',
        'postpass',
    ];
    if (in_array($action, $inline_actions, true)) {
        $classes[] = 'inkfire-inline-form';
    }
    return $classes;
}

/**
 * Filters the login redirect URL to ensure a sane, secure default.
 *
 * @since 1.5.0
 * @param string           $redirect_to           The URL to redirect to.
 * @param string           $requested_redirect_to The URL the user wanted to redirect to.
 * @param WP_User|WP_Error $user                  WP_User object on success, WP_Error on failure.
 * @return string The final, safe redirect URL.
 */
function ifls_secure_login_redirect($redirect_to, $requested_redirect_to, $user) {
    if (is_wp_error($user) || !is_a($user, 'WP_User')) {
        return $redirect_to;
    }
    if (!empty($requested_redirect_to)) {
        $validated_url = wp_validate_redirect($requested_redirect_to, '');
        if (!empty($validated_url)) {
            return $validated_url;
        }
    }
    return admin_url() ? admin_url() : home_url('/');
}

/**
 * Builds the dynamic heading text for the login card.
 *
 * @since 1.4.0
 * @param string $default_label The default prefix, e.g., "Sign in to".
 * @return string The full heading text.
 */
function ifls_heading_text($default_label) {
    $site_title = wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES);
    if (is_multisite()) {
        $network = get_network();
        if (!empty($network->site_name)) {
            $site_title = $network->site_name;
        }
    }
    $default = sprintf(__('%1$s %2$s', 'inkfire-login-styler'), $default_label, $site_title);
    
    if (defined('INKFIRE_LOGIN_HEADING') && INKFIRE_LOGIN_HEADING) {
        return INKFIRE_LOGIN_HEADING;
    }
    return apply_filters('inkfire_login_heading', $default, $site_title);
}

/**
 * Renders the appropriate inline form markup based on the current login action.
 *
 * @since 1.4.0
 * @param string $action The current login action (e.g., 'login', 'lostpassword').
 * @return string The HTML for the form.
 */
function ifls_render_inline_form($action) {
    // Default to 'login' action if none is specified.
    $action = $action === '' ? 'login' : $action;

    // LOGIN
    if ($action === 'login') {
        $redirect = isset($_REQUEST['redirect_to']) ? esc_url_raw($_REQUEST['redirect_to']) : admin_url();
        $form_html = wp_login_form([
            'echo'           => false,
            'redirect'       => $redirect,
            'remember'       => true,
            'form_id'        => 'if_card_loginform',
            'label_username' => __('Username or Email Address', 'inkfire-login-styler'),
            'label_password' => __('Password', 'inkfire-login-styler'),
            'label_log_in'   => __('Log In', 'inkfire-login-styler'),
            'id_username'    => 'if_user_login',
            'id_password'    => 'if_user_pass',
            'id_remember'    => 'if_rememberme',
            'id_submit'      => 'if_wp_submit',
        ]);
        $heading = '<h2 class="if-card-title">' . esc_html(ifls_heading_text(__('Sign in to', 'inkfire-login-styler'))) . '</h2>';
        return $heading . $form_html;
    }

    // LOST PASSWORD (request reset link)
    if ($action === 'lostpassword' || $action === 'retrievepassword') {
        ob_start(); ?>
        <h2 class="if-card-title"><?php echo esc_html(__('Reset your password', 'inkfire-login-styler')); ?></h2>
        <form name="lostpasswordform" id="if_lostpasswordform" action="<?php echo esc_url(site_url('wp-login.php?action=lostpassword', 'login_post')); ?>" method="post">
            <p>
                <label for="if_user_login_lp"><?php esc_html_e('Username or Email Address', 'inkfire-login-styler'); ?></label>
                <input type="text" name="user_login" id="if_user_login_lp" class="input" size="20" autocapitalize="off" autocomplete="username" required>
            </p>
            <?php do_action('lostpassword_form'); ?>
            <p class="submit">
                <input type="submit" name="wp-submit" class="button button-primary" value="<?php echo esc_attr__('Get New Password', 'inkfire-login-styler'); ?>">
            </p>
        </form>
        <?php
        return ob_get_clean();
    }

    // RESET PASSWORD (rp/resetpass)
    if ($action === 'rp' || $action === 'resetpass') {
        $rp_key   = isset($_REQUEST['key'])   ? sanitize_text_field(wp_unslash($_REQUEST['key']))   : '';
        $rp_login = isset($_REQUEST['login']) ? sanitize_text_field(wp_unslash($_REQUEST['login'])) : '';
        ob_start(); ?>
        <h2 class="if-card-title"><?php echo esc_html(__('Choose a new password', 'inkfire-login-styler')); ?></h2>
        <form name="resetpassform" id="if_resetpassform" action="<?php echo esc_url(site_url('wp-login.php?action=resetpass', 'login_post')); ?>" method="post" autocomplete="off">
            <p class="user-pass1-wrap">
                <label for="if_pass1"><?php esc_html_e('New password', 'inkfire-login-styler'); ?></label>
                <input type="password" name="pass1" id="if_pass1" class="input" size="20" autocomplete="new-password" spellcheck="false" required>
            </p>
            <p class="user-pass2-wrap">
                <label for="if_pass2"><?php esc_html_e('Confirm new password', 'inkfire-login-styler'); ?></label>
                <input type="password" name="pass2" id="if_pass2" class="input" size="20" autocomplete="new-password" spellcheck="false" required>
            </p>
            <?php do_action('resetpass_form'); ?>
            <input type="hidden" name="rp_key" value="<?php echo esc_attr($rp_key); ?>">
            <input type="hidden" name="rp_login" value="<?php echo esc_attr($rp_login); ?>">
            <p class="submit"><input type="submit" name="wp-submit" class="button button-primary" value="<?php echo esc_attr__('Save Password', 'inkfire-login-styler'); ?>"></p>
        </form>
        <?php
        return ob_get_clean();
    }

    // REGISTER
    if ($action === 'register' && get_option('users_can_register')) {
        $redirect = isset($_REQUEST['redirect_to']) ? esc_url_raw($_REQUEST['redirect_to']) : '';
        ob_start(); ?>
        <h2 class="if-card-title"><?php echo esc_html(__('Create an account', 'inkfire-login-styler')); ?></h2>
        <form name="registerform" id="if_registerform" action="<?php echo esc_url(site_url('wp-login.php?action=register', 'login_post')); ?>" method="post" autocomplete="off">
            <p>
                <label for="if_user_login_reg"><?php esc_html_e('Username', 'inkfire-login-styler'); ?></label>
                <input type="text" name="user_login" id="if_user_login_reg" class="input" size="20" autocapitalize="off" required>
            </p>
            <p>
                <label for="if_user_email_reg"><?php esc_html_e('Email', 'inkfire-login-styler'); ?></label>
                <input type="email" name="user_email" id="if_user_email_reg" class="input" size="25" autocomplete="email" required>
            </p>
            <?php do_action('register_form'); ?>
            <?php if ($redirect) : ?><input type="hidden" name="redirect_to" value="<?php echo esc_attr($redirect); ?>"><?php endif; ?>
            <p class="submit">
                <input type="submit" name="wp-submit" class="button button-primary" value="<?php echo esc_attr__('Register', 'inkfire-login-styler'); ?>">
            </p>
        </form>
        <?php
        return ob_get_clean();
    }

    return ''; // Return empty string for unhandled actions.
}

/**
 * Renders the entire custom login page layout.
 *
 * @since 1.4.0
 */
function ifls_render_login_layout() {
    $action     = isset($_REQUEST['action']) ? sanitize_key($_REQUEST['action']) : 'login';
    $site_name  = get_bloginfo('name');
    $home_url   = home_url('/');
    $lost_url   = wp_lostpassword_url();
    $policy_url = function_exists('get_privacy_policy_url') ? get_privacy_policy_url() : '';

    // Capture the language selector output and modify its IDs to prevent duplicates.
    $lang_selector = '';
    if (function_exists('wp_login_language_selector')) {
        ob_start();
        wp_login_language_selector();
        $lang_selector = trim(ob_get_clean());
        if ($lang_selector) {
            $lang_selector = preg_replace('/id=("|\')language-switcher(\1)/', 'id="if-language-switcher"', $lang_selector);
            $lang_selector = preg_replace('/for=("|\')language-switcher-locales(\1)/', 'for="if-language-switcher-locales"', $lang_selector);
            $lang_selector = preg_replace('/id=("|\')language-switcher-locales(\1)/', 'id="if-language-switcher-locales"', $lang_selector);
        }
    }
?>
  <div class="if-full-bg">
    <div class="if-shell" role="region" aria-label="<?php esc_attr_e('Inkfire login area', 'inkfire-login-styler'); ?>">

      <main class="if-right" role="main">
        <div class="if-logo-wrap">
          <img class="if-logo" src="<?php echo esc_url(INKFIRE_LOGIN_LOGO); ?>" alt="<?php esc_attr_e('Inkfire', 'inkfire-login-styler'); ?>" decoding="async" />
        </div>

        <section class="if-teal" aria-label="<?php esc_attr_e('Login', 'inkfire-login-styler'); ?>">
          <div class="if-cta-row">
            <div class="if-cta-cell">
              <div class="if-card" id="if-login-card">
                <?php echo ifls_render_inline_form($action); // Output is already escaped in the function ?>
              </div>
            </div>
          </div>

          <nav class="if-aux" aria-label="<?php esc_attr_e('Helpful links', 'inkfire-login-styler'); ?>">
            <div class="if-aux-links">
              <?php if ($action !== 'register' && get_option('users_can_register')) : ?>
                <a class="if-aux-link" href="<?php echo esc_url(wp_registration_url()); ?>"><?php esc_html_e('Create an account', 'inkfire-login-styler'); ?></a>
                <span class="sep" aria-hidden="true">•</span>
              <?php elseif ($action === 'register') : ?>
                <a class="if-aux-link" href="<?php echo esc_url(wp_login_url()); ?>">&larr; <?php esc_html_e('Back to Login', 'inkfire-login-styler'); ?></a>
                <span class="sep" aria-hidden="true">•</span>
              <?php endif; ?>

              <a class="if-aux-link" href="<?php echo esc_url($lost_url); ?>"><?php esc_html_e('Lost your password?', 'inkfire-login-styler'); ?></a>
              <span class="sep" aria-hidden="true">•</span>
              <a class="if-aux-link" href="<?php echo esc_url($home_url); ?>">&larr; <?php echo esc_html(sprintf(__('Back to %s', 'inkfire-login-styler'), $site_name)); ?></a>
              <?php if ($policy_url) : ?>
                <span class="sep" aria-hidden="true">•</span>
                <a class="if-aux-link" href="<?php echo esc_url($policy_url); ?>"><?php esc_html_e('Privacy Policy', 'inkfire-login-styler'); ?></a>
              <?php endif; ?>
            </div>
          </nav>
        </section>
      </main>

      <aside class="if-left" role="complementary" aria-label="<?php esc_attr_e('Contact information', 'inkfire-login-styler'); ?>">
        <div class="if-left-block">
          <img class="if-icon" src="<?php echo esc_url(INKFIRE_LOGIN_ICON); ?>" alt="" decoding="async" />
          <h3><?php esc_html_e('Stay in touch', 'inkfire-login-styler'); ?></h3>
          <p>
            <a class="if-accent" href="mailto:hello@inkfire.co.uk">hello@inkfire.co.uk</a><br>
            <a class="if-accent" href="tel:+443336134653">+44 (0)333 613 4653</a><br>
            <a class="if-accent" href="https://inkfire.co.uk/" target="_blank" rel="noopener">inkfire.co.uk</a>
          </p>
        </div>

        <div class="if-left-block">
          <h4><?php esc_html_e('Opening Times', 'inkfire-login-styler'); ?></h4>
          <p><?php esc_html_e('Monday – Friday', 'inkfire-login-styler'); ?><br><strong><?php esc_html_e('9am – 5pm GMT', 'inkfire-login-styler'); ?></strong></p>
        </div>

        <div class="if-left-block">
          <h4><?php esc_html_e('Follow Us', 'inkfire-login-styler'); ?></h4>
          <div class="if-socials">
            <a href="https://facebook.com/inkfirelimited" target="_blank" rel="noopener" aria-label="Facebook"><i class="fa-brands fa-facebook-f" aria-hidden="true"></i></a>
            <a href="https://www.instagram.com/inkfirelimited/" target="_blank" rel="noopener" aria-label="Instagram"><i class="fa-brands fa-instagram" aria-hidden="true"></i></a>
            <a href="https://uk.linkedin.com/company/inkfire" target="_blank" rel="noopener" aria-label="LinkedIn"><i class="fa-brands fa-linkedin-in" aria-hidden="true"></i></a>
            <a href="https://twitter.com/Inkfirelimited" target="_blank" rel="noopener" aria-label="X (Twitter)"><i class="fa-brands fa-x-twitter" aria-hidden="true"></i></a>
            <a href="https://www.tiktok.com/@inkfirelimited" target="_blank" rel="noopener" aria-label="TikTok"><i class="fa-brands fa-tiktok" aria-hidden="true"></i></a>
          </div>
        </div>

        <div class="if-left-block if-legal" aria-label="<?php esc_attr_e('Company information', 'inkfire-login-styler'); ?>">
          <p class="if-legal-small"><?php esc_html_e('Company Number: 15153305', 'inkfire-login-styler'); ?><br><?php esc_html_e('VAT Number: GB483189752', 'inkfire-login-styler'); ?></p>
        </div>

        <?php if ($lang_selector) : ?>
          <div class="if-left-block if-lang-left" aria-label="<?php esc_attr_e('Language selector', 'inkfire-login-styler'); ?>">
            <?php echo $lang_selector; // Output is pre-processed and considered safe. ?>
          </div>
        <?php endif; ?>
      </aside>

    </div>
  </div>
<?php
}

/**
 * Enqueues styles and outputs inline CSS for the login page.
 *
 * @since 1.0.0
 */
function ifls_enqueue_login_styles() {
    wp_dequeue_style('login');
    wp_enqueue_style('if-fa', 'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css', [], '6.5.2');
    ?>
  <style>
    .login h1, .login #backtoblog, .login #nav { display:none !important; }
    .login .screen-reader-text { position:absolute !important; width:1px !important; height:1px !important; padding:0 !important; margin:-1px !important; overflow:hidden !important; clip:rect(0 0 0 0) !important; white-space:nowrap !important; border:0 !important; }
    *,*::before,*::after{box-sizing:border-box}
    html,body.login{height:100%}
    body.login{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;line-height:1.45;color:<?php echo IF_TEXT; ?>;background:#fff}

    .if-full-bg{width:100vw;min-height:100vh;margin-left:calc(50% - 50vw);
      background-image:url('<?php echo esc_url(INKFIRE_LOGIN_BG); ?>');
      background-size:cover;background-position:center;background-attachment:scroll;
      display:grid;place-items:center;padding:16px}

    .if-shell{width:100%;max-width:1200px;border-radius:35px;overflow:hidden;background:#fff;box-shadow:0 10px 15px -3px rgba(0,0,0,.1),0 4px 6px -4px rgba(0,0,0,.1);
      display:grid;grid-template-columns:1fr 1.8fr;grid-template-areas:'left right'}
    .if-left{grid-area:left}
    .if-right{grid-area:right}
    @media (max-width:960px){ .if-shell{grid-template-columns:1fr;grid-template-areas:'right' 'left'} }

    .if-right{background:#fff;display:grid;grid-template-rows:auto 1fr}
    .if-left{background:<?php echo IF_TEAL; ?>;color:#fff;padding:48px 28px;display:grid;align-content:center;justify-items:center;gap:25px}

    .if-left-block{max-width:360px;text-align:center}
    .if-icon{width:64px;height:64px;display:block;margin:0 auto 12px}
    .if-left h3{color:<?php echo IF_PILL; ?>;margin:0 0 10px;font-size:clamp(20px,2.2vw,28px);font-weight:800}
    .if-left h4{color:<?php echo IF_PILL; ?>;margin:0 0 8px;font-size:clamp(16px,1.7vw,18px);font-weight:800}
    .if-accent{color:#ffffff;text-decoration:none;font-weight:700}
    .if-socials{display:flex;flex-wrap:wrap;gap:10px;justify-content:center}
    .if-socials a{color:#fff;display:inline-flex;text-decoration:none;align-items:center;justify-content:center;width:36px;height:36px;border-radius:999px;background:rgba(255,255,255,.14);box-shadow:inset 0 0 0 1px rgba(255,255,255,.18)}

    .if-legal{font-size:14px;line-height:1.45;color:#eaf5f4}
    .if-legal-small{opacity:.95;margin:2px 0 0}

    .if-lang-left #if-language-switcher{display:flex;align-items:center;justify-content:center;gap:8px;margin:0 auto}
    .if-lang-left #if-language-switcher label{display:none}
    .if-lang-left #if-language-switcher select{border-radius:10px;border:1px solid rgba(255,255,255,.35);background:#0f4c50;color:#fff;padding:6px 8px}
    .if-lang-left #if-language-switcher input[type="submit"]{border-radius:8px;border:1px solid rgba(255,255,255,.35);background:#0f4c50;color:#fff;padding:6px 10px}

    .if-logo-wrap{display:grid;place-items:center;padding:40px 18px}
    .if-logo{width:clamp(180px,38vw,360px);height:auto}

    .if-teal{background:<?php echo IF_TEAL2; ?>;padding:38px 38px 30px;display:grid;gap:20px;align-content:start;justify-items:stretch}
    .if-cta-row{display:flex;gap:28px;align-items:stretch;justify-content:center;flex-direction:column}
    @media (min-width:961px){ .if-cta-row{flex-direction:row} }
    .if-cta-cell{flex:1 1 0;min-width:0;display:flex}

    .if-card{position:relative;background:#fff;border-radius:25px;padding:35px;box-shadow:0 14px 24px -10px rgba(0,0,0,.15);width:100%;display:flex;flex-direction:column;align-items:stretch;text-align:left}

    .if-card-title{display:inline-block;margin:0 0 25px;font-weight:800;font-size:20px;line-height:1;color:#1b1b1b;background:<?php echo IF_PILL; ?>;padding:8px 14px;border-radius:999px;box-shadow:0 6px 12px -8px rgba(0,0,0,.25)}

    #if_card_loginform p, #if_lostpasswordform p, #if_resetpassform p, #if_registerform p{margin:0 0 12px}
    #if_card_loginform label, #if_lostpasswordform label, #if_resetpassform label, #if_registerform label{display:block;font-weight:600;color:#223;margin:0 0 6px}
    #if_card_loginform .input, #if_lostpasswordform .input, #if_resetpassform .input, #if_registerform .input,
    #if_card_loginform input[type="text"], #if_card_loginform input[type="password"],
    #if_lostpasswordform input[type="text"], #if_lostpasswordform input[type="email"],
    #if_resetpassform input[type="password"],
    #if_registerform input[type="text"], #if_registerform input[type="email"]{
      width:100%;border-radius:999px;border:1px solid #d7dee0;background:#fff;padding:14px 16px;font-size:16px;color:#111}
    #if_card_loginform .input:focus, #if_lostpasswordform .input:focus, #if_resetpassform .input:focus, #if_registerform .input:focus{border-color:#179AD6;box-shadow:0 0 0 3px rgba(23,154,214,.25);outline:0}
    #if_card_loginform .forgetmenot{display:flex;align-items:center;gap:8px;margin-top:4px}
    #if_card_loginform .forgetmenot label{margin:0;font-weight:500;color:#334}

    .wp-core-ui #if_card_loginform .button-primary,
    .wp-core-ui #if_lostpasswordform .button-primary,
    .wp-core-ui #if_resetpassform .button-primary,
    .wp-core-ui #if_registerform .button-primary{
      cursor:pointer;background:<?php echo IF_PILL; ?>;color:#1b1b1b;border:none;border-radius:999px;padding:12px 22px;font-weight:700;font-size:16px;box-shadow:0 12px 18px -10px rgba(0,0,0,.2);text-shadow:none;transition:background .18s ease,color .18s ease,transform .06s ease}
    .wp-core-ui #if_card_loginform .button-primary:hover, .wp-core-ui #if_lostpasswordform .button-primary:hover,
    .wp-core-ui #if_resetpassform .button-primary:hover, .wp-core-ui #if_registerform .button-primary:hover,
    .wp-core-ui #if_card_loginform .button-primary:active, .wp-core-ui #if_lostpasswordform .button-primary:active,
    .wp-core-ui #if_resetpassform .button-primary:active, .wp-core-ui #if_registerform .button-primary:active{background:<?php echo IF_TEAL2; ?>;color:#fff;transform:translateY(-1px)}
    .wp-core-ui #if_card_loginform .button-primary:focus-visible, .wp-core-ui #if_lostpasswordform .button-primary:focus-visible,
    .wp-core-ui #if_resetpassform .button-primary:focus-visible, .wp-core-ui #if_registerform .button-primary:focus-visible{outline:3px solid <?php echo IF_ORANGE; ?>;outline-offset:2px}

    .if-aux{position:relative;display:flex;align-items:center;justify-content:center;color:#fff}
    .if-aux-links{display:flex;flex-wrap:wrap;align-items:center;justify-content:center;gap:12px}
    .if-aux-link{display:inline-flex;align-items:center;justify-content:center;padding:7px 17px;border-radius:14px;background:rgba(255,255,255,.12);color:#fff;text-decoration:none;transition:background .18s ease,color .18s ease,transform .06s ease}
    .if-aux-link:hover,.if-aux-link:active{background:<?php echo IF_ORANGE; ?>;color:#fff;transform:translateY(-1px)}
    .if-aux-link:focus-visible{outline:3px solid #F4C946;outline-offset:2px}
    .if-aux-links .sep{display:none}

    @media (max-width:960px){
      .if-left{padding:36px 20px} .if-teal{padding:30px 24px 24px}
      .if-card{padding:28px} .if-card-title{margin-bottom:12px;padding:7px 12px}
    }
    @media (max-width:520px){
      .if-logo-wrap{padding:28px 14px} .if-card{padding:20px}
      .if-aux-links{gap:10px} .if-aux-link{width:100%; max-width:420px}
    }

    .inkfire-inline-form #language-switcher{display:none !important}
    .inkfire-inline-form #login{display:none !important}
    @media (prefers-reduced-motion: reduce){ *{animation:none !important; transition:none !important} }
  </style>
    <?php
}

/**
 * Enqueues styles for the admin area, specifically for the session timeout modal.
 *
 * @since 1.6.0
 */
function ifls_enqueue_admin_styles() {
    // These styles target the 'wp-auth-check' modal that appears on session timeout.
    // We use !important to ensure they override default admin styles in this specific context.
    ?>
    <style>
        #wp-auth-check-form .input,
        #wp-auth-check-form input[type="text"],
        #wp-auth-check-form input[type="password"] {
            width: 100%;
            border-radius: 999px !important;
            border: 1px solid #d7dee0 !important;
            background: #fff !important;
            padding: 14px 16px !important;
            font-size: 16px !important;
            color: #111 !important;
            margin-bottom: 12px;
        }
        #wp-auth-check-form .input:focus {
            border-color: #179AD6 !important;
            box-shadow: 0 0 0 3px rgba(23,154,214,.25) !important;
            outline: 0 !important;
        }
        #wp-auth-check-form .button-primary {
            cursor: pointer !important;
            background: <?php echo IF_PILL; ?> !important;
            color: #1b1b1b !important;
            border: none !important;
            border-radius: 999px !important;
            padding: 10px 20px !important;
            font-weight: 700 !important;
            font-size: 15px !important;
            box-shadow: 0 12px 18px -10px rgba(0,0,0,.2) !important;
            text-shadow: none !important;
            height: auto !important;
            line-height: normal !important;
            float: none !important;
            width: 100%;
            transition: background .18s ease, color .18s ease, transform .06s ease !important;
        }
        #wp-auth-check-form .button-primary:hover,
        #wp-auth-check-form .button-primary:active {
            background: <?php echo IF_TEAL2; ?> !important;
            color: #fff !important;
            transform: translateY(-1px) !important;
        }
        #wp-auth-check-form .button-primary:focus-visible {
            outline: 3px solid <?php echo IF_ORANGE; ?> !important;
            outline-offset: 2px !important;
        }
        #wp-auth-check-form .forgetmenot {
            margin-top: 5px !important;
            margin-bottom: 15px !important;
        }
        #wp-auth-check-form #login_error {
            margin-bottom: 15px !important;
        }
    </style>
    <?php
}

/**
 * Adds a descriptive text to the plugin's entry in the plugin list table.
 *
 * @since 1.4.0
 * @param array  $links An array of the plugin's metadata.
 * @param string $file  The plugin file path.
 * @return array The modified array of plugin metadata.
 */
function ifls_plugin_row_meta($links, $file) {
    if (plugin_basename(__FILE__) === $file) {
        $description = __('Custom, accessible login page with Inkfire branding. Supports login, password reset, and optional registration with a responsive two‑column layout.', 'inkfire-login-styler');
        $links[] = esc_html($description);
    }
    return $links;
}


/* ==========================================================================
   Hook into WordPress
   ========================================================================== */

add_filter('login_headerurl', 'ifls_login_header_url');
add_filter('login_headertext', 'ifls_login_header_text');
add_filter('login_body_class', 'ifls_login_body_class');
add_action('login_header', 'ifls_render_login_layout');
add_action('login_enqueue_scripts', 'ifls_enqueue_login_styles');
add_action('login_footer', '__return_null');
add_filter('login_redirect', 'ifls_secure_login_redirect', 10, 3);
add_filter('plugin_row_meta', 'ifls_plugin_row_meta', 10, 2);
add_action('admin_enqueue_scripts', 'ifls_enqueue_admin_styles');
