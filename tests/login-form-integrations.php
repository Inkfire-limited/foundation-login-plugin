<?php
/** Auth form integrations. Runs inside the WordPress Playground suite. */

ob_start();
do_action('woocommerce_resetpassword_form');
$reset_fields = ob_get_clean();
$fields = new WP_HTML_Tag_Processor($reset_fields);
$tokens = [];
while ($fields->next_tag('input')) {
    if ('ifls_form_nonce' === $fields->get_attribute('name')) {
        $tokens[] = $fields->get_attribute('value');
    }
}
ifls_playground_assert(1 === count($tokens) && wp_verify_nonce($tokens[0], 'ifls_form_action'), 'WooCommerce reset form must supply one valid Inkfire token.');
$_SERVER['REQUEST_METHOD'] = 'POST';
$_POST = ['ifls_form_nonce' => $tokens[0]];
do_action('validate_password_reset', new WP_Error(), get_userdata($user));
$_POST = [];
$blocked = false;
try {
    do_action('validate_password_reset', new WP_Error(), get_userdata($user));
} catch (RuntimeException $error) {
    $blocked = __('Security check failed.', 'inkfire-login-styler') === $error->getMessage();
}
ifls_playground_assert($blocked, 'Submitted reset without the Inkfire token must still fail validation.');

global $aio_wp_security;
$aio_wp_security = (object) [
    'configs' => new class {
        public $settings = [
            'aiowps_enable_login_captcha' => '1',
            'aiowps_enable_custom_login_captcha' => '0',
            'aiowps_default_captcha' => 'simple-math',
        ];
        public function get_value($key) {
            return $this->settings[$key];
        }
    },
    'captcha_obj' => new class {
        public function display_captcha_form($type, $return_html) {
            return 'simple-math' === $type && true === $return_html ? '<input name="fixture-captcha" />' : '';
        }
    },
];

$form = ifls_render_inline_form('login');
ifls_playground_assert(1 === preg_match('/<form\b[^>]*>(?:(?!<\/form>).)*name="fixture-captcha"/s', $form), 'Configured CAPTCHA missing inside the branded form.');
ifls_playground_assert(false === strpos(wp_login_form(['echo' => false]), 'fixture-captcha'), 'Inkfire added a CAPTCHA to an unrelated form.');
$aio_wp_security->configs->settings['aiowps_enable_custom_login_captcha'] = '1';
$native_captcha = static function ($middle) { return $middle . '<input name="fixture-captcha" />'; };
add_filter('login_form_middle', $native_captcha);
ifls_playground_assert(1 === substr_count(ifls_render_inline_form('login'), 'fixture-captcha'), 'AIOS custom-form mode must render its own CAPTCHA exactly once.');
remove_filter('login_form_middle', $native_captcha);
$aio_wp_security->configs->settings['aiowps_enable_login_captcha'] = '0';
ifls_playground_assert(false === strpos(ifls_render_inline_form('login'), 'fixture-captcha'), 'Disabled CAPTCHA appeared in the branded form.');
unset($GLOBALS['aio_wp_security']);

$notice_calls = 0;
add_filter('login_message', static function ($message) use (&$notice_calls) {
    ++$notice_calls;
    return $message . '<p class="message" role="alert">Fixture retry notice</p>';
});
$_REQUEST = [];
ob_start();
do_action('login_header');
// Core filters its message inside #login, then closes that block before login_footer.
apply_filters('login_message', '<div class="message">Fixture core message</div>');
do_action('login_footer');
$layout = ob_get_clean();
$card = substr($layout, strpos($layout, 'id="if-login-card"'));
$card = substr($card, 0, strpos($card, '</form>'));
ifls_playground_assert(1 === $notice_calls && 1 === substr_count($card, 'Fixture retry notice'), 'Retry notice must appear in the branded card and its provider must run only once.');
ifls_playground_assert(false !== strpos($card, 'Fixture core message') && false !== strpos($card, 'id="if_card_loginform"'), 'Core message or sign-in form missing from the branded card.');
