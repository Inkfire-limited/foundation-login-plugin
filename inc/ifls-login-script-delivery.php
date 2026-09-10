<?php
/** Keep the login script dependency chain out of asynchronous rewriting. */
if (!defined('ABSPATH')) {
    exit;
}

function ifls_login_script_attributes($attributes) {
    // Place the attribute before src and preserve nonce/integrity/other metadata.
    return ['data-cfasync' => 'false'] + $attributes;
}

function ifls_register_login_script_protection() {
    // login_init only runs on the authentication endpoint, not public pages/admin.
    add_filter('wp_script_attributes', 'ifls_login_script_attributes', PHP_INT_MAX);
    add_filter('wp_inline_script_attributes', 'ifls_login_script_attributes', PHP_INT_MAX);
}
add_action('login_init', 'ifls_register_login_script_protection', 0);
