<?php
/**
 * Diagnostics settings: defaults, accessor, constant precedence, sanitisation.
 *
 * Precedence is: defaults -> stored option -> constant.
 *
 * A constant always wins and locks the corresponding field in the UI, so a
 * site can pin behaviour in wp-config.php and the settings screen tells the
 * truth about it rather than showing an editable value that has no effect.
 *
 * @package Inkfire_Login_Styler
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Default settings, and the authoritative list of valid keys.
 *
 * @return array
 */
function ifls_diag_defaults() {
    return [
        'logging_enabled'   => true,
        'retention_days'    => 90,
        'reporting_enabled' => true,
        'report_email'      => 'webmaster@inkfire.co.uk',
        'threshold_count'   => 5,
        'threshold_minutes' => 60,
        'cooldown_hours'    => 6,
    ];
}

/**
 * Permitted range for each numeric setting.
 *
 * @return array<string, array{0:int,1:int}>
 */
function ifls_diag_ranges() {
    return [
        'retention_days'    => [1, 365],
        'threshold_count'   => [1, 100],
        'threshold_minutes' => [5, 1440],
        'cooldown_hours'    => [1, 168],
    ];
}

/**
 * Master kill switch.
 *
 * Checked before any diagnostics work anywhere, so a single line in
 * wp-config.php disables logging, detection and reporting on a live site
 * without needing database access.
 *
 * @return bool
 */
function ifls_diag_enabled() {
    return !(defined('IFLS_DISABLE_DIAGNOSTICS') && IFLS_DISABLE_DIAGNOSTICS);
}

/**
 * Whether a setting is pinned by a constant, and therefore read-only in the UI.
 *
 * @param string $key Setting key.
 * @return bool
 */
function ifls_diag_is_locked($key) {
    if ('report_email' === $key) {
        return defined('IFLS_REPORT_EMAIL');
    }

    if ('reporting_enabled' === $key) {
        return defined('IFLS_DISABLE_REPORTING');
    }

    return false;
}

/**
 * Read one setting, honouring constant precedence.
 *
 * @param string $key Setting key.
 * @return mixed Null for an unknown key.
 */
function ifls_diag_setting($key) {
    $defaults = ifls_diag_defaults();

    if (!array_key_exists($key, $defaults)) {
        return null;
    }

    // Constants win outright.
    if ('report_email' === $key && defined('IFLS_REPORT_EMAIL')) {
        $pinned = sanitize_email(IFLS_REPORT_EMAIL);
        return is_email($pinned) ? $pinned : $defaults['report_email'];
    }

    if ('reporting_enabled' === $key && defined('IFLS_DISABLE_REPORTING')) {
        return !IFLS_DISABLE_REPORTING;
    }

    $stored = get_option('ifls_diagnostics_settings', []);

    if (!is_array($stored) || !array_key_exists($key, $stored)) {
        return $defaults[$key];
    }

    return $stored[$key];
}

/**
 * Settings API sanitize_callback.
 *
 * Builds the saved array from scratch rather than filtering the input, so an
 * unknown key can never be persisted. Never trusts the posted array shape.
 *
 * @param mixed $input Raw posted value.
 * @return array
 */
function ifls_diag_sanitize($input) {
    $defaults = ifls_diag_defaults();
    $input    = is_array($input) ? $input : [];
    $out      = [];

    // Checkboxes: an absent key means the box was unchecked.
    $out['logging_enabled']   = !empty($input['logging_enabled']);
    $out['reporting_enabled'] = !empty($input['reporting_enabled']);

    // sanitize_email() strips newlines, which is what stops this field being
    // used to inject additional mail headers into the alert emails.
    $email               = isset($input['report_email']) ? sanitize_email($input['report_email']) : '';
    $out['report_email'] = is_email($email) ? $email : $defaults['report_email'];

    foreach (ifls_diag_ranges() as $key => $range) {
        $value     = isset($input[$key]) ? absint($input[$key]) : $defaults[$key];
        $out[$key] = min($range[1], max($range[0], $value));
    }

    return $out;
}
