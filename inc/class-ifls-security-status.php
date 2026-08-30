<?php
/**
 * Security capability detection and operator verification.
 *
 * WordPress can prove the controls it owns. Edge and web-server controls live
 * outside WordPress, so they are never guessed: an administrator must verify
 * them, and that verification expires after 90 days or when the site hostname
 * changes.
 *
 * @package Inkfire_Login_Styler
 */

if (!defined('ABSPATH')) {
    exit;
}
class IFLS_Security_Status {
    const OPTION = 'ifls_security_verifications';
    const MAX_AGE = 7776000; // 90 days.

    public static function init() {
        add_action('admin_post_ifls_security_verification', [__CLASS__, 'handle_verification']);
    }

    public static function site_host() {
        return strtolower((string) wp_parse_url(home_url(), PHP_URL_HOST));
    }

    public static function verifications() {
        $stored = get_option(self::OPTION, []);
        return is_array($stored) ? $stored : [];
    }

    /**
     * Return current, stale or none for an external protection layer.
     *
     * @param string $layer Edge or server.
     * @return string
     */
    public static function verification_status($layer) {
        $layer = sanitize_key((string) $layer);
        if (!in_array($layer, ['edge', 'server'], true)) {
            return 'none';
        }

        $all = self::verifications();
        $item = isset($all[$layer]) && is_array($all[$layer]) ? $all[$layer] : [];
        $verified_at = isset($item['verified_at']) ? absint($item['verified_at']) : 0;
        $host = isset($item['host']) ? strtolower((string) $item['host']) : '';

        if (!$verified_at || !$host || !hash_equals(self::site_host(), $host)) {
            return 'none';
        }

        $max_age = (int) apply_filters('ifls_security_verification_max_age', self::MAX_AGE, $layer);
        if ($max_age > 0 && $verified_at < (time() - $max_age)) {
            return 'stale';
        }

        return 'current';
    }

    public static function verification($layer) {
        $all = self::verifications();
        return isset($all[$layer]) && is_array($all[$layer]) ? $all[$layer] : [];
    }

    public static function edge_observation() {
        if (!empty($_SERVER['HTTP_CF_RAY']) && is_scalar($_SERVER['HTTP_CF_RAY'])) {
            return __('Cloudflare request headers observed. This is a hint, not proof that login WAF rules are enabled.', 'inkfire-login-styler');
        }

        return __('No supported edge provider was detected on this wp-admin request.', 'inkfire-login-styler');
    }

    public static function server_observation() {
        $software = isset($_SERVER['SERVER_SOFTWARE']) && is_scalar($_SERVER['SERVER_SOFTWARE'])
            ? sanitize_text_field(wp_unslash($_SERVER['SERVER_SOFTWARE']))
            : '';

        if (!$software) {
            return __('The web server did not identify itself. Rate-limit configuration cannot be detected from WordPress.', 'inkfire-login-styler');
        }

        return sprintf(
            /* translators: %s: server software string. */
            __('Server reports “%s”. Its rate-limit rules still require manual verification.', 'inkfire-login-styler'),
            $software
        );
    }

    public static function aios_active() {
        $active = (array) get_option('active_plugins', []);
        $network = is_multisite() ? (array) get_site_option('active_sitewide_plugins', []) : [];
        $files = array_merge($active, array_keys($network));

        foreach ($files as $file) {
            if (0 === strpos((string) $file, 'all-in-one-wp-security-and-firewall/')) {
                return true;
            }
        }

        return false;
    }

    public static function checks() {
        $application_ready = class_exists('IFLS_Enterprise_Security')
            && defined('IFLS_MAX_LOGIN_ATTEMPTS')
            && defined('IFLS_MAX_IP_ATTEMPTS')
            && IFLS_MAX_LOGIN_ATTEMPTS > 0
            && IFLS_MAX_IP_ATTEMPTS > 0;

        $owner = strtolower((string) IFLS_AUTH_TELEMETRY_OWNER);
        $aios = self::aios_active();
        $foundation_logging = function_exists('ifls_diag_enabled')
            && ifls_diag_enabled()
            && (bool) ifls_diag_setting('logging_enabled');

        if (!in_array($owner, ['coexist', 'foundation'], true)) {
            $telemetry_tone = 'red';
            $telemetry_label = __('Invalid telemetry owner', 'inkfire-login-styler');
        } elseif (!$foundation_logging && $aios) {
            $telemetry_tone = 'amber';
            $telemetry_label = __('Foundation logging is off; AIOS remains active', 'inkfire-login-styler');
        } elseif (!$foundation_logging) {
            $telemetry_tone = 'red';
            $telemetry_label = __('Foundation failed-login logging is off', 'inkfire-login-styler');
        } elseif ('foundation' === $owner || ('coexist' === $owner && !$aios)) {
            $telemetry_tone = 'green';
            $telemetry_label = 'foundation' === $owner ? __('Foundation owns failed-login telemetry', 'inkfire-login-styler') : __('No known duplicate logger active', 'inkfire-login-styler');
        } elseif ('coexist' === $owner && $aios) {
            $telemetry_tone = 'amber';
            $telemetry_label = __('Foundation and AIOS both log failures', 'inkfire-login-styler');
        }

        $external = [];
        foreach (['edge', 'server'] as $layer) {
            $state = self::verification_status($layer);
            $external[$layer] = [
                'state' => $state,
                'tone' => 'current' === $state ? 'green' : ('stale' === $state ? 'amber' : 'red'),
                'verification' => self::verification($layer),
            ];
        }

        if (!$application_ready || 'red' === $telemetry_tone) {
            $overall_tone = 'red';
            $overall_label = __('Action required', 'inkfire-login-styler');
        } elseif ('green' === $external['edge']['tone'] || 'green' === $external['server']['tone']) {
            $overall_tone = 'green' === $telemetry_tone ? 'green' : 'amber';
            $overall_label = 'green' === $overall_tone ? __('Layered protection verified', 'inkfire-login-styler') : __('Layered protection with a warning', 'inkfire-login-styler');
        } else {
            $overall_tone = 'amber';
            $overall_label = __('Application-only protection', 'inkfire-login-styler');
        }

        return [
            'overall' => ['tone' => $overall_tone, 'label' => $overall_label],
            'application' => [
                'tone' => $application_ready ? 'green' : 'red',
                'label' => $application_ready ? __('Enabled', 'inkfire-login-styler') : __('Unavailable', 'inkfire-login-styler'),
            ],
            'edge' => $external['edge'],
            'server' => $external['server'],
            'telemetry' => [
                'tone' => $telemetry_tone,
                'label' => $telemetry_label,
                'owner' => $owner,
                'aios' => $aios,
                'foundation_logging' => $foundation_logging,
            ],
        ];
    }

    public static function handle_verification() {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to do that.', 'inkfire-login-styler'));
        }

        check_admin_referer('ifls_security_verification');
        $layer = isset($_POST['layer']) ? sanitize_key(wp_unslash($_POST['layer'])) : '';
        $intent = isset($_POST['intent']) ? sanitize_key(wp_unslash($_POST['intent'])) : '';

        if (!in_array($layer, ['edge', 'server'], true) || !in_array($intent, ['verify', 'clear'], true)) {
            wp_die(esc_html__('Invalid security verification request.', 'inkfire-login-styler'), '', ['response' => 400]);
        }

        $all = self::verifications();
        if ('verify' === $intent) {
            $all[$layer] = [
                'host' => self::site_host(),
                'verified_at' => time(),
                'verified_by' => get_current_user_id(),
            ];
        } else {
            unset($all[$layer]);
        }

        update_option(self::OPTION, $all, false);
        $url = add_query_arg('ifls_security_updated', $intent, admin_url('admin.php?page=' . IFLS_Dashboard::PAGE_SLUG));
        wp_safe_redirect($url . '#ifls-security');
        exit;
    }
}
