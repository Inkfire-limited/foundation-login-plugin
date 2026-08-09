<?php
/**
 * Mail transport diagnostics.
 *
 * Surfaces in the admin what previously required hand-written throwaway
 * scripts: what wp_mail() actually did, which transport carried it, and
 * whether the domain's DNS says that transport is going to be believed.
 *
 * @package Inkfire_Login_Styler
 */

if (!defined('ABSPATH')) {
    exit;
}

class IFLS_Mail_Diagnostics {

    /**
     * Mail providers whose presence in MX means email is hosted elsewhere.
     */
    const EXTERNAL_MX_PATTERN = '/(outlook|office365|microsoft|google|googlemail|zoho|fastmail|protection\.outlook|messagelabs|mimecast|proofpoint)/i';

    /**
     * Send one test message and report exactly what the transport did.
     *
     * The recipient is passed in by the caller, which must never take it from
     * the request body - otherwise this becomes an open relay.
     *
     * @param string $to Recipient address.
     * @return array sent, error, transport, to
     */
    public static function send_test($to) {
        $to = sanitize_email((string) $to);

        if (!is_email($to)) {
            return [
                'sent'      => false,
                'error'     => __('No valid recipient address is configured.', 'inkfire-login-styler'),
                'transport' => [],
                'to'        => $to,
            ];
        }

        $captured = [];
        $error    = '';

        $capture = function ($phpmailer) use (&$captured) {
            $captured = [
                'mailer'    => isset($phpmailer->Mailer) ? $phpmailer->Mailer : '',
                'host'      => isset($phpmailer->Host) ? $phpmailer->Host : '',
                'from'      => isset($phpmailer->From) ? $phpmailer->From : '',
                'from_name' => isset($phpmailer->FromName) ? $phpmailer->FromName : '',
                'sender'    => isset($phpmailer->Sender) ? $phpmailer->Sender : '',
                'smtp_auth' => !empty($phpmailer->SMTPAuth),
            ];
        };

        $fail = function ($wp_error) use (&$error) {
            $error = is_wp_error($wp_error) ? $wp_error->get_error_message() : '';
        };

        add_action('phpmailer_init', $capture, PHP_INT_MAX);
        add_action('wp_mail_failed', $fail);

        $sent = wp_mail(
            $to,
            sprintf(
                /* translators: %s: site host name. */
                __('Foundation mail test - %s', 'inkfire-login-styler'),
                wp_parse_url(home_url(), PHP_URL_HOST)
            ),
            sprintf(
                "This is a test message from the Foundation Inkfire Login plugin.\n\nSite: %s\nSent: %s UTC\n\nIf this reached the inbox, WordPress mail is leaving this server correctly.\nIf it landed in Junk or Quarantine, that is the finding.",
                home_url(),
                gmdate('Y-m-d H:i:s')
            )
        );

        remove_action('phpmailer_init', $capture, PHP_INT_MAX);
        remove_action('wp_mail_failed', $fail);

        return [
            'sent'      => (bool) $sent,
            'error'     => $error,
            'transport' => $captured,
            'to'        => $to,
        ];
    }

    /**
     * Current transport configuration, without sending anything.
     *
     * @return array
     */
    public static function transport_info() {
        return [
            'sendmail_path' => (string) ini_get('sendmail_path'),
            'wp_mail_from'  => apply_filters('wp_mail_from', 'wordpress@' . wp_parse_url(home_url(), PHP_URL_HOST)),
            'admin_email'   => get_option('admin_email'),
        ];
    }

    /**
     * MX, SPF and DMARC for the site domain.
     *
     * Cached for an hour and wrapped so a slow or broken resolver degrades to
     * "unavailable" rather than hanging the admin page.
     *
     * @return array mx, spf, dmarc, available
     */
    public static function dns_info() {
        $domain = wp_parse_url(home_url(), PHP_URL_HOST);
        $key    = 'ifls_dns_' . md5((string) $domain);
        $cached = get_transient($key);

        if (is_array($cached)) {
            return $cached;
        }

        $info = [
            'mx'        => [],
            'spf'       => '',
            'dmarc'     => '',
            'available' => false,
        ];

        if (!$domain || !function_exists('dns_get_record')) {
            set_transient($key, $info, HOUR_IN_SECONDS);
            return $info;
        }

        try {
            $mx = @dns_get_record($domain, DNS_MX);
            if (is_array($mx)) {
                foreach ($mx as $record) {
                    if (isset($record['target'])) {
                        $info['mx'][] = $record['target'];
                    }
                }
            }

            $txt = @dns_get_record($domain, DNS_TXT);
            if (is_array($txt)) {
                foreach ($txt as $record) {
                    if (isset($record['txt']) && 0 === stripos($record['txt'], 'v=spf1')) {
                        $info['spf'] = $record['txt'];
                    }
                }
            }

            $dmarc = @dns_get_record('_dmarc.' . $domain, DNS_TXT);
            if (is_array($dmarc)) {
                foreach ($dmarc as $record) {
                    if (isset($record['txt']) && 0 === stripos($record['txt'], 'v=DMARC1')) {
                        $info['dmarc'] = $record['txt'];
                    }
                }
            }

            $info['available'] = true;
        } catch (\Throwable $e) {
            // Leave as unavailable.
        }

        set_transient($key, $info, HOUR_IN_SECONDS);

        return $info;
    }

    /**
     * Human-readable warnings about likely delivery problems.
     *
     * @param array $transport From send_test()['transport'].
     * @param array $dns       From dns_info().
     * @return string[]
     */
    public static function warnings(array $transport, array $dns) {
        $warnings = [];

        $mailer = isset($transport['mailer']) ? $transport['mailer'] : '';
        $local  = ('mail' === $mailer || '' === $mailer);

        $external_mx = false;
        $mx_records  = isset($dns['mx']) && is_array($dns['mx']) ? $dns['mx'] : [];

        foreach ($mx_records as $mx) {
            if (preg_match(self::EXTERNAL_MX_PATTERN, (string) $mx)) {
                $external_mx = true;
                break;
            }
        }

        if ($local && $external_mx) {
            $warnings[] = __(
                'This domain\'s email is hosted externally (for example Microsoft 365), but WordPress is sending through the local PHP mail() transport. Messages may be quarantined or rejected by the recipient - most often for addresses on this same domain, because the receiving tenant treats them as spoofed. Routing mail through an authenticated SMTP service is the usual fix.',
                'inkfire-login-styler'
            );
        }

        if ($local && empty($transport['sender'])) {
            $warnings[] = __(
                'No envelope sender (Return-Path) is set, so SPF is evaluated against whatever address the host substitutes rather than this domain. That commonly breaks DMARC alignment even when the SPF record itself looks correct.',
                'inkfire-login-styler'
            );
        }

        return $warnings;
    }
}
