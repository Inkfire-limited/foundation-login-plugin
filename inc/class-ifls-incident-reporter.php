<?php
/**
 * Detects that the plugin itself is malfunctioning and reports it to Inkfire.
 *
 * Two rules govern this class:
 *
 *   1. Store locally BEFORE attempting to send. When the incident IS mail
 *      failure, the local copy is the only record that will ever exist.
 *
 *   2. Never send incident mail during ordinary requests. Incidents are queued
 *      and dispatched off the request path, because sending inline would block
 *      every failed login for the SMTP timeout on exactly those sites whose
 *      mail is already broken.
 *
 * The cross-site channel carries counts and technical context only. End-user
 * IPs, usernames and email addresses stay in the client's own dashboard.
 *
 * @package Inkfire_Login_Styler
 */

if (!defined('ABSPATH')) {
    exit;
}

class IFLS_Incident_Reporter {

    const OPTION   = 'ifls_incidents';
    const MAX_KEPT = 50;
    const DISPATCH_WINDOW = 'ifls_incident_dispatch_after';
    const MAX_PER_WINDOW = 2;
    const MAX_ATTEMPTS = 3;

    private static $sending = false;

    /**
     * Identity of an incident for deduplication purposes.
     *
     * Digits are normalised away so that "5 failures" and "17 failures" are
     * recognised as the same ongoing incident rather than new ones.
     *
     * @param string $type   Incident type.
     * @param string $reason Human-readable reason.
     * @return string
     */
    public static function fingerprint($type, $reason) {
        return sha1($type . '|' . preg_replace('/\d+/', 'N', (string) $reason));
    }

    /**
     * Record an incident. Never sends mail. Never throws.
     *
     * @param string $type    Machine type, e.g. mail_failure.
     * @param string $reason  Human-readable reason.
     * @param array  $context Technical context only - no end-user PII.
     */
    public static function raise($type, $reason, array $context = []) {
        if (('mail_failure' === $type && self::$sending) || !ifls_diag_enabled() || !ifls_diag_setting('reporting_enabled')) {
            return;
        }

        try {
            self::do_raise($type, $reason, $context);
        } catch (\Throwable $e) {
            // Reporting must never break the site it is reporting on.
        }
    }

    /**
     * @param string $type    Incident type.
     * @param string $reason  Reason text.
     * @param array  $context Context payload.
     */
    private static function do_raise($type, $reason, array $context) {
        $type = sanitize_key($type);

        if ('' === $type) {
            return;
        }

        $fingerprint = self::fingerprint($type, $reason);
        $now         = time();
        $cooldown    = absint(ifls_diag_setting('cooldown_hours')) * HOUR_IN_SECONDS;

        self::edit_incidents(static function (&$incidents) use ($type, $fingerprint, $reason, $context, $now, $cooldown) {
            foreach ($incidents as &$incident) {
                if (($incident['fingerprint'] ?? '') !== $fingerprint) {
                    continue;
                }
                // A genuinely recurring, previously delivered alert can start a new cycle.
                // Exhausted alerts remain available locally even if failures continue.
                if ('sent' === $incident['status'] && $now - (int) $incident['first_seen'] >= $cooldown) {
                    $incident['first_seen'] = $now;
                    $incident['status'] = 'pending';
                    unset($incident['attempts'], $incident['next_attempt']);
                }
                $incident['count']++;
                $incident['last_seen'] = $now;
                return true;
            }
            unset($incident);

            array_unshift($incidents, [
                'fingerprint' => $fingerprint,
                'type'        => $type,
                'reason'      => substr(sanitize_text_field((string) $reason), 0, 500),
                'context'     => self::scrub($context),
                'first_seen'  => $now,
                'last_seen'   => $now,
                'count'       => 1,
                'status'      => 'pending',
            ]);
            $incidents = array_slice($incidents, 0, self::MAX_KEPT);
            return true;
        });
    }

    /**
     * Strip anything resembling end-user personal data.
     *
     * Belt and braces: known keys are removed outright, and every remaining
     * string is scanned for embedded IPs and email addresses, because context
     * is assembled by callers who may not be thinking about it.
     *
     * @param array $context Raw context.
     * @return array
     */
    private static function scrub(array $context) {
        unset($context['ip'], $context['username'], $context['email'], $context['user_email'], $context['user_login']);

        array_walk_recursive(
            $context,
            function (&$value) {
                if (!is_string($value)) {
                    return;
                }

                // IPv4, IPv6, then email addresses.
                $value = preg_replace('/\b\d{1,3}(?:\.\d{1,3}){3}\b/', '[ip removed]', $value);
                $value = preg_replace('/\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b/i', '[ip removed]', $value);
                $value = preg_replace('/[\w.+-]+@[\w-]+\.[\w.]+/', '[email removed]', $value);
            }
        );

        return $context;
    }

    /**
     * @return array Stored incidents, newest first. Always an array.
     */
    public static function incidents() {
        $stored = get_option(self::OPTION, []);
        return is_array($stored) ? $stored : [];
    }

    /**
     * Update the bounded queue only if nobody has edited it since the read.
     * Never hold a database lock over a mail call. Retry on a concurrent edit.
     */
    private static function edit_incidents(callable $edit) {
        global $wpdb;
        for ($try = 0; $try < 4; $try++) {
            $old = $wpdb->get_var($wpdb->prepare("SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", self::OPTION));
            $incidents = null === $old ? [] : maybe_unserialize($old);
            if (!is_array($incidents) || !$edit($incidents)) {
                return false;
            }

            $new = maybe_serialize($incidents);
            if (null === $old) {
                $saved = $wpdb->query($wpdb->prepare(
                    "INSERT IGNORE INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'no')",
                    self::OPTION, $new
                ));
            } else {
                $saved = $wpdb->update($wpdb->options, ['option_value' => $new], ['option_name' => self::OPTION, 'option_value' => $old]);
            }
            if (1 === $saved) {
                wp_cache_delete(self::OPTION, 'options');
                if (null === $old) {
                    wp_cache_delete('notoptions', 'options');
                }
                return true;
            }
            if (false === $saved) {
                return false;
            }
        }
        return false;
    }

    /**
     * Remove all stored incidents.
     */
    public static function clear() {
        delete_option(self::OPTION);
    }

    /**
     * Evaluate failure thresholds against the event log.
     *
     * Called from cron, never from the authentication path.
     */
    public static function check_thresholds() {
        if (!ifls_diag_enabled() || !ifls_diag_setting('reporting_enabled')) {
            return;
        }

        try {
            $count   = absint(ifls_diag_setting('threshold_count'));
            $minutes = absint(ifls_diag_setting('threshold_minutes'));

            $csrf = IFLS_Event_Log::count_since('csrf_blocked', $minutes);
            if ($csrf >= $count) {
                self::raise(
                    'csrf_storm',
                    sprintf('%d blocked security checks in %d minutes', $csrf, $minutes),
                    [
                        'counts'         => ['csrf_blocked' => $csrf],
                        'window_minutes' => $minutes,
                    ]
                );
            }

            $failed    = IFLS_Event_Log::count_since('reset_failed', $minutes);
            $completed = IFLS_Event_Log::count_since('reset_completed', $minutes);

            // The second clause is what separates "users clicked stale links"
            // from "password reset is broken". Without it this alert is noise.
            if ($failed >= $count && 0 === $completed) {
                self::raise(
                    'reset_storm',
                    sprintf('%d failed password resets in %d minutes with no successful reset', $failed, $minutes),
                    [
                        'counts'         => [
                            'reset_failed'    => $failed,
                            'reset_completed' => 0,
                        ],
                        'window_minutes' => $minutes,
                    ]
                );
            }
        } catch (\Throwable $e) {
            // no-op
        }
    }

    /** Reserve a site-wide dispatch window, including across overlapping cron runners. */
    private static function claim_window($now) {
        global $wpdb;
        $next = $now + 5 * MINUTE_IN_SECONDS;
        $updated = $wpdb->query($wpdb->prepare(
            "UPDATE {$wpdb->options} SET option_value = %s WHERE option_name = %s AND CAST(option_value AS UNSIGNED) <= %d",
            (string) $next, self::DISPATCH_WINDOW, $now
        ));
        if (0 === $updated) {
            $updated = $wpdb->query($wpdb->prepare(
                "INSERT IGNORE INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'no')",
                self::DISPATCH_WINDOW, (string) $next
            ));
        }
        return 1 === $updated;
    }

    private static function due(array $incident, $now) {
        $status = $incident['status'] ?? '';
        // Legacy failed alerts have an unknown attempt count. Keep them stopped.
        return ('pending' === $status || ('failed' === $status && isset($incident['attempts'])))
            && ($incident['attempts'] ?? 0) < self::MAX_ATTEMPTS
            && ($incident['next_attempt'] ?? 0) <= $now;
    }

    /** Dispatch only from cron. Persist each attempt before handing it to transport. */
    public static function dispatch() {
        if (!wp_doing_cron() || !ifls_diag_enabled() || !ifls_diag_setting('reporting_enabled')
            || !apply_filters('ifls_allow_incident_email_dispatch', true)) {
            return;
        }

        $now = time();
        $processed = 0;
        foreach (array_reverse(self::incidents()) as $incident) {
            if (!is_array($incident) || empty($incident['fingerprint']) || !self::due($incident, $now)) {
                continue;
            }
            if (0 === $processed && !self::claim_window($now)) {
                return;
            }
            $fingerprint = $incident['fingerprint'];
            $attempt = 0;
            $claimed = self::edit_incidents(static function (&$rows) use ($fingerprint, $now, &$attempt) {
                foreach ($rows as &$row) {
                    if ($row['fingerprint'] === $fingerprint && self::due($row, $now)) {
                        $attempt = 1 + ($row['attempts'] ?? 0);
                        $row['attempts'] = $attempt;
                        $row['status'] = 'failed';
                        $row['next_attempt'] = $now + (1 === $attempt ? 15 * MINUTE_IN_SECONDS : HOUR_IN_SECONDS);
                        return true;
                    }
                }
                return false;
            });
            if ($claimed) {
                try {
                    self::$sending = true;
                    $sent = wp_mail(ifls_diag_setting('report_email'), self::subject($incident), self::body($incident));
                } catch (\Throwable $e) {
                    $sent = false;
                } finally {
                    self::$sending = false;
                }
                if ($sent) {
                    self::edit_incidents(static function (&$rows) use ($fingerprint, $attempt, $incident) {
                        foreach ($rows as &$row) {
                            if ($row['fingerprint'] === $fingerprint && $row['first_seen'] === $incident['first_seen']
                                && ($row['attempts'] ?? 0) === $attempt) {
                                $row['status'] = 'sent';
                                return true;
                            }
                        }
                        return false;
                    });
                }
            }
            if (++$processed >= self::MAX_PER_WINDOW) {
                return;
            }
        }
    }

    /**
     * @param array $incident Incident record.
     * @return string
     */
    private static function subject(array $incident) {
        return sprintf(
            '[Foundation] %s - %s',
            wp_parse_url(home_url(), PHP_URL_HOST),
            str_replace('_', ' ', $incident['type'])
        );
    }

    /**
     * @param array $incident Incident record.
     * @return string
     */
    private static function body(array $incident) {
        $theme = wp_get_theme();

        $lines = [
            'A Foundation Inkfire Login incident was recorded.',
            '',
            'Site:        ' . home_url(),
            'Incident:    ' . $incident['type'],
            'Reason:      ' . $incident['reason'],
            'First seen:  ' . gmdate('Y-m-d H:i:s', (int) $incident['first_seen']) . ' UTC',
            'Last seen:   ' . gmdate('Y-m-d H:i:s', (int) $incident['last_seen']) . ' UTC',
            'Occurrences: ' . (int) $incident['count'],
            '',
            'Plugin:      ' . IFLS_VERSION,
            'WordPress:   ' . get_bloginfo('version'),
            'PHP:         ' . PHP_VERSION,
            'Theme:       ' . ($theme ? $theme->get('Name') : 'unknown'),
            '',
            'Context:',
            wp_json_encode($incident['context'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES),
            '',
            'Per-user detail is deliberately not included in this email. It is',
            'available on the site itself under Foundation > Diagnostics.',
        ];

        return implode("\n", $lines);
    }
}
