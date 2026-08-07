<?php
/**
 * Authentication event log.
 *
 * This data stays on the client's site. Nothing here is ever transmitted to
 * Inkfire - the incident reporter deliberately carries counts and technical
 * context only.
 *
 * Every public method is fail-safe. This code runs on every authentication on
 * every site the plugin is installed on, so a fault here must degrade to
 * "no logging", never to a broken login screen.
 *
 * @package Inkfire_Login_Styler
 */

if (!defined('ABSPATH')) {
    exit;
}

class IFLS_Event_Log {

    /**
     * Schema version. Bump to trigger dbDelta on upgrade.
     */
    const DB_VERSION = '1.0.0';

    /**
     * The complete set of valid event names. Anything else is discarded.
     */
    const EVENTS = [
        'login_success',
        'login_failed',
        'logout',
        'lockout',
        'reset_requested',
        'reset_completed',
        'reset_failed',
        'csrf_blocked',
        'registration',
    ];

    /**
     * Detail keys that must never reach storage, whatever a caller passes.
     *
     * A reset key in the log would turn a log leak into an account-takeover
     * vector, so this is enforced centrally rather than trusted to callers.
     */
    const FORBIDDEN_DETAIL_KEYS = [
        'rp_key',
        'key',
        'pass1',
        'pass2',
        'password',
        'user_pass',
        'nonce',
        '_wpnonce',
        'ifls_form_nonce',
        'cookie',
    ];

    /**
     * @return string Fully-qualified table name.
     */
    public static function table() {
        global $wpdb;
        return $wpdb->prefix . 'ifls_events';
    }

    /**
     * Create or upgrade the table. Safe to call repeatedly.
     */
    public static function install() {
        global $wpdb;

        $table   = self::table();
        $charset = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE {$table} (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            created_at DATETIME NOT NULL,
            event VARCHAR(32) NOT NULL DEFAULT '',
            user_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
            username VARCHAR(180) NOT NULL DEFAULT '',
            ip VARCHAR(45) NOT NULL DEFAULT '',
            user_agent VARCHAR(255) NOT NULL DEFAULT '',
            outcome VARCHAR(20) NOT NULL DEFAULT '',
            detail TEXT NULL,
            PRIMARY KEY  (id),
            KEY event_time (event, created_at),
            KEY created_at (created_at)
        ) {$charset};";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta($sql);

        update_option('ifls_events_db_version', self::DB_VERSION, false);
    }

    /**
     * Record an event.
     *
     * Never throws. This is the guarantee the whole feature rests on.
     *
     * @param string $event One of self::EVENTS.
     * @param array  $args  username, user_id, outcome, detail (array).
     */
    public static function record($event, array $args = []) {
        if (!ifls_diag_enabled() || !ifls_diag_setting('logging_enabled')) {
            return;
        }

        try {
            self::do_record($event, $args);
        } catch (\Throwable $e) {
            // Deliberately swallowed. Diagnostics must never break auth.
        }
    }

    /**
     * @param string $event Event name.
     * @param array  $args  Event arguments.
     */
    private static function do_record($event, array $args) {
        global $wpdb;

        if (!in_array($event, self::EVENTS, true)) {
            return;
        }

        $detail = isset($args['detail']) && is_array($args['detail']) ? $args['detail'] : [];
        foreach (self::FORBIDDEN_DETAIL_KEYS as $forbidden) {
            unset($detail[$forbidden]);
        }

        $outcome = isset($args['outcome']) ? $args['outcome'] : self::default_outcome($event);

        $username = '';
        if (isset($args['username']) && is_scalar($args['username'])) {
            $username = substr(sanitize_user((string) $args['username'], true), 0, 180);
        }

        $user_agent = '';
        if (isset($_SERVER['HTTP_USER_AGENT'])) {
            $user_agent = substr(sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])), 0, 255);
        }

        $wpdb->insert(
            self::table(),
            [
                'created_at' => gmdate('Y-m-d H:i:s'),
                'event'      => $event,
                'user_id'    => isset($args['user_id']) ? absint($args['user_id']) : 0,
                'username'   => $username,
                'ip'         => self::client_ip(),
                'user_agent' => $user_agent,
                'outcome'    => substr((string) $outcome, 0, 20),
                'detail'     => wp_json_encode($detail),
            ],
            ['%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s']
        );
    }

    /**
     * @param string $event Event name.
     * @return string
     */
    private static function default_outcome($event) {
        if (in_array($event, ['login_success', 'reset_completed', 'registration', 'logout'], true)) {
            return 'success';
        }

        if (in_array($event, ['csrf_blocked', 'lockout'], true)) {
            return 'blocked';
        }

        return 'failure';
    }

    /**
     * Prefer REMOTE_ADDR, matching the plugin's existing hardened resolution.
     *
     * @return string
     */
    private static function client_ip() {
        $ip = isset($_SERVER['REMOTE_ADDR']) ? trim((string) wp_unslash($_SERVER['REMOTE_ADDR'])) : '';
        return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '';
    }

    /**
     * Query events, newest first.
     *
     * @param array $args event, outcome, search, limit, offset.
     * @return array Row objects; always an array, even on failure.
     */
    public static function query(array $args = []) {
        global $wpdb;

        try {
            $where  = ['1=1'];
            $params = [];

            if (!empty($args['event'])) {
                $where[]  = 'event = %s';
                $params[] = $args['event'];
            }

            if (!empty($args['outcome'])) {
                $where[]  = 'outcome = %s';
                $params[] = $args['outcome'];
            }

            if (isset($args['search']) && '' !== $args['search']) {
                // esc_like() stops a bare % matching every row.
                $like     = '%' . $wpdb->esc_like($args['search']) . '%';
                $where[]  = '(username LIKE %s OR ip LIKE %s)';
                $params[] = $like;
                $params[] = $like;
            }

            $params[] = isset($args['limit']) ? absint($args['limit']) : 100;
            $params[] = isset($args['offset']) ? absint($args['offset']) : 0;

            $sql = 'SELECT * FROM ' . self::table()
                 . ' WHERE ' . implode(' AND ', $where)
                 . ' ORDER BY created_at DESC, id DESC LIMIT %d OFFSET %d';

            $rows = $wpdb->get_results($wpdb->prepare($sql, $params));

            return is_array($rows) ? $rows : [];
        } catch (\Throwable $e) {
            return [];
        }
    }

    /**
     * Count occurrences of an event within the last N minutes.
     *
     * @param string $event   Event name.
     * @param int    $minutes Window length.
     * @return int Zero on any failure.
     */
    public static function count_since($event, $minutes) {
        global $wpdb;

        try {
            return (int) $wpdb->get_var(
                $wpdb->prepare(
                    'SELECT COUNT(*) FROM ' . self::table() . ' WHERE event = %s AND created_at > %s',
                    $event,
                    gmdate('Y-m-d H:i:s', time() - (absint($minutes) * MINUTE_IN_SECONDS))
                )
            );
        } catch (\Throwable $e) {
            return 0;
        }
    }

    /**
     * Delete rows past the retention window.
     *
     * Batched so a large backlog cannot exhaust max_execution_time.
     */
    public static function prune() {
        global $wpdb;

        try {
            $days   = absint(ifls_diag_setting('retention_days'));
            $cutoff = gmdate('Y-m-d H:i:s', time() - ($days * DAY_IN_SECONDS));

            do {
                $deleted = $wpdb->query(
                    $wpdb->prepare(
                        'DELETE FROM ' . self::table() . ' WHERE created_at < %s LIMIT 1000',
                        $cutoff
                    )
                );
            } while ($deleted > 0);
        } catch (\Throwable $e) {
            // Pruning retries on the next cron run.
        }
    }

    /**
     * Remove every row. Used by the admin "clear log" control and by tests.
     */
    public static function clear() {
        global $wpdb;

        try {
            $wpdb->query('TRUNCATE TABLE ' . self::table());
        } catch (\Throwable $e) {
            // no-op
        }
    }
}
