<?php
/**
 * Diagnostics admin screen.
 *
 * Four panels: incidents, mail diagnostics, the event log, and settings.
 *
 * Everything rendered from the event log is attacker-controlled - usernames
 * and user agents arrive straight from failed login attempts - so every field
 * is escaped at the point of output without exception.
 *
 * @package Inkfire_Login_Styler
 */

if (!defined('ABSPATH')) {
    exit;
}

class IFLS_Diagnostics_Admin {

    const PAGE_SLUG = 'foundation-login-diagnostics';
    const CAPABILITY = 'manage_options';

    /**
     * Hook everything up.
     */
    public static function init() {
        add_action('admin_menu', [__CLASS__, 'register_menu'], 25);
        add_action('admin_init', [__CLASS__, 'register_settings']);
        add_action('admin_post_ifls_test_email', [__CLASS__, 'handle_test_email']);
        add_action('admin_post_ifls_clear_log', [__CLASS__, 'handle_clear_log']);
        add_action('admin_post_ifls_locate_ip', [__CLASS__, 'handle_locate_ip']);
    }

    /**
     * Add the Diagnostics subpage under the shared Foundation menu.
     */
    public static function register_menu() {
        add_submenu_page(
            'foundation-by-inkfire',
            __('Login Diagnostics', 'inkfire-login-styler'),
            __('Login Diagnostics', 'inkfire-login-styler'),
            self::CAPABILITY,
            self::PAGE_SLUG,
            [__CLASS__, 'render']
        );
    }

    /**
     * Register the settings group with its sanitiser.
     */
    public static function register_settings() {
        register_setting(
            'ifls_diagnostics',
            'ifls_diagnostics_settings',
            [
                'type'              => 'array',
                'sanitize_callback' => 'ifls_diag_sanitize',
                'default'           => ifls_diag_defaults(),
            ]
        );
    }

    /* ----------------------------------------------------------------------
       Handlers
       ---------------------------------------------------------------------- */

    /**
     * Send a diagnostic test email.
     *
     * The recipient is resolved from settings or the current user and is NEVER
     * read from the request, or this button would be an open relay.
     */
    public static function handle_test_email() {
        if (!current_user_can(self::CAPABILITY)) {
            wp_die(esc_html__('You do not have permission to do that.', 'inkfire-login-styler'));
        }

        check_admin_referer('ifls_test_email');

        $recipient = ifls_diag_setting('report_email');
        if (!is_email($recipient)) {
            $user      = wp_get_current_user();
            $recipient = $user ? $user->user_email : get_option('admin_email');
        }

        $result = IFLS_Mail_Diagnostics::send_test($recipient);

        set_transient('ifls_test_result_' . get_current_user_id(), $result, 5 * MINUTE_IN_SECONDS);

        wp_safe_redirect(self::page_url(['ifls_tested' => 1]));
        exit;
    }

    /**
     * Erase the event log. Exists so a client can satisfy an erasure request.
     */
    public static function handle_clear_log() {
        if (!current_user_can(self::CAPABILITY)) {
            wp_die(esc_html__('You do not have permission to do that.', 'inkfire-login-styler'));
        }

        check_admin_referer('ifls_clear_log');

        IFLS_Event_Log::clear();

        wp_safe_redirect(self::page_url(['ifls_cleared' => 1]));
        exit;
    }

    /**
     * Resolve one IP address to a location, on explicit admin request only.
     */
    public static function handle_locate_ip() {
        if (!current_user_can(self::CAPABILITY)) {
            wp_die(esc_html__('You do not have permission to do that.', 'inkfire-login-styler'));
        }

        check_admin_referer('ifls_locate_ip');

        $ip = isset($_REQUEST['ip']) ? sanitize_text_field(wp_unslash($_REQUEST['ip'])) : '';
        self::locate_ip($ip);

        wp_safe_redirect(self::page_url(['ifls_located' => rawurlencode($ip)]));
        exit;
    }

    /* ----------------------------------------------------------------------
       Geolocation (on demand only)
       ---------------------------------------------------------------------- */

    /**
     * Resolve an IP to a human-readable location.
     *
     * Deliberately NOT called during authentication. Running this on every
     * login would put a third-party HTTP call on the login path and would
     * systematically disclose end-user IP addresses to another company.
     * It runs only when an administrator clicks "locate" on a specific row,
     * and the result is cached so a second click costs nothing.
     *
     * @param string $ip IP address.
     * @return string Location description, or '' if unavailable.
     */
    public static function locate_ip($ip) {
        $ip = trim((string) $ip);

        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return '';
        }

        $key    = 'ifls_geo_' . md5($ip);
        $cached = get_transient($key);

        if (false !== $cached) {
            return is_string($cached) ? $cached : '';
        }

        $parts = [];

        // Reverse DNS first: free, no third party involved, and often enough
        // to tell an office connection from an unexpected country.
        $host = @gethostbyaddr($ip);
        if ($host && $host !== $ip) {
            $parts[] = $host;
        }

        /**
         * Filter the geolocation endpoint.
         *
         * %s is replaced with the IP address. Return an empty string to
         * disable third-party geolocation entirely and rely on reverse DNS.
         *
         * @param string $endpoint Endpoint URL template.
         */
        $endpoint = apply_filters('ifls_geoip_endpoint', 'https://ipwho.is/%s');

        if ($endpoint) {
            $response = wp_remote_get(
                sprintf($endpoint, rawurlencode($ip)),
                ['timeout' => 5, 'redirection' => 2]
            );

            if (!is_wp_error($response) && 200 === wp_remote_retrieve_response_code($response)) {
                $data = json_decode(wp_remote_retrieve_body($response), true);

                if (is_array($data) && !empty($data['success'])) {
                    $bits = array_filter([
                        isset($data['city']) ? $data['city'] : '',
                        isset($data['region']) ? $data['region'] : '',
                        isset($data['country']) ? $data['country'] : '',
                    ]);
                    if ($bits) {
                        array_unshift($parts, implode(', ', $bits));
                    }
                }
            }
        }

        $location = implode(' - ', $parts);

        // Cache negatives too, so a failing lookup is not retried on every click.
        set_transient($key, $location, DAY_IN_SECONDS);

        return $location;
    }

    /* ----------------------------------------------------------------------
       Rendering
       ---------------------------------------------------------------------- */

    /**
     * @param array $args Extra query args.
     * @return string
     */
    private static function page_url(array $args = []) {
        return add_query_arg(
            array_merge(['page' => self::PAGE_SLUG], $args),
            admin_url('admin.php')
        );
    }

    /**
     * One event-log table row. Every field escaped.
     *
     * @param object $row Row from IFLS_Event_Log::query().
     * @return string
     */
    public static function render_log_row($row) {
        $located = get_transient('ifls_geo_' . md5((string) $row->ip));

        $locate_link = '';
        if ($row->ip) {
            if (is_string($located) && '' !== $located) {
                $locate_link = '<br><small>' . esc_html($located) . '</small>';
            } else {
                $locate_link = '<br><a href="' . esc_url(
                    wp_nonce_url(
                        admin_url('admin-post.php?action=ifls_locate_ip&ip=' . rawurlencode($row->ip)),
                        'ifls_locate_ip'
                    )
                ) . '">' . esc_html__('Locate', 'inkfire-login-styler') . '</a>';
            }
        }

        return sprintf(
            '<tr><td>%s</td><td><code>%s</code></td><td>%s</td><td>%s%s</td><td>%s</td><td><span title="%s">%s</span></td></tr>',
            esc_html(get_date_from_gmt($row->created_at)),
            esc_html($row->event),
            esc_html('' !== $row->username ? $row->username : '-'),
            esc_html('' !== $row->ip ? $row->ip : '-'),
            $locate_link,
            esc_html($row->outcome),
            esc_attr((string) $row->user_agent),
            esc_html(mb_substr((string) $row->user_agent, 0, 40))
        );
    }

    /**
     * One incident row. Every field escaped.
     *
     * @param array $incident Incident record.
     * @return string
     */
    public static function render_incident_row(array $incident) {
        $status = isset($incident['status']) ? $incident['status'] : 'pending';

        $label = 'sent' === $status
            ? __('Reported', 'inkfire-login-styler')
            : ('failed' === $status ? __('NOT DELIVERED', 'inkfire-login-styler') : __('Queued', 'inkfire-login-styler'));

        return sprintf(
            '<tr%s><td><strong>%s</strong></td><td>%s</td><td>%d</td><td>%s</td><td>%s</td></tr>',
            'failed' === $status ? ' style="background:#fcf0f1"' : '',
            esc_html(str_replace('_', ' ', $incident['type'])),
            esc_html($incident['reason']),
            (int) $incident['count'],
            esc_html(get_date_from_gmt(gmdate('Y-m-d H:i:s', (int) $incident['last_seen']))),
            esc_html($label)
        );
    }

    /**
     * Render the whole screen.
     */
    public static function render() {
        if (!current_user_can(self::CAPABILITY)) {
            wp_die(esc_html__('You do not have permission to access this page.', 'inkfire-login-styler'));
        }

        $incidents = IFLS_Incident_Reporter::incidents();
        $test      = get_transient('ifls_test_result_' . get_current_user_id());
        $dns       = IFLS_Mail_Diagnostics::dns_info();
        $transport = IFLS_Mail_Diagnostics::transport_info();
        $warnings  = IFLS_Mail_Diagnostics::warnings(
            is_array($test) && !empty($test['transport']) ? $test['transport'] : ['mailer' => 'mail', 'sender' => ''],
            $dns
        );

        $filter_event = isset($_GET['ifls_event']) ? sanitize_key(wp_unslash($_GET['ifls_event'])) : '';
        $search       = isset($_GET['ifls_search']) ? sanitize_text_field(wp_unslash($_GET['ifls_search'])) : '';

        $rows = IFLS_Event_Log::query([
            'event'  => $filter_event,
            'search' => $search,
            'limit'  => 100,
        ]);
        ?>
        <div class="wrap">
            <h1><?php esc_html_e('Login Diagnostics', 'inkfire-login-styler'); ?></h1>

            <?php if (!ifls_diag_enabled()) : ?>
                <div class="notice notice-warning"><p>
                    <?php esc_html_e('Diagnostics are disabled by the IFLS_DISABLE_DIAGNOSTICS constant in wp-config.php.', 'inkfire-login-styler'); ?>
                </p></div>
            <?php endif; ?>

            <?php if (isset($_GET['ifls_cleared'])) : ?>
                <div class="notice notice-success is-dismissible"><p><?php esc_html_e('Event log cleared.', 'inkfire-login-styler'); ?></p></div>
            <?php endif; ?>

            <h2><?php esc_html_e('Incidents', 'inkfire-login-styler'); ?></h2>
            <p class="description">
                <?php esc_html_e('Raised automatically when this plugin malfunctions. A copy of every incident is kept here even when the alert email could not be delivered.', 'inkfire-login-styler'); ?>
            </p>
            <?php if (empty($incidents)) : ?>
                <p><em><?php esc_html_e('No incidents recorded. This is the healthy state.', 'inkfire-login-styler'); ?></em></p>
            <?php else : ?>
                <table class="widefat striped">
                    <thead><tr>
                        <th><?php esc_html_e('Incident', 'inkfire-login-styler'); ?></th>
                        <th><?php esc_html_e('Reason', 'inkfire-login-styler'); ?></th>
                        <th><?php esc_html_e('Count', 'inkfire-login-styler'); ?></th>
                        <th><?php esc_html_e('Last seen', 'inkfire-login-styler'); ?></th>
                        <th><?php esc_html_e('Status', 'inkfire-login-styler'); ?></th>
                    </tr></thead>
                    <tbody>
                    <?php
                    // Undelivered first - those are the ones nobody has been told about.
                    usort($incidents, function ($a, $b) {
                        $rank = function ($i) {
                            return (isset($i['status']) && 'failed' === $i['status']) ? 0 : 1;
                        };
                        return $rank($a) - $rank($b);
                    });
                    foreach ($incidents as $incident) {
                        echo self::render_incident_row($incident); // phpcs:ignore WordPress.Security.EscapeOutput -- escaped in render_incident_row().
                    }
                    ?>
                    </tbody>
                </table>
            <?php endif; ?>

            <h2><?php esc_html_e('Mail diagnostics', 'inkfire-login-styler'); ?></h2>

            <?php foreach ($warnings as $warning) : ?>
                <div class="notice notice-warning inline"><p><?php echo esc_html($warning); ?></p></div>
            <?php endforeach; ?>

            <?php if (is_array($test)) : ?>
                <div class="notice notice-<?php echo $test['sent'] ? 'success' : 'error'; ?> inline">
                    <p>
                        <?php if ($test['sent']) : ?>
                            <?php
                            printf(
                                /* translators: %s: recipient address. */
                                esc_html__('Test message handed to the mail transport for %s. If it does not arrive, the problem is after this server.', 'inkfire-login-styler'),
                                esc_html($test['to'])
                            );
                            ?>
                        <?php else : ?>
                            <?php esc_html_e('The mail transport refused the message.', 'inkfire-login-styler'); ?>
                            <?php echo $test['error'] ? esc_html(' ' . $test['error']) : ''; ?>
                        <?php endif; ?>
                    </p>
                </div>
            <?php endif; ?>

            <table class="widefat striped" style="max-width:900px">
                <tbody>
                    <tr><td><?php esc_html_e('Sendmail path', 'inkfire-login-styler'); ?></td><td><code><?php echo esc_html($transport['sendmail_path'] ?: '(none)'); ?></code></td></tr>
                    <tr><td><?php esc_html_e('From address', 'inkfire-login-styler'); ?></td><td><code><?php echo esc_html($transport['wp_mail_from']); ?></code></td></tr>
                    <?php if (is_array($test) && !empty($test['transport'])) : ?>
                        <tr><td><?php esc_html_e('Mailer', 'inkfire-login-styler'); ?></td><td><code><?php echo esc_html($test['transport']['mailer']); ?></code></td></tr>
                        <tr><td><?php esc_html_e('Envelope sender (Return-Path)', 'inkfire-login-styler'); ?></td><td><code><?php echo esc_html($test['transport']['sender'] ?: '(not set)'); ?></code></td></tr>
                        <tr><td><?php esc_html_e('SMTP authentication', 'inkfire-login-styler'); ?></td><td><?php echo $test['transport']['smtp_auth'] ? esc_html__('yes', 'inkfire-login-styler') : esc_html__('no', 'inkfire-login-styler'); ?></td></tr>
                    <?php endif; ?>
                    <tr><td>MX</td><td><code><?php echo esc_html($dns['mx'] ? implode(', ', $dns['mx']) : ($dns['available'] ? '(none)' : '(unavailable)')); ?></code></td></tr>
                    <tr><td>SPF</td><td><code><?php echo esc_html($dns['spf'] ?: '(none)'); ?></code></td></tr>
                    <tr><td>DMARC</td><td><code><?php echo esc_html($dns['dmarc'] ?: '(none)'); ?></code></td></tr>
                </tbody>
            </table>

            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="margin-top:12px">
                <?php wp_nonce_field('ifls_test_email'); ?>
                <input type="hidden" name="action" value="ifls_test_email">
                <?php submit_button(__('Send test email', 'inkfire-login-styler'), 'secondary', 'submit', false); ?>
                <span class="description">
                    <?php
                    printf(
                        /* translators: %s: recipient address. */
                        esc_html__('Sends to %s.', 'inkfire-login-styler'),
                        esc_html(ifls_diag_setting('report_email'))
                    );
                    ?>
                </span>
            </form>

            <h2><?php esc_html_e('Event log', 'inkfire-login-styler'); ?></h2>
            <p class="description">
                <?php
                printf(
                    /* translators: %d: retention period in days. */
                    esc_html__('Authentication activity on this site. Kept for %d days, then deleted automatically. This data never leaves this site.', 'inkfire-login-styler'),
                    (int) ifls_diag_setting('retention_days')
                );
                ?>
            </p>

            <form method="get" style="margin-bottom:10px">
                <input type="hidden" name="page" value="<?php echo esc_attr(self::PAGE_SLUG); ?>">
                <select name="ifls_event">
                    <option value=""><?php esc_html_e('All events', 'inkfire-login-styler'); ?></option>
                    <?php foreach (IFLS_Event_Log::EVENTS as $event) : ?>
                        <option value="<?php echo esc_attr($event); ?>" <?php selected($filter_event, $event); ?>><?php echo esc_html($event); ?></option>
                    <?php endforeach; ?>
                </select>
                <input type="search" name="ifls_search" value="<?php echo esc_attr($search); ?>" placeholder="<?php esc_attr_e('user or IP', 'inkfire-login-styler'); ?>">
                <?php submit_button(__('Filter', 'inkfire-login-styler'), 'secondary', '', false); ?>
            </form>

            <table class="widefat striped">
                <thead><tr>
                    <th><?php esc_html_e('When', 'inkfire-login-styler'); ?></th>
                    <th><?php esc_html_e('Event', 'inkfire-login-styler'); ?></th>
                    <th><?php esc_html_e('User', 'inkfire-login-styler'); ?></th>
                    <th><?php esc_html_e('IP', 'inkfire-login-styler'); ?></th>
                    <th><?php esc_html_e('Outcome', 'inkfire-login-styler'); ?></th>
                    <th><?php esc_html_e('Agent', 'inkfire-login-styler'); ?></th>
                </tr></thead>
                <tbody>
                <?php if (empty($rows)) : ?>
                    <tr><td colspan="6"><em><?php esc_html_e('No events recorded yet.', 'inkfire-login-styler'); ?></em></td></tr>
                <?php else : ?>
                    <?php foreach ($rows as $row) : ?>
                        <?php echo self::render_log_row($row); // phpcs:ignore WordPress.Security.EscapeOutput -- escaped in render_log_row(). ?>
                    <?php endforeach; ?>
                <?php endif; ?>
                </tbody>
            </table>

            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="margin-top:12px"
                  onsubmit="return confirm('<?php echo esc_js(__('Permanently delete all logged events?', 'inkfire-login-styler')); ?>');">
                <?php wp_nonce_field('ifls_clear_log'); ?>
                <input type="hidden" name="action" value="ifls_clear_log">
                <?php submit_button(__('Clear event log', 'inkfire-login-styler'), 'delete', 'submit', false); ?>
            </form>

            <h2><?php esc_html_e('Settings', 'inkfire-login-styler'); ?></h2>
            <form method="post" action="options.php">
                <?php settings_fields('ifls_diagnostics'); ?>
                <table class="form-table" role="presentation">
                    <?php
                    $fields = [
                        'logging_enabled'   => [__('Log authentication events', 'inkfire-login-styler'), 'checkbox'],
                        'retention_days'    => [__('Keep events for (days)', 'inkfire-login-styler'), 'number'],
                        'reporting_enabled' => [__('Report incidents to Inkfire', 'inkfire-login-styler'), 'checkbox'],
                        'report_email'      => [__('Report recipient', 'inkfire-login-styler'), 'email'],
                        'threshold_count'   => [__('Failures before alerting', 'inkfire-login-styler'), 'number'],
                        'threshold_minutes' => [__('Within (minutes)', 'inkfire-login-styler'), 'number'],
                        'cooldown_hours'    => [__('Do not repeat an alert for (hours)', 'inkfire-login-styler'), 'number'],
                    ];

                    foreach ($fields as $key => $field) :
                        list($label, $type) = $field;
                        $value  = ifls_diag_setting($key);
                        $locked = ifls_diag_is_locked($key);
                        ?>
                        <tr>
                            <th scope="row"><label for="ifls-<?php echo esc_attr($key); ?>"><?php echo esc_html($label); ?></label></th>
                            <td>
                                <?php if ('checkbox' === $type) : ?>
                                    <input type="checkbox" id="ifls-<?php echo esc_attr($key); ?>"
                                           name="ifls_diagnostics_settings[<?php echo esc_attr($key); ?>]"
                                           value="1" <?php checked((bool) $value); ?> <?php disabled($locked); ?>>
                                <?php else : ?>
                                    <input type="<?php echo esc_attr($type); ?>" id="ifls-<?php echo esc_attr($key); ?>"
                                           name="ifls_diagnostics_settings[<?php echo esc_attr($key); ?>]"
                                           value="<?php echo esc_attr((string) $value); ?>"
                                           class="regular-text" <?php disabled($locked); ?>>
                                <?php endif; ?>
                                <?php if ($locked) : ?>
                                    <p class="description"><?php esc_html_e('Pinned by a constant in wp-config.php and cannot be changed here.', 'inkfire-login-styler'); ?></p>
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </table>
                <?php submit_button(); ?>
            </form>
        </div>
        <?php
    }
}
