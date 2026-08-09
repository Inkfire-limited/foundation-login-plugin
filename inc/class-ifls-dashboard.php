<?php
/**
 * Operational dashboard for Foundation - Inkfire Login.
 *
 * Turns the former read-only admin shell into a working operations surface:
 * authentication activity, failed-login management, health checks, incidents,
 * mail testing and a downloadable privacy-safe debug report.
 *
 * @package Inkfire_Login_Styler
 */

if (!defined('ABSPATH')) {
    exit;
}

class IFLS_Dashboard {
    const PAGE_SLUG  = 'foundation-login-styler';
    const PARENT_SLUG = 'foundation-by-inkfire';
    const CAPABILITY = 'manage_options';

    public static function init() {
        add_action('admin_menu', [__CLASS__, 'register_menu'], 20);
        add_action('admin_enqueue_scripts', [__CLASS__, 'enqueue_assets']);
        add_action('admin_post_ifls_reset_login_attempts', [__CLASS__, 'handle_reset_attempts']);
        add_action('admin_post_ifls_dashboard_test_email', [__CLASS__, 'handle_test_email']);
        add_action('admin_post_ifls_download_debug_report', [__CLASS__, 'handle_debug_report']);
    }

    public static function register_menu() {
        global $admin_page_hooks;

        if (empty($admin_page_hooks[self::PARENT_SLUG])) {
            add_menu_page(
                __('Foundation', 'inkfire-login-styler'),
                __('Foundation', 'inkfire-login-styler'),
                self::CAPABILITY,
                self::PARENT_SLUG,
                [__CLASS__, 'render'],
                'dashicons-hammer',
                30
            );
        }

        add_submenu_page(
            self::PARENT_SLUG,
            __('Inkfire Login', 'inkfire-login-styler'),
            __('Inkfire Login', 'inkfire-login-styler'),
            self::CAPABILITY,
            self::PAGE_SLUG,
            [__CLASS__, 'render']
        );

        remove_submenu_page(self::PARENT_SLUG, self::PARENT_SLUG);
    }

    public static function enqueue_assets($hook) {
        $hook = (string) $hook;
        $is_dashboard = false !== strpos($hook, self::PAGE_SLUG);
        $is_diagnostics = false !== strpos($hook, IFLS_Diagnostics_Admin::PAGE_SLUG);

        if (!$is_dashboard && !$is_diagnostics) {
            return;
        }

        $asset_base = plugin_dir_url(dirname(__DIR__) . '/inkfire-login-styler.php') . 'assets/admin/';
        wp_enqueue_style('foundation-admin-shell', $asset_base . 'foundation-admin-shell.css', [], IFLS_VERSION);

        if (!$is_dashboard) {
            return;
        }

        wp_enqueue_script('foundation-admin-shell', $asset_base . 'foundation-admin-shell.js', ['wp-element'], IFLS_VERSION, true);
        wp_add_inline_script(
            'foundation-admin-shell',
            'window.foundationAdminShellData = ' . wp_json_encode(self::config()) . ';',
            'before'
        );
    }

    private static function page_url($fragment = '') {
        $url = admin_url('admin.php?page=' . self::PAGE_SLUG);
        return $fragment ? $url . '#' . ltrim($fragment, '#') : $url;
    }

    private static function diagnostics_url(array $args = [], $fragment = '') {
        $url = add_query_arg(array_merge(['page' => IFLS_Diagnostics_Admin::PAGE_SLUG], $args), admin_url('admin.php'));
        return $fragment ? $url . '#' . ltrim($fragment, '#') : $url;
    }

    private static function debug_report_url() {
        return wp_nonce_url(
            admin_url('admin-post.php?action=ifls_download_debug_report'),
            'ifls_download_debug_report'
        );
    }

    private static function count_problem_incidents(array $incidents) {
        $count = 0;
        foreach ($incidents as $incident) {
            $status = isset($incident['status']) ? $incident['status'] : 'pending';
            if ('sent' !== $status) {
                $count++;
            }
        }
        return $count;
    }

    private static function snapshot() {
        $incidents = IFLS_Incident_Reporter::incidents();
        return [
            'login_24h'    => IFLS_Event_Log::count_since('login_success', 1440),
            'failed_24h'   => IFLS_Event_Log::count_since('login_failed', 1440),
            'lockout_24h'  => IFLS_Event_Log::count_since('lockout', 1440),
            'reset_fail_24h' => IFLS_Event_Log::count_since('reset_failed', 1440),
            'problems'     => self::count_problem_incidents($incidents),
            'incidents'    => $incidents,
        ];
    }

    private static function config() {
        $snapshot = self::snapshot();
        $problem_meta = $snapshot['problems']
            ? sprintf(_n('%d incident needs attention.', '%d incidents need attention.', $snapshot['problems'], 'inkfire-login-styler'), $snapshot['problems'])
            : __('No undelivered incidents.', 'inkfire-login-styler');

        return [
            'plugin' => 'login-styler',
            'rootId' => 'foundation-admin-app',
            'eyebrow' => __('Foundation command centre', 'inkfire-login-styler'),
            'title' => __('Foundation: Inkfire Login', 'inkfire-login-styler'),
            'description' => __('Live authentication operations, failed-login management and diagnostics for this WordPress site.', 'inkfire-login-styler'),
            'badge' => 'v' . IFLS_VERSION,
            'themeStorageKey' => 'foundation-login-styler-theme',
            'actions' => [
                [
                    'label' => __('Preview login page', 'inkfire-login-styler'),
                    'href' => add_query_arg('reauth', '1', wp_login_url()),
                    'target' => '_blank',
                    'variant' => 'solid',
                ],
                [
                    'label' => __('Review failed logins', 'inkfire-login-styler'),
                    'href' => self::page_url('ifls-failed-logins'),
                    'variant' => 'ghost',
                ],
                [
                    'label' => __('Download debug report', 'inkfire-login-styler'),
                    'href' => self::debug_report_url(),
                    'variant' => 'ghost',
                ],
            ],
            'metrics' => [
                [
                    'label' => __('Successful logins · 24h', 'inkfire-login-styler'),
                    'value' => (string) $snapshot['login_24h'],
                    'meta' => __('Recorded locally on this site.', 'inkfire-login-styler'),
                ],
                [
                    'label' => __('Failed logins · 24h', 'inkfire-login-styler'),
                    'value' => (string) $snapshot['failed_24h'],
                    'meta' => sprintf(__('%d attempts trigger a %d minute lockout.', 'inkfire-login-styler'), IFLS_MAX_LOGIN_ATTEMPTS, (int) (IFLS_LOCKOUT_TIME / 60)),
                    'tone' => $snapshot['failed_24h'] ? 'danger' : '',
                ],
                [
                    'label' => __('Lockouts · 24h', 'inkfire-login-styler'),
                    'value' => (string) $snapshot['lockout_24h'],
                    'meta' => __('Blocked attempts recorded after the threshold is reached.', 'inkfire-login-styler'),
                    'tone' => $snapshot['lockout_24h'] ? 'danger' : 'accent',
                ],
                [
                    'label' => __('Incident status', 'inkfire-login-styler'),
                    'value' => $snapshot['problems'] ? __('Attention', 'inkfire-login-styler') : __('Healthy', 'inkfire-login-styler'),
                    'meta' => $problem_meta,
                    'tone' => $snapshot['problems'] ? 'danger' : 'accent',
                ],
            ],
            'sections' => [
                [
                    'id' => 'ifls-overview',
                    'navLabel' => __('Overview', 'inkfire-login-styler'),
                    'eyebrow' => __('Operations', 'inkfire-login-styler'),
                    'title' => __('Login health at a glance', 'inkfire-login-styler'),
                    'description' => __('The controls below are live. They query this site’s own authentication log and diagnostics state.', 'inkfire-login-styler'),
                    'templateId' => 'foundation-login-overview',
                ],
                [
                    'id' => 'ifls-failed-logins',
                    'navLabel' => __('Failed logins', 'inkfire-login-styler'),
                    'eyebrow' => __('Security', 'inkfire-login-styler'),
                    'title' => __('Failed login management', 'inkfire-login-styler'),
                    'description' => __('Review recent failures, inspect their source and reset a username/IP attempt counter when a legitimate user has been locked out.', 'inkfire-login-styler'),
                    'templateId' => 'foundation-login-failures',
                ],
                [
                    'id' => 'ifls-activity',
                    'navLabel' => __('Activity', 'inkfire-login-styler'),
                    'eyebrow' => __('Audit trail', 'inkfire-login-styler'),
                    'title' => __('Who is logging in and out', 'inkfire-login-styler'),
                    'description' => __('Recent successful logins, logouts, password resets, blocks and registrations.', 'inkfire-login-styler'),
                    'templateId' => 'foundation-login-activity',
                ],
                [
                    'id' => 'ifls-health-debug',
                    'navLabel' => __('Health & debug', 'inkfire-login-styler'),
                    'eyebrow' => __('Diagnostics', 'inkfire-login-styler'),
                    'title' => __('Health, mail and support report', 'inkfire-login-styler'),
                    'description' => __('Check the diagnostics pipeline, send a real mail test and download a privacy-safe support report.', 'inkfire-login-styler'),
                    'templateId' => 'foundation-login-health',
                ],
            ],
        ];
    }

    private static function event_label($event) {
        $labels = [
            'login_success' => __('Login', 'inkfire-login-styler'),
            'login_failed' => __('Failed login', 'inkfire-login-styler'),
            'logout' => __('Logout', 'inkfire-login-styler'),
            'lockout' => __('Lockout', 'inkfire-login-styler'),
            'reset_requested' => __('Reset requested', 'inkfire-login-styler'),
            'reset_completed' => __('Reset completed', 'inkfire-login-styler'),
            'reset_failed' => __('Reset failed', 'inkfire-login-styler'),
            'csrf_blocked' => __('Security block', 'inkfire-login-styler'),
            'registration' => __('Registration', 'inkfire-login-styler'),
        ];
        return isset($labels[$event]) ? $labels[$event] : str_replace('_', ' ', (string) $event);
    }

    private static function event_tone($event, $outcome = '') {
        if ('success' === $outcome || in_array($event, ['login_success', 'logout', 'reset_completed', 'registration'], true)) {
            return 'success';
        }
        if (in_array($event, ['lockout', 'csrf_blocked'], true) || 'blocked' === $outcome) {
            return 'blocked';
        }
        if ('failure' === $outcome || in_array($event, ['login_failed', 'reset_failed'], true)) {
            return 'danger';
        }
        return 'neutral';
    }

    private static function format_when($gmt) {
        if (!$gmt) {
            return __('Unknown', 'inkfire-login-styler');
        }
        return get_date_from_gmt((string) $gmt, 'j M Y · H:i');
    }

    private static function current_attempts($username, $ip) {
        return IFLS_Enterprise_Security::get_instance()->get_attempts_for((string) $username, (string) $ip);
    }

    private static function recent_failures() {
        $rows = IFLS_Event_Log::query(['limit' => 200]);
        $groups = [];

        foreach ($rows as $row) {
            if (!in_array($row->event, ['login_failed', 'lockout'], true)) {
                continue;
            }
            $key = sha1((string) $row->username . '|' . (string) $row->ip);
            if (!isset($groups[$key])) {
                $groups[$key] = [
                    'username' => (string) $row->username,
                    'ip' => (string) $row->ip,
                    'last_seen' => (string) $row->created_at,
                    'events' => 0,
                    'last_event' => (string) $row->event,
                ];
            }
            $groups[$key]['events']++;
        }

        return array_slice(array_values($groups), 0, 12);
    }

    private static function render_overview() {
        global $wpdb;
        $snapshot = self::snapshot();
        $last = IFLS_Event_Log::query(['limit' => 1]);
        $table = IFLS_Event_Log::table();
        $table_exists = ($table === $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $table)));
        $next_dispatch = wp_next_scheduled('ifls_dispatch_incidents');
        $next_prune = wp_next_scheduled('ifls_prune_events');
        ?>
        <div class="ifls-dashboard-grid">
            <article class="ifls-ops-card">
                <h3><?php esc_html_e('Authentication logging', 'inkfire-login-styler'); ?></h3>
                <p class="ifls-big-status <?php echo ifls_diag_setting('logging_enabled') && $table_exists ? 'is-ok' : 'is-warn'; ?>">
                    <?php echo ifls_diag_setting('logging_enabled') && $table_exists ? esc_html__('Recording', 'inkfire-login-styler') : esc_html__('Needs attention', 'inkfire-login-styler'); ?>
                </p>
                <p><?php echo $table_exists ? esc_html__('The local event table is available.', 'inkfire-login-styler') : esc_html__('The authentication event table was not found.', 'inkfire-login-styler'); ?></p>
            </article>
            <article class="ifls-ops-card">
                <h3><?php esc_html_e('Latest activity', 'inkfire-login-styler'); ?></h3>
                <p class="ifls-big-status"><?php echo !empty($last) ? esc_html(self::event_label($last[0]->event)) : esc_html__('No events yet', 'inkfire-login-styler'); ?></p>
                <p><?php echo !empty($last) ? esc_html(self::format_when($last[0]->created_at)) : esc_html__('The log will populate as users authenticate.', 'inkfire-login-styler'); ?></p>
            </article>
            <article class="ifls-ops-card">
                <h3><?php esc_html_e('Incident reporting', 'inkfire-login-styler'); ?></h3>
                <p class="ifls-big-status <?php echo $snapshot['problems'] ? 'is-warn' : 'is-ok'; ?>"><?php echo $snapshot['problems'] ? esc_html__('Attention', 'inkfire-login-styler') : esc_html__('Healthy', 'inkfire-login-styler'); ?></p>
                <p><?php printf(esc_html__('%d stored incident(s), %d currently undelivered.', 'inkfire-login-styler'), count($snapshot['incidents']), $snapshot['problems']); ?></p>
            </article>
            <article class="ifls-ops-card">
                <h3><?php esc_html_e('Scheduled diagnostics', 'inkfire-login-styler'); ?></h3>
                <p class="ifls-big-status <?php echo ($next_dispatch && $next_prune) ? 'is-ok' : 'is-warn'; ?>"><?php echo ($next_dispatch && $next_prune) ? esc_html__('Scheduled', 'inkfire-login-styler') : esc_html__('Check cron', 'inkfire-login-styler'); ?></p>
                <p><?php esc_html_e('Incident dispatch runs every five minutes; pruning runs daily.', 'inkfire-login-styler'); ?></p>
            </article>
        </div>
        <div class="ifls-quick-actions" aria-label="<?php esc_attr_e('Quick actions', 'inkfire-login-styler'); ?>">
            <a class="button button-primary" href="<?php echo esc_url(self::page_url('ifls-failed-logins')); ?>"><?php esc_html_e('Review failed logins', 'inkfire-login-styler'); ?></a>
            <a class="button" href="<?php echo esc_url(self::page_url('ifls-activity')); ?>"><?php esc_html_e('View login activity', 'inkfire-login-styler'); ?></a>
            <a class="button" href="<?php echo esc_url(self::diagnostics_url()); ?>"><?php esc_html_e('Open full diagnostics', 'inkfire-login-styler'); ?></a>
            <a class="button" href="<?php echo esc_url(self::debug_report_url()); ?>"><?php esc_html_e('Download debug report', 'inkfire-login-styler'); ?></a>
        </div>
        <?php
    }

    private static function render_failures() {
        $groups = self::recent_failures();
        ?>
        <div class="ifls-table-wrap">
            <table class="widefat striped ifls-dashboard-table">
                <caption class="screen-reader-text"><?php esc_html_e('Recent failed login attempts grouped by username and IP address.', 'inkfire-login-styler'); ?></caption>
                <thead><tr>
                    <th><?php esc_html_e('User / attempted username', 'inkfire-login-styler'); ?></th>
                    <th><?php esc_html_e('IP address', 'inkfire-login-styler'); ?></th>
                    <th><?php esc_html_e('Recent events', 'inkfire-login-styler'); ?></th>
                    <th><?php esc_html_e('Current counter', 'inkfire-login-styler'); ?></th>
                    <th><?php esc_html_e('Last seen', 'inkfire-login-styler'); ?></th>
                    <th><?php esc_html_e('Actions', 'inkfire-login-styler'); ?></th>
                </tr></thead>
                <tbody>
                <?php if (!$groups) : ?>
                    <tr><td colspan="6"><em><?php esc_html_e('No failed login activity has been recorded yet.', 'inkfire-login-styler'); ?></em></td></tr>
                <?php else : foreach ($groups as $group) :
                    $attempts = self::current_attempts($group['username'], $group['ip']);
                    $is_locked = $attempts >= IFLS_MAX_LOGIN_ATTEMPTS;
                    $locate_url = wp_nonce_url(
                        admin_url('admin-post.php?action=ifls_locate_ip&ip=' . rawurlencode($group['ip'])),
                        'ifls_locate_ip'
                    );
                    ?>
                    <tr>
                        <td><strong><?php echo esc_html($group['username'] ?: '-'); ?></strong></td>
                        <td><code><?php echo esc_html($group['ip'] ?: '-'); ?></code></td>
                        <td><?php echo (int) $group['events']; ?></td>
                        <td><span class="ifls-event-chip is-<?php echo $is_locked ? 'danger' : ($attempts ? 'blocked' : 'neutral'); ?>"><?php echo $is_locked ? esc_html__('Locked', 'inkfire-login-styler') : esc_html(sprintf('%d / %d', $attempts, IFLS_MAX_LOGIN_ATTEMPTS)); ?></span></td>
                        <td><?php echo esc_html(self::format_when($group['last_seen'])); ?></td>
                        <td>
                            <div class="ifls-inline-actions">
                                <?php if ($group['ip']) : ?><a class="button button-small" href="<?php echo esc_url($locate_url); ?>"><?php esc_html_e('Locate', 'inkfire-login-styler'); ?></a><?php endif; ?>
                                <?php if ($attempts > 0 && $group['username'] && $group['ip']) : ?>
                                    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                                        <?php wp_nonce_field('ifls_reset_login_attempts'); ?>
                                        <input type="hidden" name="action" value="ifls_reset_login_attempts">
                                        <input type="hidden" name="username" value="<?php echo esc_attr($group['username']); ?>">
                                        <input type="hidden" name="ip" value="<?php echo esc_attr($group['ip']); ?>">
                                        <button type="submit" class="button button-small"><?php esc_html_e('Reset attempts', 'inkfire-login-styler'); ?></button>
                                    </form>
                                <?php endif; ?>
                            </div>
                        </td>
                    </tr>
                <?php endforeach; endif; ?>
                </tbody>
            </table>
        </div>
        <p class="description"><?php esc_html_e('Reset attempts only clears this plugin’s temporary brute-force counter for that username/IP pair. It does not alter the WordPress user account or delete the audit trail.', 'inkfire-login-styler'); ?></p>
        <p><a class="button" href="<?php echo esc_url(self::diagnostics_url(['ifls_event' => 'login_failed'])); ?>"><?php esc_html_e('Open the complete failed-login log', 'inkfire-login-styler'); ?></a></p>
        <?php
    }

    private static function render_activity() {
        $rows = IFLS_Event_Log::query(['limit' => 20]);
        ?>
        <div class="ifls-table-wrap">
            <table class="widefat striped ifls-dashboard-table">
                <caption class="screen-reader-text"><?php esc_html_e('Recent authentication activity on this site.', 'inkfire-login-styler'); ?></caption>
                <thead><tr>
                    <th><?php esc_html_e('When', 'inkfire-login-styler'); ?></th>
                    <th><?php esc_html_e('Event', 'inkfire-login-styler'); ?></th>
                    <th><?php esc_html_e('User', 'inkfire-login-styler'); ?></th>
                    <th><?php esc_html_e('IP', 'inkfire-login-styler'); ?></th>
                    <th><?php esc_html_e('Outcome', 'inkfire-login-styler'); ?></th>
                </tr></thead>
                <tbody>
                <?php if (!$rows) : ?>
                    <tr><td colspan="5"><em><?php esc_html_e('No authentication events have been recorded yet.', 'inkfire-login-styler'); ?></em></td></tr>
                <?php else : foreach ($rows as $row) : $tone = self::event_tone($row->event, $row->outcome); ?>
                    <tr>
                        <td><?php echo esc_html(self::format_when($row->created_at)); ?></td>
                        <td><span class="ifls-event-chip is-<?php echo esc_attr($tone); ?>"><?php echo esc_html(self::event_label($row->event)); ?></span></td>
                        <td><?php echo esc_html($row->username ?: '-'); ?></td>
                        <td><code><?php echo esc_html($row->ip ?: '-'); ?></code></td>
                        <td><?php echo esc_html($row->outcome); ?></td>
                    </tr>
                <?php endforeach; endif; ?>
                </tbody>
            </table>
        </div>
        <p><a class="button" href="<?php echo esc_url(self::diagnostics_url()); ?>"><?php esc_html_e('Search and filter the full 90-day log', 'inkfire-login-styler'); ?></a></p>
        <?php
    }

    private static function render_health() {
        global $wpdb;
        $table = IFLS_Event_Log::table();
        $table_exists = ($table === $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $table)));
        $transport = IFLS_Mail_Diagnostics::transport_info();
        $dns = IFLS_Mail_Diagnostics::dns_info();
        $incidents = IFLS_Incident_Reporter::incidents();
        $test = get_transient('ifls_test_result_' . get_current_user_id());
        ?>
        <?php if (isset($_GET['ifls_attempts_reset'])) : ?>
            <div class="notice notice-success inline"><p><?php esc_html_e('The selected failed-login counter was reset. The audit history was kept.', 'inkfire-login-styler'); ?></p></div>
        <?php endif; ?>
        <?php if (isset($_GET['ifls_tested']) && is_array($test)) : ?>
            <div class="notice notice-<?php echo !empty($test['sent']) ? 'success' : 'error'; ?> inline"><p>
                <?php echo !empty($test['sent'])
                    ? esc_html(sprintf(__('Test email was handed to the mail transport for %s.', 'inkfire-login-styler'), $test['to']))
                    : esc_html__('The mail transport refused the test email.', 'inkfire-login-styler'); ?>
                <?php if (empty($test['sent']) && !empty($test['error'])) : ?> <?php echo esc_html($test['error']); ?><?php endif; ?>
            </p></div>
        <?php endif; ?>

        <div class="ifls-health-grid">
            <article class="ifls-health-item"><span><?php esc_html_e('Diagnostics', 'inkfire-login-styler'); ?></span><strong><?php echo ifls_diag_enabled() ? esc_html__('Enabled', 'inkfire-login-styler') : esc_html__('Disabled', 'inkfire-login-styler'); ?></strong></article>
            <article class="ifls-health-item"><span><?php esc_html_e('Event database', 'inkfire-login-styler'); ?></span><strong><?php echo $table_exists ? esc_html__('Ready', 'inkfire-login-styler') : esc_html__('Missing', 'inkfire-login-styler'); ?></strong></article>
            <article class="ifls-health-item"><span><?php esc_html_e('Incident reporting', 'inkfire-login-styler'); ?></span><strong><?php echo ifls_diag_setting('reporting_enabled') ? esc_html__('Enabled', 'inkfire-login-styler') : esc_html__('Disabled', 'inkfire-login-styler'); ?></strong></article>
            <article class="ifls-health-item"><span><?php esc_html_e('Stored incidents', 'inkfire-login-styler'); ?></span><strong><?php echo (int) count($incidents); ?></strong></article>
            <article class="ifls-health-item"><span><?php esc_html_e('WordPress mail from', 'inkfire-login-styler'); ?></span><strong class="ifls-health-code"><?php echo esc_html($transport['wp_mail_from']); ?></strong></article>
            <article class="ifls-health-item"><span><?php esc_html_e('DNS checks', 'inkfire-login-styler'); ?></span><strong><?php echo !empty($dns['available']) ? esc_html__('Available', 'inkfire-login-styler') : esc_html__('Unavailable', 'inkfire-login-styler'); ?></strong></article>
            <article class="ifls-health-item"><span><?php esc_html_e('Incident cron', 'inkfire-login-styler'); ?></span><strong><?php echo wp_next_scheduled('ifls_dispatch_incidents') ? esc_html__('Scheduled', 'inkfire-login-styler') : esc_html__('Not scheduled', 'inkfire-login-styler'); ?></strong></article>
            <article class="ifls-health-item"><span><?php esc_html_e('Retention', 'inkfire-login-styler'); ?></span><strong><?php echo esc_html(sprintf(__('%d days', 'inkfire-login-styler'), (int) ifls_diag_setting('retention_days'))); ?></strong></article>
        </div>

        <div class="ifls-quick-actions">
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                <?php wp_nonce_field('ifls_dashboard_test_email'); ?>
                <input type="hidden" name="action" value="ifls_dashboard_test_email">
                <button type="submit" class="button button-primary"><?php esc_html_e('Send test email', 'inkfire-login-styler'); ?></button>
            </form>
            <a class="button" href="<?php echo esc_url(self::debug_report_url()); ?>"><?php esc_html_e('Download debug report', 'inkfire-login-styler'); ?></a>
            <a class="button" href="<?php echo esc_url(self::diagnostics_url()); ?>"><?php esc_html_e('Diagnostics settings & full log', 'inkfire-login-styler'); ?></a>
        </div>
        <p class="description"><?php esc_html_e('The downloadable report contains site/runtime configuration, diagnostic health, counts and incident metadata. It deliberately excludes passwords, reset keys, cookies and end-user IP/email data.', 'inkfire-login-styler'); ?></p>
        <?php
    }

    /**
     * Server-rendered fallback for administrators who disable JavaScript.
     *
     * React replaces this content when the enhanced dashboard loads. Keeping
     * functional forms and links in the initial HTML means no critical admin
     * action disappears when scripts are unavailable.
     *
     * @param string $overview Overview section HTML.
     * @param string $failures Failed-login section HTML.
     * @param string $activity Activity section HTML.
     * @param string $health Health section HTML.
     */
    private static function render_fallback($overview, $failures, $activity, $health) {
        ?>
        <div class="foundation-app-root foundation-admin-fallback">
            <header class="foundation-shell-panel">
                <p class="foundation-shell-kicker"><?php esc_html_e('Foundation command centre', 'inkfire-login-styler'); ?></p>
                <h1 class="foundation-shell-section__title"><?php esc_html_e('Foundation: Inkfire Login', 'inkfire-login-styler'); ?></h1>
                <p class="foundation-shell-section__description"><?php esc_html_e('JavaScript is unavailable. All authentication operations and diagnostics controls remain available below.', 'inkfire-login-styler'); ?></p>
                <div class="foundation-shell-actions">
                    <a class="foundation-shell-button is-solid" href="<?php echo esc_url(add_query_arg('reauth', '1', wp_login_url())); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e('Preview login page', 'inkfire-login-styler'); ?></a>
                    <a class="foundation-shell-button is-ghost" href="<?php echo esc_url(self::diagnostics_url()); ?>"><?php esc_html_e('Open full diagnostics', 'inkfire-login-styler'); ?></a>
                    <a class="foundation-shell-button is-ghost" href="<?php echo esc_url(self::debug_report_url()); ?>"><?php esc_html_e('Download debug report', 'inkfire-login-styler'); ?></a>
                </div>
            </header>

            <nav class="foundation-shell-nav" aria-label="<?php esc_attr_e('Section navigation', 'inkfire-login-styler'); ?>">
                <a class="foundation-nav-button" href="#ifls-overview"><?php esc_html_e('Overview', 'inkfire-login-styler'); ?></a>
                <a class="foundation-nav-button" href="#ifls-failed-logins"><?php esc_html_e('Failed logins', 'inkfire-login-styler'); ?></a>
                <a class="foundation-nav-button" href="#ifls-activity"><?php esc_html_e('Activity', 'inkfire-login-styler'); ?></a>
                <a class="foundation-nav-button" href="#ifls-health-debug"><?php esc_html_e('Health & debug', 'inkfire-login-styler'); ?></a>
            </nav>

            <div class="foundation-shell-sections">
                <section id="ifls-overview" class="foundation-shell-section foundation-shell-panel">
                    <header class="foundation-shell-section__header"><div><p class="foundation-shell-kicker"><?php esc_html_e('Operations', 'inkfire-login-styler'); ?></p><h2 class="foundation-shell-section__title"><?php esc_html_e('Login health at a glance', 'inkfire-login-styler'); ?></h2></div></header>
                    <div class="foundation-admin-rich"><?php echo $overview; // phpcs:ignore WordPress.Security.EscapeOutput -- generated by escaped render method. ?></div>
                </section>
                <section id="ifls-failed-logins" class="foundation-shell-section foundation-shell-panel">
                    <header class="foundation-shell-section__header"><div><p class="foundation-shell-kicker"><?php esc_html_e('Security', 'inkfire-login-styler'); ?></p><h2 class="foundation-shell-section__title"><?php esc_html_e('Failed login management', 'inkfire-login-styler'); ?></h2></div></header>
                    <div class="foundation-admin-rich"><?php echo $failures; // phpcs:ignore WordPress.Security.EscapeOutput -- generated by escaped render method. ?></div>
                </section>
                <section id="ifls-activity" class="foundation-shell-section foundation-shell-panel">
                    <header class="foundation-shell-section__header"><div><p class="foundation-shell-kicker"><?php esc_html_e('Audit trail', 'inkfire-login-styler'); ?></p><h2 class="foundation-shell-section__title"><?php esc_html_e('Who is logging in and out', 'inkfire-login-styler'); ?></h2></div></header>
                    <div class="foundation-admin-rich"><?php echo $activity; // phpcs:ignore WordPress.Security.EscapeOutput -- generated by escaped render method. ?></div>
                </section>
                <section id="ifls-health-debug" class="foundation-shell-section foundation-shell-panel">
                    <header class="foundation-shell-section__header"><div><p class="foundation-shell-kicker"><?php esc_html_e('Diagnostics', 'inkfire-login-styler'); ?></p><h2 class="foundation-shell-section__title"><?php esc_html_e('Health, mail and support report', 'inkfire-login-styler'); ?></h2></div></header>
                    <div class="foundation-admin-rich"><?php echo $health; // phpcs:ignore WordPress.Security.EscapeOutput -- generated by escaped render method. ?></div>
                </section>
            </div>
        </div>
        <?php
    }

    public static function render() {
        if (!current_user_can(self::CAPABILITY)) {
            wp_die(esc_html__('You do not have permission to access this page.', 'inkfire-login-styler'));
        }

        ob_start(); self::render_overview(); $overview = ob_get_clean();
        ob_start(); self::render_failures(); $failures = ob_get_clean();
        ob_start(); self::render_activity(); $activity = ob_get_clean();
        ob_start(); self::render_health(); $health = ob_get_clean();
        ?>
        <div class="wrap foundation-admin-wrap">
            <div id="foundation-admin-app"><?php self::render_fallback($overview, $failures, $activity, $health); ?></div>
            <template id="foundation-login-overview"><?php echo $overview; // phpcs:ignore WordPress.Security.EscapeOutput -- generated by escaped render method. ?></template>
            <template id="foundation-login-failures"><?php echo $failures; // phpcs:ignore WordPress.Security.EscapeOutput ?></template>
            <template id="foundation-login-activity"><?php echo $activity; // phpcs:ignore WordPress.Security.EscapeOutput ?></template>
            <template id="foundation-login-health"><?php echo $health; // phpcs:ignore WordPress.Security.EscapeOutput ?></template>
        </div>
        <?php
    }

    public static function handle_reset_attempts() {
        if (!current_user_can(self::CAPABILITY)) {
            wp_die(esc_html__('You do not have permission to do that.', 'inkfire-login-styler'));
        }
        check_admin_referer('ifls_reset_login_attempts');

        $username = isset($_POST['username']) && is_scalar($_POST['username'])
            ? preg_replace('/[\x00-\x1F\x7F]/u', '', (string) wp_unslash($_POST['username']))
            : '';
        $ip = isset($_POST['ip']) ? sanitize_text_field(wp_unslash($_POST['ip'])) : '';

        IFLS_Enterprise_Security::get_instance()->clear_attempts_for($username, $ip);

        wp_safe_redirect(add_query_arg('ifls_attempts_reset', '1', self::page_url()) . '#ifls-failed-logins');
        exit;
    }

    public static function handle_test_email() {
        if (!current_user_can(self::CAPABILITY)) {
            wp_die(esc_html__('You do not have permission to do that.', 'inkfire-login-styler'));
        }
        check_admin_referer('ifls_dashboard_test_email');

        $recipient = ifls_diag_setting('report_email');
        if (!is_email($recipient)) {
            $user = wp_get_current_user();
            $recipient = $user && is_email($user->user_email) ? $user->user_email : get_option('admin_email');
        }

        $result = IFLS_Mail_Diagnostics::send_test($recipient);
        set_transient('ifls_test_result_' . get_current_user_id(), $result, 5 * MINUTE_IN_SECONDS);

        wp_safe_redirect(add_query_arg('ifls_tested', '1', self::page_url()) . '#ifls-health-debug');
        exit;
    }

    private static function debug_report_text() {
        global $wpdb;

        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $lines = [];
        $host = wp_parse_url(home_url(), PHP_URL_HOST);
        $theme = wp_get_theme();
        $table = IFLS_Event_Log::table();
        $table_exists = ($table === $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $table)));
        $transport = IFLS_Mail_Diagnostics::transport_info();
        $dns = IFLS_Mail_Diagnostics::dns_info();
        $incidents = IFLS_Incident_Reporter::incidents();
        $plugins = get_plugins();
        $active = (array) get_option('active_plugins', []);

        $add = function ($key, $value = '') use (&$lines) {
            $lines[] = str_pad((string) $key, 28) . (string) $value;
        };

        $lines[] = 'Foundation - Inkfire Login | Debug Report';
        $lines[] = str_repeat('=', 56);
        $add('Generated (UTC):', gmdate('Y-m-d H:i:s'));
        $add('Site:', home_url());
        $add('Plugin version:', IFLS_VERSION);
        $add('WordPress:', get_bloginfo('version'));
        $add('PHP:', PHP_VERSION);
        $add('Multisite:', is_multisite() ? 'yes' : 'no');
        $add('Theme:', $theme->get('Name') . ' ' . $theme->get('Version'));
        $add('Memory limit:', ini_get('memory_limit'));
        $lines[] = '';

        $lines[] = 'Diagnostics health';
        $lines[] = str_repeat('-', 56);
        $add('Diagnostics enabled:', ifls_diag_enabled() ? 'yes' : 'no');
        $add('Logging enabled:', ifls_diag_setting('logging_enabled') ? 'yes' : 'no');
        $add('Event table:', $table_exists ? 'present' : 'missing');
        $add('Event DB version:', get_option('ifls_events_db_version', '(none)'));
        $add('Retention days:', (int) ifls_diag_setting('retention_days'));
        $add('Reporting enabled:', ifls_diag_setting('reporting_enabled') ? 'yes' : 'no');
        $add('Report recipient configured:', is_email((string) ifls_diag_setting('report_email')) ? 'yes' : 'no');
        $add('Alert threshold:', sprintf('%d in %d minutes', (int) ifls_diag_setting('threshold_count'), (int) ifls_diag_setting('threshold_minutes')));
        $add('Cooldown hours:', (int) ifls_diag_setting('cooldown_hours'));
        $add('Dispatch cron:', wp_next_scheduled('ifls_dispatch_incidents') ? gmdate('Y-m-d H:i:s', wp_next_scheduled('ifls_dispatch_incidents')) . ' UTC' : 'not scheduled');
        $add('Prune cron:', wp_next_scheduled('ifls_prune_events') ? gmdate('Y-m-d H:i:s', wp_next_scheduled('ifls_prune_events')) . ' UTC' : 'not scheduled');
        $lines[] = '';

        $lines[] = 'Authentication counts';
        $lines[] = str_repeat('-', 56);
        foreach ([
            'login_success', 'login_failed', 'logout', 'lockout', 'reset_requested',
            'reset_completed', 'reset_failed', 'csrf_blocked', 'registration'
        ] as $event) {
            $add($event . ' 24h:', IFLS_Event_Log::count_since($event, 1440));
            $add($event . ' 7d:', IFLS_Event_Log::count_since($event, 10080));
        }
        $lines[] = '';

        $lines[] = 'Incident summary (no end-user PII)';
        $lines[] = str_repeat('-', 56);
        if (!$incidents) {
            $lines[] = 'No incidents recorded.';
        } else {
            foreach (array_slice($incidents, 0, 20) as $incident) {
                $lines[] = sprintf(
                    '- %s | %s | count=%d | status=%s | last=%s UTC',
                    isset($incident['type']) ? $incident['type'] : 'unknown',
                    isset($incident['reason']) ? $incident['reason'] : '',
                    isset($incident['count']) ? (int) $incident['count'] : 0,
                    isset($incident['status']) ? $incident['status'] : 'pending',
                    isset($incident['last_seen']) ? gmdate('Y-m-d H:i:s', (int) $incident['last_seen']) : 'unknown'
                );
            }
        }
        $lines[] = '';

        $lines[] = 'Mail / DNS';
        $lines[] = str_repeat('-', 56);
        $add('Mail sender configured:', is_email($transport['wp_mail_from']) ? 'yes' : 'no');
        $add('Admin mailbox configured:', is_email($transport['admin_email']) ? 'yes' : 'no');
        $add('DNS available:', !empty($dns['available']) ? 'yes' : 'no');
        $add('MX available:', !empty($dns['mx']) ? 'yes' : 'no');
        $add('SPF present:', !empty($dns['spf']) ? 'yes' : 'no');
        $add('DMARC present:', !empty($dns['dmarc']) ? 'yes' : 'no');
        $lines[] = '';

        $lines[] = 'Active plugins';
        $lines[] = str_repeat('-', 56);
        foreach ($active as $file) {
            $data = isset($plugins[$file]) ? $plugins[$file] : [];
            $lines[] = sprintf('- %s %s (%s)', isset($data['Name']) ? $data['Name'] : $file, isset($data['Version']) ? $data['Version'] : '', $file);
        }
        $lines[] = '';
        $lines[] = 'Privacy note: this report excludes event-row usernames, IP addresses, user agents, email addresses, passwords, reset keys, cookies and nonces.';

        return implode("\n", $lines) . "\n";
    }

    public static function handle_debug_report() {
        if (!current_user_can(self::CAPABILITY)) {
            wp_die(esc_html__('You do not have permission to do that.', 'inkfire-login-styler'));
        }
        check_admin_referer('ifls_download_debug_report');

        $host = sanitize_file_name((string) wp_parse_url(home_url(), PHP_URL_HOST));
        $filename = sprintf('foundation-login-debug-%s-%s.txt', $host ?: 'site', gmdate('Ymd-His'));
        nocache_headers();
        header('Content-Type: text/plain; charset=utf-8');
        header('X-Content-Type-Options: nosniff');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        echo self::debug_report_text(); // phpcs:ignore WordPress.Security.EscapeOutput -- plain text attachment assembled from escaped/safe diagnostics.
        exit;
    }
}
