<?php
/**
 * Fired when the plugin is uninstalled.
 *
 * @package Inkfire_Login_Styler
 */

// If uninstall not called from WordPress, then exit.
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

// 1. Delete Plugin Options
delete_option('ifls_installed_version');
delete_option('ifls_auto_updates');
delete_option('ifls_health_status');

// 2.1.0 additions
delete_option('ifls_diagnostics_settings');
delete_option('ifls_incidents');
delete_option('ifls_events_db_version');

global $wpdb;

// 2. Clear transients.
//
// On a site with a persistent object cache (Redis/Memcached), transients never
// touch wp_options at all -- so the raw DELETE below is a silent no-op there.
// Delete through the API first so the object cache is actually cleared, then
// sweep the table for anything left behind.
$transients = $wpdb->get_col(
    "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE '\_transient\_ifls\_%'"
);

foreach ($transients as $option_name) {
    delete_transient(str_replace('_transient_', '', $option_name));
}

// Sweep orphaned rows and timeouts. Patterns are hardcoded literals, so
// prepare() is unnecessary; '_' is escaped so it is not a single-char wildcard.
$wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '\_transient\_ifls\_%'");
$wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '\_transient\_timeout\_ifls\_%'");

// 3. Drop the event log table.
$wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}ifls_events");

// 4. Unschedule cron events.
wp_clear_scheduled_hook('ifls_prune_events');
wp_clear_scheduled_hook('ifls_dispatch_incidents');

// 5. Clear Object Cache
if (function_exists('wp_cache_flush')) {
    wp_cache_flush();
}