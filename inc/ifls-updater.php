<?php
/**
 * IFLS Updater (zero-config, public GitHub)
 * Pulls updates from GitHub Releases/tags. No tokens. No wp-config edits.
 * Works across all sites without touching their admin.
 */
if (!defined('ABSPATH')) exit;

if (!function_exists('ifls_boot_updater')) {
    function ifls_boot_updater() {
        // Load PUC
        $puc_loader = __DIR__ . '/../plugin-update-checker/plugin-update-checker.php';
        if (!file_exists($puc_loader)) return;
        require_once $puc_loader;

        // Your public repo URL (leave as https://github.com/USER/REPO/)
        $repoUrl = 'https://github.com/hawks010/foundation-login-plugin/';

        // Branch to read metadata from (usually 'main' or 'master')
        $branch  = 'main';

        // MUST match your plugin folder slug
        $slug    = 'foundation-inkfire-login-styler';

        // Build checker
        $factory = \YahnisElsts\PluginUpdateChecker\v5\PucFactory::buildUpdateChecker(
            $repoUrl,
            dirname(__DIR__) . '/inkfire-login-styler.php',
            $slug
        );

        // Track a specific branch if you publish releases from that branch
        if (method_exists($factory, 'setBranch')) {
            $factory->setBranch($branch);
        }

        // No authentication needed for public repos.
        // If you ever go private, you can add:
        // if (defined('IFLS_GH_TOKEN') && IFLS_GH_TOKEN) { $factory->setAuthentication(IFLS_GH_TOKEN); }
    }
}

// Auto-boot on plugins_loaded
add_action('plugins_loaded', 'ifls_boot_updater');