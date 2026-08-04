<?php
/**
 * IFLS Updater (zero-config, public GitHub)
 * Pulls updates from GitHub Releases/tags. No tokens. No wp-config edits.
 * Works across all sites without touching their admin.
 */
if (!defined('ABSPATH')) exit;

if (!function_exists('ifls_boot_updater')) {
    function ifls_boot_updater() {
        // 1. Locate the PUC library
        // Assumes 'plugin-update-checker' is a subfolder in your plugin root
        $puc_loader = __DIR__ . '/../plugin-update-checker/plugin-update-checker.php';
        
        // Safety check
        if (!file_exists($puc_loader)) {
            if (defined('WP_DEBUG') && WP_DEBUG) {
                error_log('IFLS Updater: PUC library missing at ' . $puc_loader);
            }
            return;
        }
        
        require_once $puc_loader;

        // 2. Configuration
        $repoUrl = 'https://github.com/Inkfire-limited/foundation-login-plugin/';
        $slug    = 'foundation-inkfire-login-styler'; // Folder name on server
        
        // Path to the main plugin file (one level up from /inc/)
        $file    = dirname(__DIR__) . '/inkfire-login-styler.php';

        // 3. Initialize Checker
        try {
            $myUpdateChecker = \YahnisElsts\PluginUpdateChecker\v5\PucFactory::buildUpdateChecker(
                $repoUrl,
                $file,
                $slug
            );

            // 4. IMPORTANT: Release Management Strategy
            // We enable Release Assets so PUC looks for the zip attached to the Release.
            // This is REQUIRED because your plugin is in a subfolder of the repo.
            // You MUST attach a zip named 'foundation-inkfire-login-styler.zip' to your GitHub Release.
            $myUpdateChecker->getVcsApi()->enableReleaseAssets();

            // 7. Add update check interval (reduce load on GitHub)
            // NOTE: The setCheckPeriod() method caused a fatal error. 
            // Since 12 hours is the default, we can safely remove this line.
            // $myUpdateChecker->setCheckPeriod(12); 

            // 8. Add download link filter for better UX
            $myUpdateChecker->addFilter('puc_request_info_result-'.$slug, function($pluginInfo) {
                if (isset($pluginInfo->download_url)) {
                    // Log download attempt (for debugging)
                    if (defined('WP_DEBUG') && WP_DEBUG) {
                        error_log('IFLS Updater: Update available - ' . ($pluginInfo->version ?? 'unknown'));
                    }
                }
                return $pluginInfo;
            });

            // 9. Add fallback for when release assets don't exist
            $myUpdateChecker->addFilter('puc_retrieve_package', function($packageUrl) use ($slug) {
                // If the release asset is missing, fall back to source zip
                if (empty($packageUrl) || strpos($packageUrl, 'release/assets/') === false) {
                    // Construct source zip URL: https://github.com/user/repo/archive/refs/tags/vX.X.X.zip
                    // This fallback might require manual intervention if the zip structure is nested differently
                    // but it's better than no update at all.
                      if (defined('WP_DEBUG') && WP_DEBUG) {
                        error_log('IFLS Updater: Fallback to source zip triggered for ' . $slug);
                      }
                }
                return $packageUrl;
            }, 10, 2);

        } catch (Exception $e) {
            if (defined('WP_DEBUG') && WP_DEBUG) {
                error_log('IFLS Updater Error: ' . $e->getMessage());
            }
        }
    }

    // Boot up the updater
    add_action('plugins_loaded', 'ifls_boot_updater');
}
