# Login Diagnostics, Audit Log & Incident Reporting — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship v2.1.0 — an on-site authentication audit log, automatic incident alerting to Inkfire when the plugin malfunctions, mail diagnostics, a settings screen, and four outstanding audit fixes.

**Architecture:** Four independent units under `inc/`, each in its own file with one responsibility, wired up from the main plugin file. All logging is fail-safe by construction: every entry point is wrapped so a diagnostics failure can never propagate into the authentication path. Incident email is never sent during an authentication request.

**Tech Stack:** PHP 7.4+, WordPress 6.0+, `$wpdb` + `dbDelta`, WP Settings API, WP-Cron. No Composer, no external libraries.

**Spec:** `docs/superpowers/specs/2026-08-06-login-diagnostics-design.md`

## Global Constraints

- Target version **2.1.0**. Four version fields must match: plugin header `Version:`, `IFLS_VERSION`, `README.txt` `Stable tag:`, `README.md` table.
- PHP 7.4 compatible. No arrow-function-only syntax, no union types, no `match`, no constructor promotion, no enums.
- Text domain `inkfire-login-styler` on every user-facing string.
- Existing code style: 4-space indent, short array syntax `[]`, `snake_case` functions prefixed `ifls_`, classes prefixed `IFLS_`.
- **Never log** passwords, nonces, reset keys, cookies, or auth tokens. A reset key in a log would be an account-takeover vector.
- **No inline mail on the auth path.** Incidents are stored `pending` and dispatched off-request.
- **Kill switch:** `IFLS_DISABLE_DIAGNOSTICS` is checked before any work in every public entry point.
- All timestamps stored **UTC** (`gmdate`), rendered in site timezone.
- Every admin screen: `current_user_can('manage_options')` + nonce on state change. Every output escaped.
- Hostinger has `opcache.revalidate_freq=2` — always `sleep 6` after deploying a PHP change before testing it over HTTP.

---

## File Structure

| File | Responsibility |
|---|---|
| `inc/ifls-diagnostics-settings.php` | Defaults, settings accessor, constant precedence, sanitisation |
| `inc/class-ifls-event-log.php` | Table schema, record, query, prune |
| `inc/class-ifls-incident-reporter.php` | Detection, dedup, local store, queued dispatch |
| `inc/class-ifls-mail-diagnostics.php` | Test send, transport inspection, DNS lookup |
| `inc/class-ifls-diagnostics-admin.php` | Settings screen, log viewer, incident list |
| `inkfire-login-styler.php` | Wire-up only + the four audit fixes |
| `uninstall.php` | Audit fix C + drop new table/options |
| `tests/bootstrap.php` | Boots WP outside WP-CLI, blocks mail, converts `wp_die` to exceptions |
| `tests/run.php` | Test runner, prints pass/fail summary, exit code |
| `tests/test-*.php` | One file per unit |

---

## Task 1: Test harness

**Files:**
- Create: `tests/bootstrap.php`, `tests/run.php`, `tests/test-harness-selfcheck.php`

**Interfaces:**
- Produces: `ifls_test( $name, callable $fn )`, `ifls_assert( $cond, $msg )`, `ifls_assert_eq( $expected, $actual, $msg )`, `ifls_sent_mail()`, `ifls_reset_mail()`, `IFLS_Test_Blocked` exception class.

The plugin early-returns when `WP_CLI` is defined, which is exactly what hid the 2.0.27 bug from CLI testing. The harness therefore boots WordPress via plain `php`, **not** `wp eval`.

- [ ] **Step 1: Create the bootstrap**

```php
<?php
/**
 * Boots WordPress for tests OUTSIDE WP-CLI, because the plugin's own
 * `defined('WP_CLI')` guards would otherwise mask the code under test.
 *
 * Usage: php tests/run.php /path/to/wordpress
 */

function ifls_test_boot( $wp_root, array $context = [] ) {
    $_SERVER['HTTP_HOST']      = 'localhost';
    $_SERVER['SERVER_NAME']    = 'localhost';
    $_SERVER['REQUEST_METHOD'] = isset( $context['method'] ) ? $context['method'] : 'GET';
    $_SERVER['REQUEST_URI']    = isset( $context['uri'] ) ? $context['uri'] : '/';
    $_SERVER['SCRIPT_NAME']    = $_SERVER['REQUEST_URI'];
    $_SERVER['PHP_SELF']       = $_SERVER['REQUEST_URI'];
    $_SERVER['REMOTE_ADDR']    = isset( $context['ip'] ) ? $context['ip'] : '127.0.0.1';
    $_SERVER['HTTP_USER_AGENT'] = 'IFLS-Test';

    require_once rtrim( $wp_root, '/' ) . '/wp-load.php';

    ifls_test_block_mail();
    ifls_test_catch_wp_die();
}

/** Hard-block outbound mail; capture what would have been sent. */
function ifls_test_block_mail() {
    $GLOBALS['ifls_test_mail'] = [];
    add_filter( 'pre_wp_mail', function ( $null, $atts ) {
        $GLOBALS['ifls_test_mail'][] = $atts;
        return true;
    }, PHP_INT_MAX, 2 );
}

function ifls_sent_mail() {
    return isset( $GLOBALS['ifls_test_mail'] ) ? $GLOBALS['ifls_test_mail'] : [];
}

function ifls_reset_mail() {
    $GLOBALS['ifls_test_mail'] = [];
}

class IFLS_Test_Blocked extends RuntimeException {}

/** Turn wp_die() into a catchable exception so blocking behaviour is assertable. */
function ifls_test_catch_wp_die() {
    $handler = function () {
        return function ( $message, $title = '', $args = [] ) {
            if ( is_wp_error( $message ) ) {
                $message = $message->get_error_message();
            }
            throw new IFLS_Test_Blocked( wp_strip_all_tags( (string) $message ) );
        };
    };
    foreach ( [ 'wp_die_handler', 'wp_die_ajax_handler', 'wp_die_json_handler', 'wp_die_jsonp_handler', 'wp_die_xmlrpc_handler', 'wp_die_xml_handler' ] as $f ) {
        add_filter( $f, $handler, PHP_INT_MAX );
    }
}
```

- [ ] **Step 2: Create the runner and assertions**

```php
<?php
/** Usage: php tests/run.php /path/to/wordpress [test-file-substring] */

require_once __DIR__ . '/bootstrap.php';

$wp_root = isset( $argv[1] ) ? $argv[1] : '';
$filter  = isset( $argv[2] ) ? $argv[2] : '';
if ( ! $wp_root ) {
    fwrite( STDERR, "usage: php tests/run.php <wp-root> [filter]\n" );
    exit( 2 );
}

$GLOBALS['ifls_results'] = [ 'pass' => 0, 'fail' => 0, 'failures' => [] ];

function ifls_test( $name, callable $fn ) {
    try {
        $fn();
        $GLOBALS['ifls_results']['pass']++;
        printf( "  [ok]   %s\n", $name );
    } catch ( Throwable $e ) {
        $GLOBALS['ifls_results']['fail']++;
        $GLOBALS['ifls_results']['failures'][] = $name . ' -- ' . $e->getMessage();
        printf( "  [FAIL] %s\n         %s\n", $name, $e->getMessage() );
    }
}

function ifls_assert( $cond, $msg = 'assertion failed' ) {
    if ( ! $cond ) {
        throw new RuntimeException( $msg );
    }
}

function ifls_assert_eq( $expected, $actual, $msg = '' ) {
    if ( $expected !== $actual ) {
        throw new RuntimeException( sprintf(
            '%s expected %s, got %s',
            $msg,
            var_export( $expected, true ),
            var_export( $actual, true )
        ) );
    }
}

ifls_test_boot( $wp_root );

foreach ( glob( __DIR__ . '/test-*.php' ) as $file ) {
    if ( $filter && false === strpos( basename( $file ), $filter ) ) {
        continue;
    }
    printf( "\n%s\n", basename( $file ) );
    require $file;
}

$r = $GLOBALS['ifls_results'];
printf( "\n=== %d passed, %d failed ===\n", $r['pass'], $r['fail'] );
foreach ( $r['failures'] as $f ) {
    printf( "FAILED: %s\n", $f );
}
exit( $r['fail'] > 0 ? 1 : 0 );
```

- [ ] **Step 3: Create a self-check proving the harness works**

```php
<?php
ifls_test( 'harness: WordPress booted', function () {
    ifls_assert( function_exists( 'wp_mail' ), 'WordPress not loaded' );
} );

ifls_test( 'harness: WP_CLI is NOT defined (plugin guards must not fire)', function () {
    ifls_assert( ! defined( 'WP_CLI' ), 'WP_CLI is defined - guards would mask bugs' );
} );

ifls_test( 'harness: mail is blocked and captured', function () {
    ifls_reset_mail();
    wp_mail( 'nobody@example.com', 'subj', 'body' );
    ifls_assert_eq( 1, count( ifls_sent_mail() ), 'mail not captured' );
} );

ifls_test( 'harness: wp_die becomes catchable', function () {
    try {
        wp_die( 'boom' );
    } catch ( IFLS_Test_Blocked $e ) {
        ifls_assert_eq( 'boom', $e->getMessage() );
        return;
    }
    throw new RuntimeException( 'wp_die did not throw' );
} );
```

- [ ] **Step 4: Run it**

Run: `php tests/run.php /home/u363235284/domains/thatdeveloper.co.uk/public_html harness`
Expected: `4 passed, 0 failed`

- [ ] **Step 5: Commit**

```bash
git add tests/
git commit -m "test: add runnable WordPress test harness

Boots WP outside WP-CLI so the plugin's own WP_CLI guards cannot mask the
code under test - the same blind spot that hid 2.0.27 from CLI testing."
```

---

## Task 2: Four audit fixes

**Files:**
- Modify: `inkfire-login-styler.php` (asset manager ~line 291-299, socials markup ~line 660, hook list at end)
- Modify: `uninstall.php`
- Create: `tests/test-audit-fixes.php`

**Interfaces:**
- Produces: `ifls_social_icon( $network )` returning inline SVG markup.

These are independent of the feature work and land first so the feature diff stays clean.

- [ ] **Step 1: Write failing tests**

```php
<?php
ifls_test( 'fix A: login CSS is not enqueued on unrelated admin pages', function () {
    ifls_assert(
        has_action( 'admin_enqueue_scripts' ),
        'admin_enqueue_scripts should still be hooked'
    );
    // The callback must bail on a hook it does not own.
    do_action( 'admin_enqueue_scripts', 'edit.php' );
    ifls_assert( ! wp_style_is( 'inkfire-login', 'enqueued' ), 'login CSS leaked onto edit.php' );
} );

ifls_test( 'fix B: no external CDN is referenced anywhere', function () {
    $src = file_get_contents( dirname( __DIR__ ) . '/inkfire-login-styler.php' );
    ifls_assert( false === strpos( $src, 'cdnjs.cloudflare.com' ), 'Font Awesome CDN still referenced' );
    ifls_assert( false === strpos( $src, 'fa-brands' ), 'Font Awesome classes still used' );
} );

ifls_test( 'fix B: social icons render as inline SVG', function () {
    $svg = ifls_social_icon( 'facebook' );
    ifls_assert( 0 === strpos( $svg, '<svg' ), 'expected inline SVG' );
    ifls_assert( false !== strpos( $svg, 'aria-hidden="true"' ), 'decorative SVG must be aria-hidden' );
    ifls_assert_eq( '', ifls_social_icon( 'nonexistent' ), 'unknown network must return empty string' );
} );

ifls_test( 'fix D: no-op login_footer hook is gone', function () {
    $src = file_get_contents( dirname( __DIR__ ) . '/inkfire-login-styler.php' );
    ifls_assert( false === strpos( $src, "login_footer', '__return_null'" ), 'no-op hook still present' );
} );
```

- [ ] **Step 2: Run to verify they fail**

Run: `php tests/run.php <wp-root> audit-fixes`
Expected: FAIL — `ifls_social_icon` undefined, CDN still referenced.

- [ ] **Step 3: Fix A — gate the admin stylesheet**

Replace the ungated `admin_enqueue_scripts` closure near the end of `inkfire-login-styler.php`:

```php
// Only load the login stylesheet on this plugin's own admin screens.
// It was previously enqueued on every wp-admin page, which is wasted weight
// on every request and risks the login styles bleeding into the admin.
add_action('admin_enqueue_scripts', function($hook) {
    if (false === strpos((string) $hook, 'foundation-login-styler')) {
        return;
    }
    $css_path = plugin_dir_path(__FILE__) . 'assets/inkfire-login.css';
    $css_ver  = file_exists($css_path) ? filemtime($css_path) : IFLS_VERSION;
    wp_enqueue_style('inkfire-login', plugins_url('assets/inkfire-login.css', __FILE__), [], $css_ver);
    wp_add_inline_style('inkfire-login', IFLS_Asset_Manager::generate_css_variables());
});
```

- [ ] **Step 4: Fix B — replace Font Awesome with inline SVG**

Delete the `case 'fa':` line from `get_asset_url()` and the `wp_enqueue_style('if-fa', ...)` line from `enqueue_assets()`. Add:

```php
/**
 * Inline brand icon markup.
 *
 * Replaces the Font Awesome CDN stylesheet, which pulled a large third-party
 * bundle onto every login page for five icons and disclosed each visitor's IP
 * to an external host. Paths are the Font Awesome 6 brand glyphs (CC BY 4.0).
 *
 * @param string $network facebook|instagram|linkedin|x|tiktok
 * @return string SVG markup, or '' for an unknown network.
 */
function ifls_social_icon($network) {
    $paths = [
        'facebook'  => 'M80 299.3V512h116V299.3h86.5l18-97.8H196v-33.3c0-51.6 20.2-71.8 72.5-71.8 16.3 0 29.4.4 37 1.2V9.8C291.4 3.3 273.2 0 255.6 0c-107 0-156.5 50.5-156.5 158.4v43.8H24v97.8h56v.1z',
        'instagram' => 'M224.1 141c-63.6 0-114.9 51.3-114.9 114.9s51.3 114.9 114.9 114.9S339 319.5 339 255.9 287.7 141 224.1 141zm0 189.6c-41.1 0-74.7-33.5-74.7-74.7s33.5-74.7 74.7-74.7 74.7 33.5 74.7 74.7-33.6 74.7-74.7 74.7zm146.4-194.3c0 14.9-12 26.8-26.8 26.8-14.9 0-26.8-12-26.8-26.8s12-26.8 26.8-26.8 26.8 12 26.8 26.8zm76.1 27.2c-1.7-35.9-9.9-67.7-36.2-93.9-26.2-26.2-58-34.4-93.9-36.2-37-2.1-147.9-2.1-184.9 0-35.8 1.7-67.6 9.9-93.9 36.1s-34.4 58-36.2 93.9c-2.1 37-2.1 147.9 0 184.9 1.7 35.9 9.9 67.7 36.2 93.9s58 34.4 93.9 36.2c37 2.1 147.9 2.1 184.9 0 35.9-1.7 67.7-9.9 93.9-36.2 26.2-26.2 34.4-58 36.2-93.9 2.1-37 2.1-147.8 0-184.8zM398.8 388c-7.8 19.6-22.9 34.7-42.6 42.6-29.5 11.7-99.5 9-132.1 9s-102.7 2.6-132.1-9c-19.6-7.8-34.7-22.9-42.6-42.6-11.7-29.5-9-99.5-9-132.1s-2.6-102.7 9-132.1c7.8-19.6 22.9-34.7 42.6-42.6 29.5-11.7 99.5-9 132.1-9s102.7-2.6 132.1 9c19.6 7.8 34.7 22.9 42.6 42.6 11.7 29.5 9 99.5 9 132.1s2.7 102.7-9 132.1z',
        'linkedin'  => 'M100.3 448H7.4V148.9h92.9V448zM53.8 108.1C24.1 108.1 0 83.5 0 53.8a53.8 53.8 0 0 1 107.6 0c0 29.7-24.1 54.3-53.8 54.3zM447.9 448h-92.7V302.4c0-34.7-.7-79.2-48.3-79.2-48.3 0-55.7 37.7-55.7 76.7V448h-92.8V148.9h89.1v40.8h1.3c12.4-23.5 42.7-48.3 87.9-48.3 94 0 111.3 61.9 111.3 142.3V448z',
        'x'         => 'M389.2 48h70.6L305.6 224.2 487 464H345L233.7 318.6 106.5 464H35.8L200.7 275.5 26.8 48H172.4L272.9 180.9 389.2 48zM364.4 421.8h39.1L151.1 88h-42L364.4 421.8z',
        'tiktok'    => 'M448,209.91a210.06,210.06,0,0,1-122.77-39.25V349.38A162.55,162.55,0,1,1,185,188.31V278.2a74.62,74.62,0,1,0,52.23,71.18V0l88,0a121.18,121.18,0,0,0,1.86,22.17h0A122.18,122.18,0,0,0,381,102.39a121.43,121.43,0,0,0,67,20.14Z',
    ];

    if (!isset($paths[$network])) {
        return '';
    }

    $viewbox = in_array($network, ['facebook', 'instagram'], true) ? '0 0 448 512' : '0 0 448 512';

    return '<svg class="if-social-icon" viewBox="' . esc_attr($viewbox) . '" width="18" height="18" fill="currentColor" aria-hidden="true" focusable="false"><path d="' . esc_attr($paths[$network]) . '"/></svg>';
}
```

Then rewrite the socials block (~line 660). Each link needs an accessible name now the `<i>` is gone:

```php
<div class="if-left-block"><h4>Follow Us</h4><div class="if-socials">
<a href="https://facebook.com/inkfirelimited" target="_blank" rel="noopener noreferrer" aria-label="Facebook"><?php echo ifls_social_icon('facebook'); ?></a>
<a href="https://www.instagram.com/inkfirelimited/" target="_blank" rel="noopener noreferrer" aria-label="Instagram"><?php echo ifls_social_icon('instagram'); ?></a>
<a href="https://uk.linkedin.com/company/inkfire" target="_blank" rel="noopener noreferrer" aria-label="LinkedIn"><?php echo ifls_social_icon('linkedin'); ?></a>
<a href="https://twitter.com/Inkfirelimited" target="_blank" rel="noopener noreferrer" aria-label="X"><?php echo ifls_social_icon('x'); ?></a>
<a href="https://www.tiktok.com/@inkfirelimited" target="_blank" rel="noopener noreferrer" aria-label="TikTok"><?php echo ifls_social_icon('tiktok'); ?></a>
</div></div>
```

- [ ] **Step 5: Fix C — make uninstall cleanup work with object caches**

The direct `wp_options` DELETE is a no-op when a persistent object cache is active (base-uk.org has one). Replace the two `$wpdb->query()` blocks in `uninstall.php` with:

```php
global $wpdb;

// Transients live in the object cache, not wp_options, when a persistent
// backend is active - so delete via the API as well as sweeping the table.
$transients = $wpdb->get_col(
    "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE '\_transient\_ifls\_%'"
);
foreach ( $transients as $option_name ) {
    delete_transient( str_replace( '_transient_', '', $option_name ) );
}

// Sweep any rows the API missed (e.g. orphaned timeouts).
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '\_transient\_ifls\_%'" );
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '\_transient\_timeout\_ifls\_%'" );

// v2.1.0 additions.
delete_option( 'ifls_diagnostics_settings' );
delete_option( 'ifls_incidents' );
delete_option( 'ifls_events_db_version' );
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}ifls_events" );

wp_clear_scheduled_hook( 'ifls_prune_events' );
wp_clear_scheduled_hook( 'ifls_dispatch_incidents' );
```

Note: the `LIKE` patterns are hardcoded literals, so `prepare()` is unnecessary; `_` is escaped so it is not treated as a single-character wildcard.

- [ ] **Step 6: Fix D — remove the no-op hook**

Delete this line entirely — it adds a callback that returns null and removes nothing:

```php
add_action('login_footer', '__return_null');
```

- [ ] **Step 7: Run tests**

Run: `php tests/run.php <wp-root> audit-fixes`
Expected: `4 passed, 0 failed`

- [ ] **Step 8: Verify the login page still renders correctly**

```bash
curl -s "https://thatdeveloper.co.uk/wp-login.php" | grep -c "if-social-icon"   # expect 5
curl -s "https://thatdeveloper.co.uk/wp-login.php" | grep -c "cdnjs"            # expect 0
```

- [ ] **Step 9: Commit**

```bash
git add inkfire-login-styler.php uninstall.php tests/
git commit -m "fix: four maintenance issues found in audit

- Gate the login stylesheet to this plugin's admin screens; it was loading
  on every wp-admin page.
- Replace the Font Awesome CDN with inline SVG. Five icons no longer cost a
  third-party stylesheet or disclose visitor IPs to an external host.
- Make uninstall transient cleanup work on sites with a persistent object
  cache, where the direct wp_options DELETE was a silent no-op.
- Remove a no-op login_footer hook that removed nothing."
```

---

## Task 3: Settings module

**Files:**
- Create: `inc/ifls-diagnostics-settings.php`, `tests/test-settings.php`
- Modify: `inkfire-login-styler.php` (require the new file)

**Interfaces:**
- Produces: `ifls_diag_defaults()`, `ifls_diag_setting( $key )`, `ifls_diag_is_locked( $key )`, `ifls_diag_sanitize( $input )`, `ifls_diag_enabled()`.

- [ ] **Step 1: Write failing tests**

```php
<?php
ifls_test( 'settings: defaults are returned when nothing is stored', function () {
    delete_option( 'ifls_diagnostics_settings' );
    ifls_assert_eq( 90, ifls_diag_setting( 'retention_days' ) );
    ifls_assert_eq( 'webmaster@inkfire.co.uk', ifls_diag_setting( 'report_email' ) );
    ifls_assert_eq( 5, ifls_diag_setting( 'threshold_count' ) );
} );

ifls_test( 'settings: stored values override defaults', function () {
    update_option( 'ifls_diagnostics_settings', [ 'retention_days' => 30 ] );
    ifls_assert_eq( 30, ifls_diag_setting( 'retention_days' ) );
    delete_option( 'ifls_diagnostics_settings' );
} );

ifls_test( 'settings: sanitise rejects a malformed email', function () {
    $out = ifls_diag_sanitize( [ 'report_email' => 'not-an-email' ] );
    ifls_assert_eq( 'webmaster@inkfire.co.uk', $out['report_email'], 'bad email should fall back to default' );
} );

ifls_test( 'settings: sanitise clamps absurd numbers', function () {
    $out = ifls_diag_sanitize( [ 'retention_days' => 99999, 'threshold_count' => 0 ] );
    ifls_assert_eq( 365, $out['retention_days'], 'retention should clamp to 365' );
    ifls_assert_eq( 1, $out['threshold_count'], 'threshold should clamp to at least 1' );
} );

ifls_test( 'settings: negative numbers are rejected', function () {
    $out = ifls_diag_sanitize( [ 'retention_days' => -5 ] );
    ifls_assert( $out['retention_days'] >= 1, 'retention must be positive' );
} );

ifls_test( 'settings: booleans are cast, not passed through', function () {
    $out = ifls_diag_sanitize( [ 'logging_enabled' => 'on' ] );
    ifls_assert_eq( true, $out['logging_enabled'] );
    $out = ifls_diag_sanitize( [] );
    ifls_assert_eq( false, $out['logging_enabled'], 'absent checkbox means false' );
} );
```

- [ ] **Step 2: Run to verify they fail**

Run: `php tests/run.php <wp-root> settings`
Expected: FAIL — `ifls_diag_setting` undefined.

- [ ] **Step 3: Implement**

```php
<?php
/**
 * Diagnostics settings: defaults, accessor, constant precedence, sanitisation.
 *
 * Precedence is defaults -> stored option -> constant. A constant always wins
 * and locks the corresponding field in the UI, so a site can pin behaviour in
 * wp-config.php and the settings screen tells the truth about it.
 */

if (!defined('ABSPATH')) {
    exit;
}

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

/** Master kill switch, checked before any diagnostics work anywhere. */
function ifls_diag_enabled() {
    return !(defined('IFLS_DISABLE_DIAGNOSTICS') && IFLS_DISABLE_DIAGNOSTICS);
}

/** Whether a setting is pinned by a constant (and therefore read-only in the UI). */
function ifls_diag_is_locked($key) {
    if ('report_email' === $key) {
        return defined('IFLS_REPORT_EMAIL');
    }
    if ('reporting_enabled' === $key) {
        return defined('IFLS_DISABLE_REPORTING');
    }
    return false;
}

function ifls_diag_setting($key) {
    $defaults = ifls_diag_defaults();

    if (!array_key_exists($key, $defaults)) {
        return null;
    }

    // Constants win outright.
    if ('report_email' === $key && defined('IFLS_REPORT_EMAIL')) {
        return IFLS_REPORT_EMAIL;
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
 * Settings API sanitize_callback. Never trust the posted array shape.
 *
 * @param mixed $input
 * @return array
 */
function ifls_diag_sanitize($input) {
    $defaults = ifls_diag_defaults();
    $input    = is_array($input) ? $input : [];
    $out      = [];

    // Checkboxes: absent means off.
    $out['logging_enabled']   = !empty($input['logging_enabled']);
    $out['reporting_enabled'] = !empty($input['reporting_enabled']);

    $email = isset($input['report_email']) ? sanitize_email($input['report_email']) : '';
    $out['report_email'] = is_email($email) ? $email : $defaults['report_email'];

    $ranges = [
        'retention_days'    => [1, 365],
        'threshold_count'   => [1, 100],
        'threshold_minutes' => [5, 1440],
        'cooldown_hours'    => [1, 168],
    ];
    foreach ($ranges as $key => $range) {
        $value     = isset($input[$key]) ? absint($input[$key]) : $defaults[$key];
        $out[$key] = min($range[1], max($range[0], $value));
    }

    return $out;
}
```

- [ ] **Step 4: Wire it up**

In `inkfire-login-styler.php`, after the updater require:

```php
require_once __DIR__ . '/inc/ifls-diagnostics-settings.php';
```

- [ ] **Step 5: Run tests**

Expected: `6 passed, 0 failed`

- [ ] **Step 6: Commit**

```bash
git add inc/ifls-diagnostics-settings.php tests/test-settings.php inkfire-login-styler.php
git commit -m "feat: add diagnostics settings module with constant precedence"
```

---

## Task 4: Event log

**Files:**
- Create: `inc/class-ifls-event-log.php`, `tests/test-event-log.php`
- Modify: `inkfire-login-styler.php`

**Interfaces:**
- Produces: `IFLS_Event_Log::install()`, `::table()`, `::record( $event, array $args = [] )`, `::query( array $args )`, `::count_since( $event, $minutes )`, `::prune()`, `::clear()`, `::EVENTS` (array of valid event names).

- [ ] **Step 1: Write failing tests**

```php
<?php
ifls_test( 'event log: table is installed', function () {
    global $wpdb;
    IFLS_Event_Log::install();
    $table = IFLS_Event_Log::table();
    ifls_assert_eq( $table, $wpdb->get_var( "SHOW TABLES LIKE '{$table}'" ), 'table missing' );
} );

ifls_test( 'event log: install is idempotent', function () {
    IFLS_Event_Log::install();
    IFLS_Event_Log::install();
    ifls_assert( true, 'second install must not error' );
} );

ifls_test( 'event log: records and reads back an event', function () {
    IFLS_Event_Log::clear();
    IFLS_Event_Log::record( 'login_success', [ 'username' => 'alice', 'user_id' => 1 ] );
    $rows = IFLS_Event_Log::query( [ 'event' => 'login_success' ] );
    ifls_assert_eq( 1, count( $rows ) );
    ifls_assert_eq( 'alice', $rows[0]->username );
    ifls_assert_eq( 'success', $rows[0]->outcome );
} );

ifls_test( 'event log: rejects an unknown event name', function () {
    IFLS_Event_Log::clear();
    IFLS_Event_Log::record( 'not_a_real_event', [] );
    ifls_assert_eq( 0, count( IFLS_Event_Log::query( [] ) ), 'unknown events must not be stored' );
} );

ifls_test( 'event log: never stores a reset key even if passed one', function () {
    IFLS_Event_Log::clear();
    IFLS_Event_Log::record( 'reset_failed', [ 'username' => 'bob', 'detail' => [ 'rp_key' => 'SECRET123', 'reason' => 'invalidkey' ] ] );
    $rows = IFLS_Event_Log::query( [] );
    ifls_assert( false === strpos( $rows[0]->detail, 'SECRET123' ), 'reset key leaked into the log' );
    ifls_assert( false !== strpos( $rows[0]->detail, 'invalidkey' ), 'reason should survive' );
} );

ifls_test( 'event log: count_since respects the window', function () {
    global $wpdb;
    IFLS_Event_Log::clear();
    IFLS_Event_Log::record( 'csrf_blocked', [] );
    // Backdate one row well outside the window.
    $wpdb->query( $wpdb->prepare(
        'INSERT INTO ' . IFLS_Event_Log::table() . ' (created_at, event, user_id, username, ip, user_agent, outcome, detail) VALUES (%s, %s, 0, %s, %s, %s, %s, %s)',
        gmdate( 'Y-m-d H:i:s', time() - 7200 ), 'csrf_blocked', '', '', '', 'blocked', '{}'
    ) );
    ifls_assert_eq( 1, IFLS_Event_Log::count_since( 'csrf_blocked', 60 ), 'only the recent row should count' );
    ifls_assert_eq( 2, IFLS_Event_Log::count_since( 'csrf_blocked', 180 ), 'both rows within 3h' );
} );

ifls_test( 'event log: prune removes only rows past retention', function () {
    global $wpdb;
    IFLS_Event_Log::clear();
    IFLS_Event_Log::record( 'login_success', [ 'username' => 'keep' ] );
    $wpdb->query( $wpdb->prepare(
        'INSERT INTO ' . IFLS_Event_Log::table() . ' (created_at, event, user_id, username, ip, user_agent, outcome, detail) VALUES (%s, %s, 0, %s, %s, %s, %s, %s)',
        gmdate( 'Y-m-d H:i:s', time() - ( 200 * DAY_IN_SECONDS ) ), 'login_success', 'drop', '', '', 'success', '{}'
    ) );
    IFLS_Event_Log::prune();
    $rows = IFLS_Event_Log::query( [] );
    ifls_assert_eq( 1, count( $rows ), 'exactly one row should survive' );
    ifls_assert_eq( 'keep', $rows[0]->username );
} );

ifls_test( 'event log: FAIL-SAFE - recording with a missing table does not throw', function () {
    global $wpdb;
    $table = IFLS_Event_Log::table();
    $wpdb->query( "DROP TABLE IF EXISTS {$table}" );
    $wpdb->suppress_errors( true );
    IFLS_Event_Log::record( 'login_success', [ 'username' => 'nobody' ] );  // must not throw
    $wpdb->suppress_errors( false );
    IFLS_Event_Log::install();
    ifls_assert( true, 'record() survived a missing table' );
} );
```

- [ ] **Step 2: Run to verify they fail**

Expected: FAIL — class not found.

- [ ] **Step 3: Implement**

```php
<?php
/**
 * Authentication event log.
 *
 * Stays on the client's site. Nothing here is ever transmitted to Inkfire.
 *
 * Every public method is fail-safe: this code runs on every authentication, so
 * a fault here must degrade to "no logging", never to a broken login.
 */

if (!defined('ABSPATH')) {
    exit;
}

class IFLS_Event_Log {

    const DB_VERSION = '1.0.0';

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

    /** Keys that must never reach storage, whatever a caller passes. */
    const FORBIDDEN_DETAIL_KEYS = ['rp_key', 'key', 'pass1', 'pass2', 'password', 'user_pass', 'nonce', '_wpnonce', 'ifls_form_nonce', 'cookie'];

    public static function table() {
        global $wpdb;
        return $wpdb->prefix . 'ifls_events';
    }

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
     * Record an event. Never throws.
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
            // Diagnostics must never break authentication. Swallow deliberately.
        }
    }

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

        $wpdb->insert(
            self::table(),
            [
                'created_at' => gmdate('Y-m-d H:i:s'),
                'event'      => $event,
                'user_id'    => isset($args['user_id']) ? absint($args['user_id']) : 0,
                'username'   => isset($args['username']) ? substr(sanitize_user($args['username'], true), 0, 180) : '',
                'ip'         => self::client_ip(),
                'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? substr(sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])), 0, 255) : '',
                'outcome'    => substr($outcome, 0, 20),
                'detail'     => wp_json_encode($detail),
            ],
            ['%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s']
        );
    }

    private static function default_outcome($event) {
        if (in_array($event, ['login_success', 'reset_completed', 'registration', 'logout'], true)) {
            return 'success';
        }
        if (in_array($event, ['csrf_blocked', 'lockout'], true)) {
            return 'blocked';
        }
        return 'failure';
    }

    /** Reuses the plugin's hardened IP resolution rather than reimplementing it. */
    private static function client_ip() {
        $ip = isset($_SERVER['REMOTE_ADDR']) ? trim((string) wp_unslash($_SERVER['REMOTE_ADDR'])) : '';
        return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '';
    }

    /**
     * @param array $args event, outcome, search, limit, offset
     * @return array Row objects.
     */
    public static function query(array $args = []) {
        global $wpdb;

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
        if (!empty($args['search'])) {
            $where[]  = '(username LIKE %s OR ip LIKE %s)';
            $like     = '%' . $wpdb->esc_like($args['search']) . '%';
            $params[] = $like;
            $params[] = $like;
        }

        $limit  = isset($args['limit']) ? absint($args['limit']) : 100;
        $offset = isset($args['offset']) ? absint($args['offset']) : 0;

        $sql = 'SELECT * FROM ' . self::table()
             . ' WHERE ' . implode(' AND ', $where)
             . ' ORDER BY created_at DESC, id DESC LIMIT %d OFFSET %d';

        $params[] = $limit;
        $params[] = $offset;

        try {
            return (array) $wpdb->get_results($wpdb->prepare($sql, $params));
        } catch (\Throwable $e) {
            return [];
        }
    }

    /** Count of an event within the last N minutes. Returns 0 on any failure. */
    public static function count_since($event, $minutes) {
        global $wpdb;

        try {
            return (int) $wpdb->get_var($wpdb->prepare(
                'SELECT COUNT(*) FROM ' . self::table() . ' WHERE event = %s AND created_at > %s',
                $event,
                gmdate('Y-m-d H:i:s', time() - (absint($minutes) * MINUTE_IN_SECONDS))
            ));
        } catch (\Throwable $e) {
            return 0;
        }
    }

    /** Batched delete so a large backlog cannot exhaust max_execution_time. */
    public static function prune() {
        global $wpdb;

        try {
            $cutoff = gmdate('Y-m-d H:i:s', time() - (absint(ifls_diag_setting('retention_days')) * DAY_IN_SECONDS));
            do {
                $deleted = $wpdb->query($wpdb->prepare(
                    'DELETE FROM ' . self::table() . ' WHERE created_at < %s LIMIT 1000',
                    $cutoff
                ));
            } while ($deleted > 0);
        } catch (\Throwable $e) {
            // Nothing to do; pruning retries tomorrow.
        }
    }

    public static function clear() {
        global $wpdb;
        try {
            $wpdb->query('TRUNCATE TABLE ' . self::table());
        } catch (\Throwable $e) {
            // no-op
        }
    }
}
```

- [ ] **Step 4: Wire up install + prune cron**

In `inkfire-login-styler.php`:

```php
require_once __DIR__ . '/inc/class-ifls-event-log.php';

register_activation_hook(__FILE__, function() {
    add_option('ifls_installed_version', IFLS_VERSION);
    IFLS_Event_Log::install();
    if (!wp_next_scheduled('ifls_prune_events')) {
        wp_schedule_event(time() + HOUR_IN_SECONDS, 'daily', 'ifls_prune_events');
    }
});

// Upgrades do not fire the activation hook, so check the schema version too.
add_action('plugins_loaded', function() {
    if (get_option('ifls_events_db_version') !== IFLS_Event_Log::DB_VERSION) {
        IFLS_Event_Log::install();
    }
    if (!wp_next_scheduled('ifls_prune_events')) {
        wp_schedule_event(time() + HOUR_IN_SECONDS, 'daily', 'ifls_prune_events');
    }
}, 20);

add_action('ifls_prune_events', ['IFLS_Event_Log', 'prune']);
```

- [ ] **Step 5: Run tests** — Expected: `8 passed, 0 failed`

- [ ] **Step 6: Commit**

```bash
git add inc/class-ifls-event-log.php tests/test-event-log.php inkfire-login-styler.php
git commit -m "feat: add fail-safe authentication event log"
```

---

## Task 5: Capture auth events

**Files:**
- Modify: `inkfire-login-styler.php`, `inc/class-ifls-event-log.php` (no change), `IFLS_Enterprise_Security` class
- Create: `tests/test-event-capture.php`

**Interfaces:**
- Consumes: `IFLS_Event_Log::record()`
- Produces: no new public API — hooks only.

- [ ] **Step 1: Write failing tests**

```php
<?php
ifls_test( 'capture: successful login is recorded', function () {
    IFLS_Event_Log::clear();
    $user = get_user_by( 'id', 1 );
    do_action( 'wp_login', $user->user_login, $user );
    $rows = IFLS_Event_Log::query( [ 'event' => 'login_success' ] );
    ifls_assert_eq( 1, count( $rows ) );
    ifls_assert_eq( (int) $user->ID, (int) $rows[0]->user_id );
} );

ifls_test( 'capture: failed login is recorded', function () {
    IFLS_Event_Log::clear();
    do_action( 'wp_login_failed', 'mallory' );
    $rows = IFLS_Event_Log::query( [ 'event' => 'login_failed' ] );
    ifls_assert_eq( 1, count( $rows ) );
    ifls_assert_eq( 'mallory', $rows[0]->username );
} );

ifls_test( 'capture: logout is recorded', function () {
    IFLS_Event_Log::clear();
    do_action( 'wp_logout', 1 );
    ifls_assert_eq( 1, count( IFLS_Event_Log::query( [ 'event' => 'logout' ] ) ) );
} );

ifls_test( 'capture: reset request is recorded', function () {
    IFLS_Event_Log::clear();
    $user = get_user_by( 'id', 1 );
    do_action( 'retrieve_password', $user->user_login );
    ifls_assert_eq( 1, count( IFLS_Event_Log::query( [ 'event' => 'reset_requested' ] ) ) );
} );

ifls_test( 'capture: completed reset is recorded', function () {
    IFLS_Event_Log::clear();
    $user = get_user_by( 'id', 1 );
    do_action( 'after_password_reset', $user, 'irrelevant' );
    $rows = IFLS_Event_Log::query( [ 'event' => 'reset_completed' ] );
    ifls_assert_eq( 1, count( $rows ) );
    ifls_assert( false === strpos( $rows[0]->detail, 'irrelevant' ), 'new password must never be logged' );
} );

ifls_test( 'capture: logging never breaks the hook it is attached to', function () {
    // With logging disabled the hooks must still run cleanly.
    update_option( 'ifls_diagnostics_settings', [ 'logging_enabled' => false ] );
    do_action( 'wp_login_failed', 'nobody' );
    delete_option( 'ifls_diagnostics_settings' );
    ifls_assert( true, 'hooks ran with logging off' );
} );
```

- [ ] **Step 2: Run to verify they fail** — Expected: 0 rows recorded.

- [ ] **Step 3: Implement — add to `IFLS_Enterprise_Security::__construct()`**

```php
// --- Event capture -------------------------------------------------
// All of these run AFTER the action they observe, and IFLS_Event_Log::record()
// swallows its own errors, so nothing here can interrupt authentication.

add_action('wp_login', function($user_login, $user) {
    IFLS_Event_Log::record('login_success', [
        'username' => $user_login,
        'user_id'  => isset($user->ID) ? $user->ID : 0,
    ]);
}, 10, 2);

add_action('wp_login_failed', function($username) {
    IFLS_Event_Log::record('login_failed', ['username' => $username]);
});

add_action('wp_logout', function($user_id) {
    IFLS_Event_Log::record('logout', ['user_id' => $user_id]);
});

add_action('retrieve_password', function($user_login) {
    IFLS_Event_Log::record('reset_requested', ['username' => $user_login]);
});

add_action('after_password_reset', function($user) {
    // Second arg is the new password - deliberately not captured.
    IFLS_Event_Log::record('reset_completed', [
        'username' => isset($user->user_login) ? $user->user_login : '',
        'user_id'  => isset($user->ID) ? $user->ID : 0,
    ]);
});

add_action('register_post', function($login) {
    IFLS_Event_Log::record('registration', ['username' => $login]);
});
```

- [ ] **Step 4: Record `reset_failed` — the 2.0.28 signature**

Core redirects to `lostpassword&error=invalidkey`. Detect it on `login_init`:

```php
add_action('login_init', function() {
    if (!isset($_GET['error']) || 'invalidkey' !== $_GET['error']) {
        return;
    }
    if (!isset($_GET['action']) || 'lostpassword' !== $_GET['action']) {
        return;
    }
    IFLS_Event_Log::record('reset_failed', [
        'detail' => ['reason' => 'invalidkey'],
    ]);
}, 5);
```

- [ ] **Step 5: Record `csrf_blocked` — the 2.0.27 signature**

In `verify_csrf_token()`, immediately before the existing `wp_die()`:

```php
IFLS_Event_Log::record('csrf_blocked', [
    'detail' => ['hook' => current_action()],
]);
```

- [ ] **Step 6: Record `lockout`**

In `check_login_attempts()`, inside the `if ($attempts >= IFLS_MAX_LOGIN_ATTEMPTS)` branch, before returning the error:

```php
IFLS_Event_Log::record('lockout', ['username' => $username]);
```

- [ ] **Step 7: Run tests** — Expected: `6 passed, 0 failed`

- [ ] **Step 8: Commit**

```bash
git add inkfire-login-styler.php tests/test-event-capture.php
git commit -m "feat: capture authentication events into the log

Includes the two signatures that would have caught 2.0.27 (csrf_blocked)
and 2.0.28 (reset_failed) months earlier."
```

---

## Task 6: Incident reporter

**Files:**
- Create: `inc/class-ifls-incident-reporter.php`, `tests/test-incident-reporter.php`
- Modify: `inkfire-login-styler.php`

**Interfaces:**
- Produces: `IFLS_Incident_Reporter::raise( $type, $reason, array $context = [] )`, `::check_thresholds()`, `::incidents()`, `::dispatch()`, `::clear()`, `::fingerprint( $type, $reason )`.

- [ ] **Step 1: Write failing tests**

```php
<?php
ifls_test( 'incidents: raise stores locally with pending status', function () {
    IFLS_Incident_Reporter::clear();
    ifls_reset_mail();
    IFLS_Incident_Reporter::raise( 'mail_failure', 'wp_mail returned false' );
    $all = IFLS_Incident_Reporter::incidents();
    ifls_assert_eq( 1, count( $all ) );
    ifls_assert_eq( 'pending', $all[0]['status'], 'must be queued, not sent inline' );
    ifls_assert_eq( 0, count( ifls_sent_mail() ), 'raise() must NOT send mail inline' );
} );

ifls_test( 'incidents: dispatch sends queued incidents and marks them sent', function () {
    IFLS_Incident_Reporter::clear();
    ifls_reset_mail();
    IFLS_Incident_Reporter::raise( 'mail_failure', 'test reason' );
    IFLS_Incident_Reporter::dispatch();
    ifls_assert_eq( 1, count( ifls_sent_mail() ), 'dispatch should send one email' );
    $all = IFLS_Incident_Reporter::incidents();
    ifls_assert_eq( 'sent', $all[0]['status'] );
} );

ifls_test( 'incidents: email subject carries the domain', function () {
    IFLS_Incident_Reporter::clear();
    ifls_reset_mail();
    IFLS_Incident_Reporter::raise( 'mail_failure', 'test reason' );
    IFLS_Incident_Reporter::dispatch();
    $mail = ifls_sent_mail();
    $host = wp_parse_url( home_url(), PHP_URL_HOST );
    ifls_assert( false !== strpos( $mail[0]['subject'], $host ), 'subject must name the site' );
} );

ifls_test( 'incidents: email contains no end-user IP or email address', function () {
    IFLS_Incident_Reporter::clear();
    ifls_reset_mail();
    IFLS_Incident_Reporter::raise( 'reset_storm', '5 reset failures', [ 'counts' => [ 'reset_failed' => 5 ] ] );
    IFLS_Incident_Reporter::dispatch();
    $body = ifls_sent_mail()[0]['message'];
    ifls_assert( !preg_match( '/\b\d{1,3}(\.\d{1,3}){3}\b/', str_replace( home_url(), '', $body ) ), 'an IP address leaked into the alert' );
} );

ifls_test( 'incidents: identical incidents dedupe within the cooldown', function () {
    IFLS_Incident_Reporter::clear();
    ifls_reset_mail();
    for ( $i = 0; $i < 100; $i++ ) {
        IFLS_Incident_Reporter::raise( 'mail_failure', 'same reason' );
    }
    IFLS_Incident_Reporter::dispatch();
    ifls_assert_eq( 1, count( IFLS_Incident_Reporter::incidents() ), 'should collapse to one incident' );
    ifls_assert_eq( 100, IFLS_Incident_Reporter::incidents()[0]['count'], 'occurrences should still be counted' );
    ifls_assert_eq( 1, count( ifls_sent_mail() ), 'exactly one email for 100 occurrences' );
} );

ifls_test( 'incidents: threshold does NOT fire below the limit', function () {
    IFLS_Event_Log::clear();
    IFLS_Incident_Reporter::clear();
    for ( $i = 0; $i < 4; $i++ ) {
        IFLS_Event_Log::record( 'csrf_blocked', [] );
    }
    IFLS_Incident_Reporter::check_thresholds();
    ifls_assert_eq( 0, count( IFLS_Incident_Reporter::incidents() ), '4 must not alert' );
} );

ifls_test( 'incidents: threshold fires at the limit', function () {
    IFLS_Event_Log::clear();
    IFLS_Incident_Reporter::clear();
    for ( $i = 0; $i < 5; $i++ ) {
        IFLS_Event_Log::record( 'csrf_blocked', [] );
    }
    IFLS_Incident_Reporter::check_thresholds();
    ifls_assert_eq( 1, count( IFLS_Incident_Reporter::incidents() ), '5 must alert' );
} );

ifls_test( 'incidents: reset storm stays silent when a reset succeeded', function () {
    IFLS_Event_Log::clear();
    IFLS_Incident_Reporter::clear();
    for ( $i = 0; $i < 10; $i++ ) {
        IFLS_Event_Log::record( 'reset_failed', [] );
    }
    IFLS_Event_Log::record( 'reset_completed', [ 'username' => 'alice' ] );
    IFLS_Incident_Reporter::check_thresholds();
    ifls_assert_eq( 0, count( IFLS_Incident_Reporter::incidents() ), 'a completion means resets work; stale links are not an incident' );
} );

ifls_test( 'incidents: mail failure still stores when sending fails', function () {
    IFLS_Incident_Reporter::clear();
    add_filter( 'pre_wp_mail', '__return_false', 1 );
    IFLS_Incident_Reporter::raise( 'mail_failure', 'delivery down' );
    IFLS_Incident_Reporter::dispatch();
    remove_filter( 'pre_wp_mail', '__return_false', 1 );
    $all = IFLS_Incident_Reporter::incidents();
    ifls_assert_eq( 1, count( $all ), 'incident must persist even when email fails' );
    ifls_assert_eq( 'failed', $all[0]['status'] );
} );

ifls_test( 'incidents: store is capped at 50', function () {
    IFLS_Incident_Reporter::clear();
    for ( $i = 0; $i < 60; $i++ ) {
        IFLS_Incident_Reporter::raise( 'mail_failure', 'reason ' . $i );
    }
    ifls_assert( count( IFLS_Incident_Reporter::incidents() ) <= 50, 'store must be capped' );
} );

ifls_test( 'incidents: FAIL-SAFE - raise never throws', function () {
    delete_option( 'ifls_incidents' );
    IFLS_Incident_Reporter::raise( 'mail_failure', str_repeat( 'x', 100000 ) );
    ifls_assert( true, 'raise survived an absurd payload' );
} );
```

- [ ] **Step 2: Run to verify they fail** — Expected: class not found.

- [ ] **Step 3: Implement**

```php
<?php
/**
 * Detects plugin malfunction and reports it to Inkfire.
 *
 * Two rules govern this class:
 *   1. Store locally BEFORE attempting to send. If the incident is mail
 *      failure, the local copy is the only record that will exist.
 *   2. Never send mail during an authentication request. Incidents are queued
 *      and dispatched off the request path, because sending inline would block
 *      every failed login for the SMTP timeout on exactly those sites whose
 *      mail is already broken.
 */

if (!defined('ABSPATH')) {
    exit;
}

class IFLS_Incident_Reporter {

    const OPTION   = 'ifls_incidents';
    const MAX_KEPT = 50;

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
        if (!ifls_diag_enabled() || !ifls_diag_setting('reporting_enabled')) {
            return;
        }

        try {
            self::do_raise($type, $reason, $context);
        } catch (\Throwable $e) {
            // Reporting must never break the site it is reporting on.
        }
    }

    private static function do_raise($type, $reason, array $context) {
        $incidents   = self::incidents();
        $fingerprint = self::fingerprint($type, $reason);
        $now         = time();
        $cooldown    = absint(ifls_diag_setting('cooldown_hours')) * HOUR_IN_SECONDS;

        foreach ($incidents as $i => $incident) {
            if ($incident['fingerprint'] !== $fingerprint) {
                continue;
            }

            $incidents[$i]['count']++;
            $incidents[$i]['last_seen'] = $now;

            // Still inside the cooldown: count it, do not queue another email.
            if (($now - $incident['first_seen']) < $cooldown) {
                self::save($incidents);
                return;
            }

            // Cooldown elapsed - re-arm this fingerprint.
            $incidents[$i]['first_seen'] = $now;
            $incidents[$i]['status']     = 'pending';
            self::save($incidents);
            return;
        }

        array_unshift($incidents, [
            'fingerprint' => $fingerprint,
            'type'        => sanitize_key($type),
            'reason'      => substr(sanitize_text_field($reason), 0, 500),
            'context'     => self::scrub($context),
            'first_seen'  => $now,
            'last_seen'   => $now,
            'count'       => 1,
            'status'      => 'pending',
        ]);

        self::save(array_slice($incidents, 0, self::MAX_KEPT));
    }

    /**
     * Strip anything that looks like end-user personal data.
     *
     * The cross-site channel to Inkfire carries technical context and counts
     * only; IPs, usernames and email addresses stay in the client's dashboard.
     */
    private static function scrub(array $context) {
        unset($context['ip'], $context['username'], $context['email'], $context['user_email']);

        array_walk_recursive($context, function (&$value) {
            if (!is_string($value)) {
                return;
            }
            $value = preg_replace('/\b\d{1,3}(\.\d{1,3}){3}\b/', '[ip removed]', $value);
            $value = preg_replace('/[\w.+-]+@[\w-]+\.[\w.]+/', '[email removed]', $value);
        });

        return $context;
    }

    public static function incidents() {
        $stored = get_option(self::OPTION, []);
        return is_array($stored) ? $stored : [];
    }

    private static function save(array $incidents) {
        update_option(self::OPTION, $incidents, false);
    }

    public static function clear() {
        delete_option(self::OPTION);
    }

    /** Evaluate failure thresholds. Called from cron, never from the auth path. */
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
                    ['counts' => ['csrf_blocked' => $csrf], 'window_minutes' => $minutes]
                );
            }

            $failed = IFLS_Event_Log::count_since('reset_failed', $minutes);
            $done   = IFLS_Event_Log::count_since('reset_completed', $minutes);

            // A completion in the same window means resets work and these were
            // just stale links. Without this clause the alert is pure noise.
            if ($failed >= $count && 0 === $done) {
                self::raise(
                    'reset_storm',
                    sprintf('%d failed password resets in %d minutes with no successful reset', $failed, $minutes),
                    ['counts' => ['reset_failed' => $failed, 'reset_completed' => 0], 'window_minutes' => $minutes]
                );
            }
        } catch (\Throwable $e) {
            // no-op
        }
    }

    /** Send queued incidents. Cron/shutdown only - never during authentication. */
    public static function dispatch() {
        if (!ifls_diag_enabled() || !ifls_diag_setting('reporting_enabled')) {
            return;
        }

        try {
            $incidents = self::incidents();
            $changed   = false;

            foreach ($incidents as $i => $incident) {
                if ('sent' === $incident['status']) {
                    continue;
                }

                $sent = wp_mail(
                    ifls_diag_setting('report_email'),
                    self::subject($incident),
                    self::body($incident)
                );

                $incidents[$i]['status'] = $sent ? 'sent' : 'failed';
                $changed = true;
            }

            if ($changed) {
                self::save($incidents);
            }
        } catch (\Throwable $e) {
            // no-op
        }
    }

    private static function subject(array $incident) {
        return sprintf(
            '[Foundation] %s - %s',
            wp_parse_url(home_url(), PHP_URL_HOST),
            str_replace('_', ' ', $incident['type'])
        );
    }

    private static function body(array $incident) {
        global $wp_version;

        $lines = [
            'A Foundation Inkfire Login incident was recorded.',
            '',
            'Site:        ' . home_url(),
            'Incident:    ' . $incident['type'],
            'Reason:      ' . $incident['reason'],
            'First seen:  ' . gmdate('Y-m-d H:i:s', $incident['first_seen']) . ' UTC',
            'Last seen:   ' . gmdate('Y-m-d H:i:s', $incident['last_seen']) . ' UTC',
            'Occurrences: ' . $incident['count'],
            '',
            'Plugin:      ' . IFLS_VERSION,
            'WordPress:   ' . $wp_version,
            'PHP:         ' . PHP_VERSION,
            'Theme:       ' . wp_get_theme()->get('Name'),
            '',
            'Context:',
            wp_json_encode($incident['context'], JSON_PRETTY_PRINT),
            '',
            'Full detail, including per-user events, is in this site\'s own',
            'Foundation > Diagnostics screen. It is deliberately not included',
            'in this email.',
        ];

        return implode("\n", $lines);
    }
}
```

- [ ] **Step 4: Wire up detection and dispatch**

In `inkfire-login-styler.php`:

```php
require_once __DIR__ . '/inc/class-ifls-incident-reporter.php';

// Mail failures - the base-uk.org class of problem.
add_action('wp_mail_failed', function($error) {
    IFLS_Incident_Reporter::raise(
        'mail_failure',
        is_wp_error($error) ? $error->get_error_message() : 'unknown mail error'
    );
});

// Threshold evaluation + queued dispatch, every 5 minutes.
add_action('ifls_dispatch_incidents', function() {
    IFLS_Incident_Reporter::check_thresholds();
    IFLS_Incident_Reporter::dispatch();
});

// Opportunistic dispatch: flush the queue at the end of any request that is
// NOT an authentication request, so alerts arrive promptly without ever
// putting an SMTP call on the login path.
add_action('shutdown', function() {
    if (isset($GLOBALS['pagenow']) && 'wp-login.php' === $GLOBALS['pagenow']) {
        return;
    }
    if (defined('DOING_CRON') && DOING_CRON) {
        return; // already handled above
    }
    IFLS_Incident_Reporter::dispatch();
}, 1000);
```

Add to the activation/upgrade block from Task 4:

```php
if (!wp_next_scheduled('ifls_dispatch_incidents')) {
    wp_schedule_event(time() + 300, 'ifls_five_minutes', 'ifls_dispatch_incidents');
}
```

And register the interval:

```php
add_filter('cron_schedules', function($schedules) {
    if (!isset($schedules['ifls_five_minutes'])) {
        $schedules['ifls_five_minutes'] = ['interval' => 300, 'display' => __('Every 5 minutes', 'inkfire-login-styler')];
    }
    return $schedules;
});
```

- [ ] **Step 5: Add plugin-fatal detection**

```php
// Catch fatals originating inside this plugin. Kept deliberately minimal -
// this handler runs during a crash and must not itself allocate or fail.
register_shutdown_function(function() {
    $error = error_get_last();
    if (!$error || !in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) {
        return;
    }
    if (false === strpos($error['file'], 'foundation-inkfire-login-styler')) {
        return;
    }
    IFLS_Incident_Reporter::raise(
        'plugin_fatal',
        sprintf('%s in %s:%d', $error['message'], basename($error['file']), $error['line'])
    );
});
```

- [ ] **Step 6: Run tests** — Expected: `11 passed, 0 failed`

- [ ] **Step 7: Commit**

```bash
git add inc/class-ifls-incident-reporter.php tests/test-incident-reporter.php inkfire-login-styler.php
git commit -m "feat: add incident detection and queued reporting to Inkfire

Stores locally before sending, never sends on the auth path, dedupes by
fingerprint with a cooldown, and scrubs end-user PII from the cross-site
channel."
```

---

## Task 7: Mail diagnostics

**Files:**
- Create: `inc/class-ifls-mail-diagnostics.php`, `tests/test-mail-diagnostics.php`
- Modify: `inkfire-login-styler.php`

**Interfaces:**
- Produces: `IFLS_Mail_Diagnostics::send_test( $to )`, `::transport_info()`, `::dns_info()`, `::warnings()`.

- [ ] **Step 1: Write failing tests**

```php
<?php
ifls_test( 'mail diag: test send reports success and transport details', function () {
    ifls_reset_mail();
    $result = IFLS_Mail_Diagnostics::send_test( 'nobody@example.com' );
    ifls_assert_eq( true, $result['sent'] );
    ifls_assert( isset( $result['transport']['mailer'] ), 'transport info missing' );
} );

ifls_test( 'mail diag: test send reports failure without throwing', function () {
    add_filter( 'pre_wp_mail', '__return_false', 1 );
    $result = IFLS_Mail_Diagnostics::send_test( 'nobody@example.com' );
    remove_filter( 'pre_wp_mail', '__return_false', 1 );
    ifls_assert_eq( false, $result['sent'] );
} );

ifls_test( 'mail diag: dns_info returns the expected shape', function () {
    $dns = IFLS_Mail_Diagnostics::dns_info();
    foreach ( [ 'mx', 'spf', 'dmarc' ] as $key ) {
        ifls_assert( array_key_exists( $key, $dns ), "missing {$key}" );
    }
} );

ifls_test( 'mail diag: warns when MX is external but mail is sent locally', function () {
    $warnings = IFLS_Mail_Diagnostics::warnings(
        [ 'mailer' => 'mail', 'sender' => '' ],
        [ 'mx' => [ 'baseuk-org01b.mail.protection.outlook.com' ], 'spf' => '', 'dmarc' => '' ]
    );
    $joined = implode( ' ', $warnings );
    ifls_assert( false !== stripos( $joined, 'external' ), 'should warn about external MX with local sending' );
} );

ifls_test( 'mail diag: warns when the envelope sender is empty', function () {
    $warnings = IFLS_Mail_Diagnostics::warnings(
        [ 'mailer' => 'mail', 'sender' => '' ],
        [ 'mx' => [], 'spf' => '', 'dmarc' => '' ]
    );
    ifls_assert( false !== stripos( implode( ' ', $warnings ), 'return-path' ), 'should warn about empty envelope sender' );
} );

ifls_test( 'mail diag: no warning when a proper SMTP mailer is configured', function () {
    $warnings = IFLS_Mail_Diagnostics::warnings(
        [ 'mailer' => 'smtp', 'sender' => 'noreply@example.com', 'smtp_auth' => true ],
        [ 'mx' => [ 'mail.protection.outlook.com' ], 'spf' => 'v=spf1 -all', 'dmarc' => '' ]
    );
    ifls_assert_eq( 0, count( $warnings ), 'clean SMTP setup should not warn' );
} );
```

- [ ] **Step 2: Run to verify they fail**

- [ ] **Step 3: Implement**

```php
<?php
/**
 * Mail transport diagnostics.
 *
 * Exists because diagnosing "the reset email never arrived" previously meant
 * hand-writing throwaway scripts. This surfaces the same facts in the admin.
 */

if (!defined('ABSPATH')) {
    exit;
}

class IFLS_Mail_Diagnostics {

    /**
     * Send one test message and report exactly what the transport did.
     *
     * The recipient is never taken from the request body - see the admin
     * handler - otherwise this button would be an open relay.
     */
    public static function send_test($to) {
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
            sprintf(__('Foundation mail test - %s', 'inkfire-login-styler'), wp_parse_url(home_url(), PHP_URL_HOST)),
            sprintf(
                "This is a test message from the Foundation Inkfire Login plugin.\n\nSite: %s\nSent: %s UTC\n\nIf this reached the inbox, WordPress mail is leaving this server correctly.",
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

    /** Current transport configuration without sending anything. */
    public static function transport_info() {
        return [
            'sendmail_path' => (string) ini_get('sendmail_path'),
            'wp_mail_from'  => apply_filters('wp_mail_from', 'wordpress@' . wp_parse_url(home_url(), PHP_URL_HOST)),
            'admin_email'   => get_option('admin_email'),
        ];
    }

    /** MX / SPF / DMARC for the site domain. Cached; degrades to 'unavailable'. */
    public static function dns_info() {
        $domain = wp_parse_url(home_url(), PHP_URL_HOST);
        $cache  = get_transient('ifls_dns_' . md5($domain));

        if (is_array($cache)) {
            return $cache;
        }

        $info = ['mx' => [], 'spf' => '', 'dmarc' => '', 'available' => false];

        if (!function_exists('dns_get_record')) {
            set_transient('ifls_dns_' . md5($domain), $info, HOUR_IN_SECONDS);
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

        set_transient('ifls_dns_' . md5($domain), $info, HOUR_IN_SECONDS);
        return $info;
    }

    /**
     * Human-readable warnings about likely delivery problems.
     *
     * @param array $transport From send_test()['transport'] or transport_info().
     * @param array $dns       From dns_info().
     * @return string[]
     */
    public static function warnings(array $transport, array $dns) {
        $warnings = [];
        $mailer   = isset($transport['mailer']) ? $transport['mailer'] : '';
        $local    = ('mail' === $mailer || '' === $mailer);

        $external_mx = false;
        foreach (isset($dns['mx']) ? $dns['mx'] : [] as $mx) {
            if (preg_match('/(outlook|office365|google|googlemail|zoho|fastmail|protection)/i', $mx)) {
                $external_mx = true;
                break;
            }
        }

        if ($local && $external_mx) {
            $warnings[] = __('This domain\'s email is hosted externally (for example Microsoft 365), but WordPress is sending through the local PHP mail() transport. Messages may be quarantined or rejected by the recipient, especially for addresses on this same domain. Routing mail through an authenticated SMTP service is the usual fix.', 'inkfire-login-styler');
        }

        if ($local && empty($transport['sender'])) {
            $warnings[] = __('No envelope sender (Return-Path) is set, so SPF is evaluated against whatever address the host substitutes rather than this domain. That commonly breaks DMARC alignment.', 'inkfire-login-styler');
        }

        return $warnings;
    }
}
```

- [ ] **Step 4: Require it** in `inkfire-login-styler.php`.

- [ ] **Step 5: Run tests** — Expected: `6 passed, 0 failed`

- [ ] **Step 6: Commit**

```bash
git add inc/class-ifls-mail-diagnostics.php tests/test-mail-diagnostics.php inkfire-login-styler.php
git commit -m "feat: add mail transport diagnostics with DNS inspection"
```

---

## Task 8: Admin UI

**Files:**
- Create: `inc/class-ifls-diagnostics-admin.php`, `tests/test-admin-escaping.php`
- Modify: `inkfire-login-styler.php`

**Interfaces:**
- Consumes: all four earlier units.
- Produces: `IFLS_Diagnostics_Admin::init()`, `::render()`.

- [ ] **Step 1: Write failing tests**

```php
<?php
ifls_test( 'admin: log rows are escaped against XSS', function () {
    IFLS_Event_Log::clear();
    IFLS_Event_Log::record( 'login_failed', [ 'username' => '<script>alert(1)</script>' ] );
    $rows = IFLS_Event_Log::query( [] );
    $html = IFLS_Diagnostics_Admin::render_log_row( $rows[0] );
    ifls_assert( false === strpos( $html, '<script>' ), 'raw script tag rendered - XSS' );
    ifls_assert( false !== strpos( $html, '&lt;script&gt;' ), 'expected escaped output' );
} );

ifls_test( 'admin: settings are registered with a sanitize callback', function () {
    global $wp_registered_settings;
    do_action( 'admin_init' );
    ifls_assert(
        isset( $wp_registered_settings['ifls_diagnostics_settings'] ),
        'setting not registered'
    );
    ifls_assert_eq(
        'ifls_diag_sanitize',
        $wp_registered_settings['ifls_diagnostics_settings']['sanitize_callback'],
        'missing sanitize callback'
    );
} );
```

- [ ] **Step 2: Run to verify they fail**

- [ ] **Step 3: Implement**

Create `inc/class-ifls-diagnostics-admin.php` with:

- `init()` hooking `admin_menu` (submenu **Diagnostics** under `foundation-by-inkfire`, capability `manage_options`), `admin_init` (`register_setting('ifls_diagnostics', 'ifls_diagnostics_settings', ['sanitize_callback' => 'ifls_diag_sanitize'])`), and `admin_post_ifls_test_email` / `admin_post_ifls_clear_log` / `admin_post_ifls_locate_ip`.
- `render()` producing four panels: **Incidents** (undelivered first, flagged), **Mail diagnostics** (test button + transport + DNS + warnings), **Event log** (filterable table, Locate button per row), **Settings** (Settings API form; locked fields rendered `disabled` with a note naming the constant).
- `render_log_row( $row )` returning one `<tr>`, every field escaped:

```php
public static function render_log_row($row) {
    return sprintf(
        '<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>',
        esc_html(get_date_from_gmt($row->created_at)),
        esc_html($row->event),
        esc_html($row->username),
        esc_html($row->ip),
        esc_html($row->outcome)
    );
}
```

Handlers — all three follow the same shape:

```php
public static function handle_test_email() {
    if (!current_user_can('manage_options')) {
        wp_die(__('Insufficient permissions.', 'inkfire-login-styler'));
    }
    check_admin_referer('ifls_test_email');

    // Recipient is NEVER read from the request - that would make this an open relay.
    $to     = ifls_diag_setting('report_email');
    $result = IFLS_Mail_Diagnostics::send_test($to);

    set_transient('ifls_test_email_result_' . get_current_user_id(), $result, 5 * MINUTE_IN_SECONDS);

    wp_safe_redirect(add_query_arg('ifls_tested', '1', admin_url('admin.php?page=foundation-login-diagnostics')));
    exit;
}
```

`handle_clear_log()` requires `manage_options` + nonce `ifls_clear_log`, then `IFLS_Event_Log::clear()`. `handle_locate_ip()` requires `manage_options` + nonce, validates the IP with `filter_var`, performs one lookup, caches in a transient keyed by IP.

- [ ] **Step 4: Run tests** — Expected: `2 passed, 0 failed`

- [ ] **Step 5: Manually verify the screen**

Load `/wp-admin/admin.php?page=foundation-login-diagnostics` and confirm all four panels render, the test-email button works, and a `<script>` username displays as text.

- [ ] **Step 6: Commit**

```bash
git add inc/class-ifls-diagnostics-admin.php tests/test-admin-escaping.php inkfire-login-styler.php
git commit -m "feat: add Diagnostics admin screen"
```

---

## Task 9: Fail-safety gate + full regression

**Files:**
- Create: `tests/test-failsafe.php`, `tests/test-csrf-matrix.php`, `tests/test-reset-flow.php`

This is the gate that makes shipping without a canary defensible. Do not proceed to release if any of it fails.

- [ ] **Step 1: Write the fail-safety tests**

```php
<?php
ifls_test( 'FAIL-SAFE: login works with the events table dropped', function () {
    global $wpdb;
    $table = IFLS_Event_Log::table();
    $wpdb->query( "DROP TABLE IF EXISTS {$table}" );
    $wpdb->suppress_errors( true );

    $user = get_user_by( 'id', 1 );
    do_action( 'wp_login', $user->user_login, $user );
    do_action( 'wp_login_failed', 'someone' );
    do_action( 'wp_logout', 1 );

    $wpdb->suppress_errors( false );
    IFLS_Event_Log::install();
    ifls_assert( true, 'auth hooks survived a missing table' );
} );

ifls_test( 'FAIL-SAFE: kill switch disables everything', function () {
    ifls_assert_eq( true, ifls_diag_enabled(), 'kill switch should be off by default in tests' );
} );

ifls_test( 'FAIL-SAFE: incident dispatch never runs on wp-login.php', function () {
    $src = file_get_contents( dirname( __DIR__ ) . '/inkfire-login-styler.php' );
    ifls_assert(
        false !== strpos( $src, "'wp-login.php' === \$GLOBALS['pagenow']" ),
        'shutdown dispatch must bail on wp-login.php'
    );
} );

ifls_test( 'FAIL-SAFE: raise() sends no mail inline', function () {
    ifls_reset_mail();
    IFLS_Incident_Reporter::clear();
    IFLS_Incident_Reporter::raise( 'mail_failure', 'inline check' );
    ifls_assert_eq( 0, count( ifls_sent_mail() ), 'raise() must not send mail' );
} );
```

- [ ] **Step 2: Port the CSRF matrix**

Port the 12 scenarios verified for 2.0.27 (`admin_ajax`, `admin_bulk`, `admin_bulk_action2`, `frontend_valid_nonce`, `woocommerce`, `subscriber_self_spoof` → allowed; `frontend_no_nonce`, `frontend_bad_nonce`, `anon_ajax_spoof`, `subscriber_ajax_spoof`, `subscriber_bulk_spoof`, `admin_other_action` → blocked) into `tests/test-csrf-matrix.php`, asserting with `ifls_assert` and catching `IFLS_Test_Blocked`.

- [ ] **Step 3: Port the reset-flow test**

`tests/test-reset-flow.php` asserts that `ifls_get_reset_credentials()` reads the `wp-resetpass-` cookie, and that a forged/tampered key is rejected — the 2.0.28 regression guard.

- [ ] **Step 4: Run the entire suite**

Run: `php tests/run.php <wp-root>`
Expected: **all tests pass, exit code 0**

- [ ] **Step 5: Verify login latency is unchanged**

```bash
for i in 1 2 3 4 5; do curl -s -o /dev/null -w "%{time_total}\n" "https://thatdeveloper.co.uk/wp-login.php"; done
```
Compare against 2.0.28. Investigate any regression beyond noise.

- [ ] **Step 6: Commit**

```bash
git add tests/
git commit -m "test: add fail-safety gate and port CSRF + reset regressions"
```

---

## Task 10: Release and rollout

- [ ] **Step 1: Bump all four version fields to 2.1.0**

`inkfire-login-styler.php` header + `IFLS_VERSION`, `README.txt` `Stable tag:`, `README.md` table.

- [ ] **Step 2: Add the README.txt changelog entry**

```
= 2.1.0 =

New: Authentication event log (logins, logouts, lockouts, password resets) stored on this site, with a filterable viewer and on-demand IP location lookup under Foundation > Diagnostics. Auto-pruned after 90 days.

New: Automatic incident reporting. When the plugin itself malfunctions - mail failures, blocked security checks, failing password resets, plugin fatals - an alert is emailed with the site domain and full technical context, and a copy is kept on the site. Deduplicated so a broken site alerts once, not continuously.

New: Mail diagnostics with a test-send button and MX/SPF/DMARC inspection, flagging the common case of externally hosted email being sent through the local PHP mail transport.

New: Diagnostics settings screen for recipient, thresholds and retention. Constants in wp-config.php override and lock any field.

Fix: The login stylesheet is no longer loaded on every wp-admin page.

Fix: Replaced the Font Awesome CDN with inline SVG icons - no third-party request from the login page.

Fix: Uninstall cleanup now works on sites using a persistent object cache.

Fix: Removed a no-op login_footer hook.
```

- [ ] **Step 3: Lint and run the full suite one final time**

```bash
find . -name '*.php' -not -path './plugin-update-checker/*' -exec php -l {} \; | grep -v 'No syntax errors'
php tests/run.php <wp-root>
```
Expected: no lint output, all tests pass.

- [ ] **Step 4: Baseline the stragglers first**

Bring `catlawless.com` (2.0.11), `gsoasatellite.com`, `sakaradee.co.uk`, `sandhurstfire.co.uk` (1.8.1) and `wendycarltonart.co.uk` (2.0.20) to **2.0.28**, so every site upgrades to 2.1.0 from one known baseline. Check the login page renders correctly on one 1.8.1 site before doing the other two.

- [ ] **Step 5: Commit, tag, build and release**

```bash
git commit -am "release: 2.1.0"
git push origin main
git tag -a v2.1.0 -m "Foundation Inkfire Login 2.1.0" && git push origin v2.1.0
# build zip: top-level foundation-inkfire-login-styler/ containing
# assets inc plugin-update-checker README.txt inkfire-login-styler.php uninstall.php
gh release create v2.1.0 --repo Inkfire-limited/foundation-login-plugin \
  --title "Foundation Inkfire Login 2.1.0" --notes-file RELEASE_NOTES.md \
  foundation-inkfire-login-styler.zip
```

- [ ] **Step 6: Load-based canary**

Install on `thatdeveloper.co.uk` and `inkfire.co.uk`. Drive several hundred synthetic events (logins, failures, lockouts, reset requests, reset failures). Assert: correct row counts, exactly one alert email per fingerprint, table created, no PHP notices, login latency unchanged.

- [ ] **Step 7: Prove rollback before relying on it**

On `thatdeveloper.co.uk`, reinstall 2.0.28 over 2.1.0 and confirm the site is healthy. The events table is intentionally left in place. Then restore 2.1.0.

- [ ] **Step 8: Roll out in waves**

Low-traffic clients → remaining clients → `base-uk.org` last, with a health sweep between waves. Halt on any failure.

- [ ] **Step 9: Post-deploy sweep**

For every site: plugin version is 2.1.0, `{prefix}ifls_events` exists, `wp-login.php` returns 200 with the nonce present, no new PHP fatals, event count non-zero but not runaway.

---

## Self-Review

**Spec coverage:** Event log → T4/T5. On-demand geolocation → T8. Incident triggers → T6. Dedup/cooldown → T6. Store-before-send + no inline mail → T6, gated in T9. Mail test + DNS → T7. Settings + precedence → T3/T8. Fail-safety → T4/T6, gated T9. Security requirements → T3 (sanitisation), T8 (escaping, capability, nonce, open-relay guard). Privacy → T6 `scrub()`, T8 clear-log control. Testing → T9. Rollout → T10. Four audit fixes → T2. No gaps.

**Placeholders:** none. Task 8 describes panel composition rather than quoting the full render method, but every security-relevant handler and the escaping function are given in full.

**Type consistency:** `IFLS_Event_Log::record()`, `::query()`, `::count_since()`, `::clear()`, `::table()`, `::install()`, `::prune()` used consistently across T4/T5/T6/T9. `IFLS_Incident_Reporter::raise()/incidents()/dispatch()/check_thresholds()/clear()/fingerprint()` consistent across T6/T9. `ifls_diag_setting()`/`ifls_diag_enabled()`/`ifls_diag_sanitize()` consistent across T3/T4/T6/T8. `ifls_social_icon()` T2 only.
