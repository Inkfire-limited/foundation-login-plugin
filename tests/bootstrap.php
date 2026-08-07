<?php
/**
 * Test bootstrap for Foundation - Inkfire Login.
 *
 * Boots WordPress OUTSIDE WP-CLI on purpose. The plugin contains
 * `defined('WP_CLI') && WP_CLI` early-returns, so running these tests through
 * `wp eval` would silently skip the very code under test -- that blind spot is
 * how the 2.0.27 admin-reset bug survived command-line testing for months.
 *
 * Outbound mail is hard-blocked and captured, and wp_die() is converted into a
 * catchable exception so "this request should be rejected" is assertable.
 *
 * Usage: php tests/run.php /path/to/wordpress [filter]
 *
 * @package Inkfire_Login_Styler
 */

/**
 * Fake a real HTTP request and load WordPress.
 *
 * @param string $wp_root Absolute path to the WordPress root.
 * @param array  $context Optional: method, uri, ip.
 */
function ifls_test_boot( $wp_root, array $context = array() ) {
	$_SERVER['HTTP_HOST']       = 'localhost';
	$_SERVER['SERVER_NAME']     = 'localhost';
	$_SERVER['REQUEST_METHOD']  = isset( $context['method'] ) ? $context['method'] : 'GET';
	$_SERVER['REQUEST_URI']     = isset( $context['uri'] ) ? $context['uri'] : '/';
	$_SERVER['SCRIPT_NAME']     = $_SERVER['REQUEST_URI'];
	$_SERVER['PHP_SELF']        = $_SERVER['REQUEST_URI'];
	$_SERVER['REMOTE_ADDR']     = isset( $context['ip'] ) ? $context['ip'] : '127.0.0.1';
	$_SERVER['HTTP_USER_AGENT'] = 'IFLS-Test';

	$wp_load = rtrim( $wp_root, '/' ) . '/wp-load.php';

	if ( ! file_exists( $wp_load ) ) {
		fwrite( STDERR, "Cannot find wp-load.php at {$wp_load}\n" );
		exit( 2 );
	}

	require_once $wp_load;

	ifls_test_block_mail();
	ifls_test_catch_wp_die();
}

/**
 * Hard-block outbound mail and capture what would have been sent.
 *
 * Uses pre_wp_mail, which short-circuits before anything reaches the MTA, so
 * running the suite can never email a real person.
 */
function ifls_test_block_mail() {
	$GLOBALS['ifls_test_mail'] = array();
	$GLOBALS['ifls_test_mail_fails'] = false;

	// Runs at PHP_INT_MAX so nothing can re-enable real sending after it. That
	// also means a test cannot simulate failure with its own pre_wp_mail
	// filter, since this one would run last and win - use
	// ifls_force_mail_failure() instead.
	add_filter(
		'pre_wp_mail',
		function ( $null, $atts ) {
			$GLOBALS['ifls_test_mail'][] = $atts;
			return empty( $GLOBALS['ifls_test_mail_fails'] );
		},
		PHP_INT_MAX,
		2
	);
}

/**
 * Make wp_mail() report failure while still never sending anything.
 *
 * @param bool $fails Whether wp_mail() should return false.
 */
function ifls_force_mail_failure( $fails = true ) {
	$GLOBALS['ifls_test_mail_fails'] = (bool) $fails;
}

/**
 * Messages captured since the last reset.
 *
 * @return array
 */
function ifls_sent_mail() {
	return isset( $GLOBALS['ifls_test_mail'] ) ? $GLOBALS['ifls_test_mail'] : array();
}

/**
 * Clear the captured mail buffer.
 */
function ifls_reset_mail() {
	$GLOBALS['ifls_test_mail'] = array();
}

/**
 * Thrown in place of wp_die() so blocking behaviour can be asserted.
 */
class IFLS_Test_Blocked extends RuntimeException {}

/**
 * Convert every wp_die() handler into a thrown IFLS_Test_Blocked.
 */
function ifls_test_catch_wp_die() {
	$handler = function () {
		return function ( $message, $title = '', $args = array() ) {
			if ( is_wp_error( $message ) ) {
				$message = $message->get_error_message();
			}
			throw new IFLS_Test_Blocked( wp_strip_all_tags( (string) $message ) );
		};
	};

	$filters = array(
		'wp_die_handler',
		'wp_die_ajax_handler',
		'wp_die_json_handler',
		'wp_die_jsonp_handler',
		'wp_die_xmlrpc_handler',
		'wp_die_xml_handler',
	);

	foreach ( $filters as $filter ) {
		add_filter( $filter, $handler, PHP_INT_MAX );
	}
}
