<?php
/**
 * Proves the harness itself works before anything relies on it.
 *
 * @package Inkfire_Login_Styler
 */

ifls_test(
	'harness: WordPress booted',
	function () {
		ifls_assert( function_exists( 'wp_mail' ), 'WordPress not loaded' );
		ifls_assert( function_exists( 'add_filter' ), 'plugin API not loaded' );
	}
);

ifls_test(
	'harness: WP_CLI is NOT defined, so the plugin guards cannot mask bugs',
	function () {
		ifls_assert( ! defined( 'WP_CLI' ), 'WP_CLI is defined - plugin early-returns would hide the code under test' );
	}
);

ifls_test(
	'harness: the plugin under test is actually loaded',
	function () {
		ifls_assert( defined( 'IFLS_VERSION' ), 'plugin not active on the target site' );
	}
);

ifls_test(
	'harness: mail is blocked and captured',
	function () {
		ifls_reset_mail();
		wp_mail( 'nobody@example.com', 'subject', 'body' );
		ifls_assert_eq( 1, count( ifls_sent_mail() ), 'mail was not captured' );
		$captured = ifls_sent_mail();
		ifls_assert_eq( 'subject', $captured[0]['subject'] );
	}
);

ifls_test(
	'harness: mail buffer resets',
	function () {
		ifls_reset_mail();
		ifls_assert_eq( 0, count( ifls_sent_mail() ) );
	}
);

ifls_test(
	'harness: wp_die becomes a catchable exception',
	function () {
		try {
			wp_die( 'boom' );
		} catch ( IFLS_Test_Blocked $e ) {
			ifls_assert_eq( 'boom', $e->getMessage() );
			return;
		}
		throw new RuntimeException( 'wp_die did not throw' );
	}
);

ifls_test(
	'harness: assertions actually fail when they should',
	function () {
		try {
			ifls_assert_eq( 1, 2, 'deliberate' );
		} catch ( RuntimeException $e ) {
			return;
		}
		throw new RuntimeException( 'ifls_assert_eq did not throw on mismatch' );
	}
);
