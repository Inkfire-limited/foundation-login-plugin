<?php
/**
 * Regression guard for the 2.0.28 fix.
 *
 * wp-login.php moves the reset key out of the URL into the
 * wp-resetpass-<COOKIEHASH> cookie before `action=resetpass` renders. Reading
 * it from $_REQUEST produced an empty hidden rp_key field, core's
 * hash_equals() check failed, and NO password was ever changed - silently,
 * for seven months.
 *
 * If these fail, password reset is broken again.
 *
 * @package Inkfire_Login_Styler
 */

ifls_test(
	'reset credentials: helper exists',
	function () {
		ifls_assert( function_exists( 'ifls_get_reset_credentials' ), 'ifls_get_reset_credentials() is missing' );
	}
);

ifls_test(
	'reset credentials: key is read from the reset cookie, not the URL',
	function () {
		$cookie = 'wp-resetpass-' . COOKIEHASH;

		$restore_cookie  = isset( $_COOKIE[ $cookie ] ) ? $_COOKIE[ $cookie ] : null;
		$restore_key     = isset( $_REQUEST['key'] ) ? $_REQUEST['key'] : null;
		$restore_login   = isset( $_REQUEST['login'] ) ? $_REQUEST['login'] : null;

		// This is the real situation on action=resetpass: cookie set, URL empty.
		$_COOKIE[ $cookie ]  = 'alice:SECRETKEY123456';
		unset( $_REQUEST['key'], $_REQUEST['login'] );

		list( $login, $key ) = ifls_get_reset_credentials();

		ifls_assert_eq( 'alice', $login, 'login should come from the cookie' );
		ifls_assert_eq( 'SECRETKEY123456', $key, 'key should come from the cookie' );

		unset( $_COOKIE[ $cookie ] );
		if ( null !== $restore_cookie ) {
			$_COOKIE[ $cookie ] = $restore_cookie;
		}
		if ( null !== $restore_key ) {
			$_REQUEST['key'] = $restore_key;
		}
		if ( null !== $restore_login ) {
			$_REQUEST['login'] = $restore_login;
		}
	}
);

ifls_test(
	'reset credentials: key is NOT altered (hash_equals needs it byte-exact)',
	function () {
		$cookie = 'wp-resetpass-' . COOKIEHASH;
		$raw    = 'bob:AbC123xyzQQ0';

		$_COOKIE[ $cookie ] = $raw;
		list( , $key ) = ifls_get_reset_credentials();
		unset( $_COOKIE[ $cookie ] );

		ifls_assert_eq( 'AbC123xyzQQ0', $key, 'the key must survive verbatim - sanitising it breaks hash_equals' );
	}
);

ifls_test(
	'reset credentials: falls back to the request on the initial action=rp render',
	function () {
		$cookie = 'wp-resetpass-' . COOKIEHASH;
		unset( $_COOKIE[ $cookie ] );

		$_REQUEST['key']   = 'URLKEY9876543210';
		$_REQUEST['login'] = 'carol';

		list( $login, $key ) = ifls_get_reset_credentials();

		ifls_assert_eq( 'carol', $login );
		ifls_assert_eq( 'URLKEY9876543210', $key );

		unset( $_REQUEST['key'], $_REQUEST['login'] );
	}
);

ifls_test(
	'reset credentials: a malformed cookie does not fatal',
	function () {
		$cookie             = 'wp-resetpass-' . COOKIEHASH;
		$_COOKIE[ $cookie ] = 'no-colon-here';

		$result = ifls_get_reset_credentials();

		unset( $_COOKIE[ $cookie ] );

		ifls_assert( is_array( $result ), 'must always return an array' );
		ifls_assert_eq( 2, count( $result ), 'must always return exactly two elements' );
	}
);

ifls_test(
	'reset form renders a populated rp_key on the resetpass step',
	function () {
		$cookie             = 'wp-resetpass-' . COOKIEHASH;
		$_COOKIE[ $cookie ] = 'dave:RENDERKEY123456';

		$html = ifls_render_inline_form( 'resetpass' );

		unset( $_COOKIE[ $cookie ] );

		ifls_assert( (bool) preg_match( '/name="rp_key" value="([^"]*)"/', $html, $m ), 'rp_key field missing' );
		ifls_assert_eq( 'RENDERKEY123456', $m[1], 'rp_key rendered empty - password reset is broken again' );
	}
);
