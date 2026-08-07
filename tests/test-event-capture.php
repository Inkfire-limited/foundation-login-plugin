<?php
/**
 * Auth event capture.
 *
 * Two of these matter more than the rest: csrf_blocked and reset_failed are
 * the signatures the 2.0.27 and 2.0.28 bugs emitted for months with nobody
 * listening. If they stop being recorded, the alarm goes silent again.
 *
 * @package Inkfire_Login_Styler
 */

ifls_test(
	'capture: successful login is recorded',
	function () {
		IFLS_Event_Log::clear();
		$user = get_user_by( 'id', 1 );

		do_action( 'wp_login', $user->user_login, $user );

		$rows = IFLS_Event_Log::query( array( 'event' => 'login_success' ) );
		ifls_assert_eq( 1, count( $rows ) );
		ifls_assert_eq( (int) $user->ID, (int) $rows[0]->user_id );
		ifls_assert_eq( $user->user_login, $rows[0]->username );
	}
);

ifls_test(
	'capture: failed login is recorded with the attempted username',
	function () {
		IFLS_Event_Log::clear();

		do_action( 'wp_login_failed', 'mallory' );

		$rows = IFLS_Event_Log::query( array( 'event' => 'login_failed' ) );
		ifls_assert_eq( 1, count( $rows ) );
		ifls_assert_eq( 'mallory', $rows[0]->username );
	}
);

ifls_test(
	'capture: logout is recorded',
	function () {
		IFLS_Event_Log::clear();

		do_action( 'wp_logout', 1 );

		$rows = IFLS_Event_Log::query( array( 'event' => 'logout' ) );
		ifls_assert_eq( 1, count( $rows ) );
		ifls_assert_eq( 1, (int) $rows[0]->user_id );
	}
);

ifls_test(
	'capture: a reset request is recorded when a key is minted',
	function () {
		IFLS_Event_Log::clear();
		$user = get_user_by( 'id', 1 );

		// Note: the retrieve_password ACTION fires inside get_password_reset_key(),
		// not inside the retrieve_password() function - so this records "a reset
		// key was actually issued", which is the more useful signal.
		do_action( 'retrieve_password', $user->user_login );

		ifls_assert_eq( 1, count( IFLS_Event_Log::query( array( 'event' => 'reset_requested' ) ) ) );
	}
);

ifls_test(
	'capture: a completed reset is recorded, and the new password is not',
	function () {
		IFLS_Event_Log::clear();
		$user = get_user_by( 'id', 1 );

		do_action( 'after_password_reset', $user, 'SuperSecret123!' );

		$rows = IFLS_Event_Log::query( array( 'event' => 'reset_completed' ) );
		ifls_assert_eq( 1, count( $rows ) );
		ifls_assert(
			false === strpos( $rows[0]->detail . $rows[0]->username, 'SuperSecret123!' ),
			'the new password leaked into the log'
		);
	}
);

ifls_test(
	'capture: REGRESSION GUARD - csrf_blocked is recorded (the 2.0.27 signature)',
	function () {
		IFLS_Event_Log::clear();

		$security = IFLS_Enterprise_Security::get_instance();

		// No nonce present, and not an admin reset -> must be blocked AND logged.
		$restore = $_POST;
		$_POST   = array();

		try {
			$security->verify_csrf_token();
		} catch ( IFLS_Test_Blocked $e ) {
			// expected
		}

		$_POST = $restore;

		ifls_assert_eq(
			1,
			count( IFLS_Event_Log::query( array( 'event' => 'csrf_blocked' ) ) ),
			'blocked security checks are no longer logged - the 2.0.27 alarm is silent'
		);
	}
);

ifls_test(
	'capture: REGRESSION GUARD - reset_failed is recorded (the 2.0.28 signature)',
	function () {
		IFLS_Event_Log::clear();

		$restore_action = isset( $_GET['action'] ) ? $_GET['action'] : null;
		$restore_error  = isset( $_GET['error'] ) ? $_GET['error'] : null;

		$_GET['action'] = 'lostpassword';
		$_GET['error']  = 'invalidkey';

		do_action( 'login_init' );

		if ( null === $restore_action ) {
			unset( $_GET['action'] );
		} else {
			$_GET['action'] = $restore_action;
		}
		if ( null === $restore_error ) {
			unset( $_GET['error'] );
		} else {
			$_GET['error'] = $restore_error;
		}

		ifls_assert_eq(
			1,
			count( IFLS_Event_Log::query( array( 'event' => 'reset_failed' ) ) ),
			'failed resets are no longer logged - the 2.0.28 alarm is silent'
		);
	}
);

ifls_test(
	'capture: an ordinary login page view records no reset_failed',
	function () {
		IFLS_Event_Log::clear();

		$restore_action = isset( $_GET['action'] ) ? $_GET['action'] : null;
		$restore_error  = isset( $_GET['error'] ) ? $_GET['error'] : null;
		unset( $_GET['action'], $_GET['error'] );

		do_action( 'login_init' );

		if ( null !== $restore_action ) {
			$_GET['action'] = $restore_action;
		}
		if ( null !== $restore_error ) {
			$_GET['error'] = $restore_error;
		}

		ifls_assert_eq( 0, count( IFLS_Event_Log::query( array() ) ), 'a plain login view must not log anything' );
	}
);

ifls_test(
	'capture: hooks still run cleanly when logging is switched off',
	function () {
		update_option( 'ifls_diagnostics_settings', array( 'logging_enabled' => false ) );

		$user = get_user_by( 'id', 1 );
		do_action( 'wp_login', $user->user_login, $user );
		do_action( 'wp_login_failed', 'nobody' );
		do_action( 'wp_logout', 1 );

		delete_option( 'ifls_diagnostics_settings' );

		ifls_assert( true, 'auth hooks ran with logging disabled' );
	}
);
