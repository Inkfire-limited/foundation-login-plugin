<?php
/**
 * Regression guard for the 2.0.27 fix.
 *
 * The plugin's front-end CSRF check hangs off `lostpassword_post`, which
 * WordPress core also fires for its own admin reset tools. Getting the
 * exemption wrong in either direction is a real bug:
 *
 *   too strict -> admins cannot send reset links (the original 2.0.27 bug)
 *   too loose  -> anonymous callers slip through, because is_admin() is TRUE
 *                 for unauthenticated requests to admin-ajax.php
 *
 * Both directions are asserted here.
 *
 * @package Inkfire_Login_Styler
 */

/**
 * Run one scenario in a subprocess and return PASSED / BLOCKED / ERROR.
 *
 * @param string $scenario Scenario key.
 * @param string $target   Target username.
 * @return string
 */
function ifls_run_csrf_scenario( $scenario, $target ) {
	// Shared hosts commonly disable shell_exec/exec/popen; proc_open usually
	// survives. If even that is gone, skip rather than report a false failure.
	if ( ! function_exists( 'proc_open' ) ) {
		return array( 'SKIP', 'proc_open unavailable on this host' );
	}

	$descriptors = array(
		0 => array( 'pipe', 'r' ),
		1 => array( 'pipe', 'w' ),
		2 => array( 'pipe', 'w' ),
	);

	$process = proc_open(
		array(
			PHP_BINARY,
			__DIR__ . '/csrf-scenario.php',
			untrailingslashit( ABSPATH ),
			$scenario,
			$target,
		),
		$descriptors,
		$pipes
	);

	if ( ! is_resource( $process ) ) {
		return array( 'FATAL', 'could not spawn scenario process' );
	}

	fclose( $pipes[0] );
	$stdout = stream_get_contents( $pipes[1] );
	$stderr = stream_get_contents( $pipes[2] );
	fclose( $pipes[1] );
	fclose( $pipes[2] );
	proc_close( $process );

	$output = $stdout . $stderr;

	if ( preg_match( '/^RESULT=([A-Z]+)(.*)$/m', $output, $m ) ) {
		return array( $m[1], trim( $m[2] ) );
	}

	return array( 'FATAL', trim( $output ) );
}

// Two subscribers are required: one target, one acting cross-user.
$ifls_fixtures = array();
foreach ( array( 'ifls-csrf-a', 'ifls-csrf-b' ) as $login ) {
	$existing = get_user_by( 'login', $login );
	if ( $existing ) {
		$ifls_fixtures[] = $existing->ID;
		continue;
	}
	$id = wp_insert_user(
		array(
			'user_login' => $login,
			'user_email' => $login . '@example.com',
			'user_pass'  => wp_generate_password( 24 ),
			'role'       => 'subscriber',
		)
	);
	$ifls_fixtures[] = $id;
}

$ifls_matrix = array(
	// Legitimate paths that must be allowed.
	'admin_ajax'            => 'PASSED',
	'admin_bulk'            => 'PASSED',
	'admin_bulk_action2'    => 'PASSED',
	'frontend_valid_nonce'  => 'PASSED',
	'woocommerce'           => 'PASSED',
	'subscriber_self_spoof' => 'PASSED',
	// Attack paths that must stay blocked.
	'frontend_no_nonce'     => 'BLOCKED',
	'frontend_bad_nonce'    => 'BLOCKED',
	'anon_ajax_spoof'       => 'BLOCKED',
	'subscriber_ajax_spoof' => 'BLOCKED',
	'subscriber_bulk_spoof' => 'BLOCKED',
	'admin_other_action'    => 'BLOCKED',
);

foreach ( $ifls_matrix as $ifls_scenario => $ifls_want ) {
	ifls_test(
		sprintf( 'csrf matrix: %s must be %s', $ifls_scenario, strtolower( $ifls_want ) ),
		function () use ( $ifls_scenario, $ifls_want ) {
			list( $got, $detail ) = ifls_run_csrf_scenario( $ifls_scenario, 'ifls-csrf-a' );
			ifls_assert_eq( $ifls_want, $got, $ifls_scenario . ' (' . $detail . ')' );
		}
	);
}

// Clean up fixtures.
require_once ABSPATH . 'wp-admin/includes/user.php';
foreach ( $ifls_fixtures as $ifls_id ) {
	if ( $ifls_id && ! is_wp_error( $ifls_id ) ) {
		wp_delete_user( $ifls_id );
	}
}
