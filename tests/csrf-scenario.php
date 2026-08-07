<?php
/**
 * Runs ONE lost-password CSRF scenario in its own process.
 *
 * Each scenario needs different constants (WP_ADMIN, DOING_AJAX) defined
 * before WordPress boots, which is impossible to vary inside a single process.
 * test-csrf-matrix.php therefore shells out to this script per scenario.
 *
 * Usage: php csrf-scenario.php <wp-root> <scenario> <target-username>
 * Prints: RESULT=PASSED|BLOCKED|ERROR ...
 *
 * @package Inkfire_Login_Styler
 */

$root     = isset( $argv[1] ) ? $argv[1] : '';
$scenario = isset( $argv[2] ) ? $argv[2] : '';
$username = isset( $argv[3] ) ? $argv[3] : '';

if ( ! $root || ! $scenario || ! $username ) {
	fwrite( STDERR, "usage: php csrf-scenario.php <wp-root> <scenario> <username>\n" );
	exit( 2 );
}

$_SERVER['HTTP_HOST']       = 'localhost';
$_SERVER['SERVER_NAME']     = 'localhost';
$_SERVER['REQUEST_METHOD']  = 'POST';
$_SERVER['REQUEST_URI']     = '/wp-login.php?action=lostpassword';
$_SERVER['SCRIPT_NAME']     = '/wp-login.php';
$_SERVER['PHP_SELF']        = '/wp-login.php';
$_SERVER['REMOTE_ADDR']     = '127.0.0.1';
$_SERVER['HTTP_USER_AGENT'] = 'IFLS-Test';

$as_user = 0;

switch ( $scenario ) {
	case 'admin_ajax': // user-edit.php "Send Reset Link"
		define( 'WP_ADMIN', true );
		define( 'DOING_AJAX', true );
		$_SERVER['REQUEST_URI'] = '/wp-admin/admin-ajax.php';
		$_REQUEST['action']     = 'send-password-reset';
		$_POST['action']        = 'send-password-reset';
		$as_user                = 'ADMIN';
		break;

	case 'admin_bulk': // users.php bulk action
		define( 'WP_ADMIN', true );
		$_SERVER['REQUEST_URI'] = '/wp-admin/users.php';
		$_REQUEST['action']     = 'resetpassword';
		$_POST['action']        = 'resetpassword';
		$as_user                = 'ADMIN';
		break;

	case 'admin_bulk_action2': // bottom bulk dropdown
		define( 'WP_ADMIN', true );
		$_SERVER['REQUEST_URI'] = '/wp-admin/users.php';
		$_REQUEST['action']     = '-1';
		$_REQUEST['action2']    = 'resetpassword';
		$_POST['action2']       = 'resetpassword';
		$as_user                = 'ADMIN';
		break;

	case 'frontend_no_nonce':
		break;

	case 'frontend_bad_nonce':
		$_POST['ifls_form_nonce'] = 'deadbeefdead';
		break;

	case 'frontend_valid_nonce':
		break; // nonce minted after boot

	case 'woocommerce':
		$_POST['woocommerce-lost-password-nonce'] = 'wc-nonce';
		break;

	case 'anon_ajax_spoof': // is_admin() is true here even logged out
		define( 'WP_ADMIN', true );
		define( 'DOING_AJAX', true );
		$_SERVER['REQUEST_URI'] = '/wp-admin/admin-ajax.php';
		$_REQUEST['action']     = 'send-password-reset';
		$_POST['action']        = 'send-password-reset';
		break;

	case 'subscriber_ajax_spoof': // subscriber targeting ANOTHER user
		define( 'WP_ADMIN', true );
		define( 'DOING_AJAX', true );
		$_SERVER['REQUEST_URI'] = '/wp-admin/admin-ajax.php';
		$_REQUEST['action']     = 'send-password-reset';
		$_POST['action']        = 'send-password-reset';
		$as_user                = 'SUBSCRIBER';
		break;

	case 'subscriber_self_spoof': // widest the exemption can open
		define( 'WP_ADMIN', true );
		define( 'DOING_AJAX', true );
		$_SERVER['REQUEST_URI'] = '/wp-admin/admin-ajax.php';
		$_REQUEST['action']     = 'send-password-reset';
		$_POST['action']        = 'send-password-reset';
		$as_user                = 'SELF';
		break;

	case 'subscriber_bulk_spoof':
		define( 'WP_ADMIN', true );
		$_SERVER['REQUEST_URI'] = '/wp-admin/users.php';
		$_REQUEST['action']     = 'resetpassword';
		$_POST['action']        = 'resetpassword';
		$as_user                = 'SELF';
		break;

	case 'admin_other_action': // admin context, but not a reset tool
		define( 'WP_ADMIN', true );
		$_SERVER['REQUEST_URI'] = '/wp-admin/users.php';
		$_REQUEST['action']     = 'delete';
		$_POST['action']        = 'delete';
		$as_user                = 'ADMIN';
		break;

	default:
		fwrite( STDERR, "unknown scenario: {$scenario}\n" );
		exit( 2 );
}

require_once rtrim( $root, '/' ) . '/wp-load.php';

// Nothing may leave the server.
add_filter( 'pre_wp_mail', '__return_true', PHP_INT_MAX );

// Make wp_die() catchable.
$to_exception = function () {
	return function ( $message, $title = '', $args = array() ) {
		if ( is_wp_error( $message ) ) {
			$message = $message->get_error_message();
		}
		throw new RuntimeException( wp_strip_all_tags( (string) $message ) );
	};
};
foreach ( array( 'wp_die_handler', 'wp_die_ajax_handler', 'wp_die_json_handler' ) as $f ) {
	add_filter( $f, $to_exception, PHP_INT_MAX );
}

$target = get_user_by( 'login', $username );
if ( ! $target ) {
	echo "RESULT=ERROR DETAIL=target user not found\n";
	exit( 2 );
}

if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
	$_POST['user_id'] = $target->ID;
}

if ( 'SELF' === $as_user ) {
	wp_set_current_user( $target->ID );
} elseif ( 'ADMIN' === $as_user ) {
	$admins = get_users( array( 'role' => 'administrator', 'number' => 1, 'fields' => 'ID' ) );
	if ( empty( $admins ) ) {
		echo "RESULT=ERROR DETAIL=no administrator\n";
		exit( 2 );
	}
	wp_set_current_user( (int) $admins[0] );
} elseif ( 'SUBSCRIBER' === $as_user ) {
	// Must be a DIFFERENT user, or edit_user passes on self and this silently
	// becomes the subscriber_self_spoof case instead.
	$subs = get_users(
		array(
			'role'    => 'subscriber',
			'number'  => 1,
			'fields'  => 'ID',
			'exclude' => array( $target->ID ),
		)
	);
	if ( empty( $subs ) ) {
		echo "RESULT=ERROR DETAIL=no second subscriber for cross-user spoof\n";
		exit( 2 );
	}
	wp_set_current_user( (int) $subs[0] );
}

if ( 'frontend_valid_nonce' === $scenario ) {
	$_POST['ifls_form_nonce'] = wp_create_nonce( 'ifls_form_action' );
}

if ( ! has_action( 'lostpassword_post' ) ) {
	echo "RESULT=ERROR DETAIL=nothing hooked to lostpassword_post\n";
	exit( 2 );
}

try {
	$result = retrieve_password( $username );
} catch ( Throwable $e ) {
	echo 'RESULT=BLOCKED DETAIL=' . str_replace( "\n", ' ', $e->getMessage() ) . "\n";
	exit( 1 );
}

if ( is_wp_error( $result ) ) {
	echo 'RESULT=ERROR DETAIL=' . $result->get_error_code() . "\n";
	exit( 2 );
}

echo "RESULT=PASSED\n";
exit( 0 );
