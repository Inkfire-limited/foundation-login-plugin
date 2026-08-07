<?php
/**
 * Diagnostics admin screen.
 *
 * Log rows contain attacker-controlled data (usernames and user agents come
 * straight from failed login attempts), so escaping is the highest-value thing
 * tested here.
 *
 * @package Inkfire_Login_Styler
 */

ifls_test(
	'admin: FORENSICS - a hostile username is preserved so the attempt is visible',
	function () {
		IFLS_Event_Log::clear();
		IFLS_Event_Log::record( 'login_failed', array( 'username' => '<script>alert(1)</script>' ) );

		$rows = IFLS_Event_Log::query( array() );

		ifls_assert_eq(
			'<script>alert(1)</script>',
			$rows[0]->username,
			'the attempted username must be preserved - an audit log that discards the payload hides the attack'
		);
	}
);

ifls_test(
	'admin: XSS - a hostile username is escaped when rendered',
	function () {
		IFLS_Event_Log::clear();
		IFLS_Event_Log::record( 'login_failed', array( 'username' => '<script>alert(1)</script>' ) );

		$rows = IFLS_Event_Log::query( array() );
		$html = IFLS_Diagnostics_Admin::render_log_row( $rows[0] );

		ifls_assert( false === strpos( $html, '<script>' ), 'raw script tag rendered - stored XSS' );
		ifls_assert( false !== strpos( $html, '&lt;script&gt;' ), 'the username should be visible but escaped' );
	}
);

ifls_test(
	'admin: control characters are stripped from a stored username',
	function () {
		IFLS_Event_Log::clear();
		IFLS_Event_Log::record( 'login_failed', array( 'username' => "ad\x00min\x1b[31m" ) );

		$rows = IFLS_Event_Log::query( array() );

		ifls_assert(
			! preg_match( '/[\x00-\x1F\x7F]/', $rows[0]->username ),
			'control characters must not reach storage - they can corrupt terminal output and log viewers'
		);
	}
);

ifls_test(
	'admin: XSS - a hostile user agent is escaped in the log table',
	function () {
		IFLS_Event_Log::clear();

		$original                   = isset( $_SERVER['HTTP_USER_AGENT'] ) ? $_SERVER['HTTP_USER_AGENT'] : '';
		$_SERVER['HTTP_USER_AGENT'] = '"><img src=x onerror=alert(1)>';

		IFLS_Event_Log::record( 'login_failed', array( 'username' => 'x' ) );

		$_SERVER['HTTP_USER_AGENT'] = $original;

		$rows = IFLS_Event_Log::query( array() );
		$html = IFLS_Diagnostics_Admin::render_log_row( $rows[0] );

		ifls_assert( false === strpos( $html, 'onerror=alert' ), 'unescaped attribute payload rendered' );
	}
);

ifls_test(
	'admin: an incident with a hostile reason is escaped',
	function () {
		IFLS_Incident_Reporter::clear();
		IFLS_Incident_Reporter::raise( 'mail_failure', '<img src=x onerror=alert(1)>' );

		$incidents = IFLS_Incident_Reporter::incidents();
		$html      = IFLS_Diagnostics_Admin::render_incident_row( $incidents[0] );

		ifls_assert( false === strpos( $html, 'onerror=alert' ), 'unescaped incident reason rendered' );

		IFLS_Incident_Reporter::clear();
	}
);

ifls_test(
	'admin: settings are registered with the sanitise callback',
	function () {
		IFLS_Diagnostics_Admin::register_settings();

		global $wp_registered_settings;

		ifls_assert(
			isset( $wp_registered_settings['ifls_diagnostics_settings'] ),
			'setting was not registered'
		);
		ifls_assert_eq(
			'ifls_diag_sanitize',
			$wp_registered_settings['ifls_diagnostics_settings']['sanitize_callback'],
			'settings must be sanitised on save'
		);
	}
);

ifls_test(
	'admin: SECURITY - the test-email recipient never comes from the request',
	function () {
		$src = file_get_contents( dirname( __DIR__ ) . '/inc/class-ifls-diagnostics-admin.php' );

		// The handler must resolve the recipient from settings/current user only.
		ifls_assert(
			false === strpos( $src, "\$_POST['to']" ) && false === strpos( $src, "\$_REQUEST['to']" ),
			'the test-email handler reads a recipient from the request - that is an open relay'
		);
	}
);

ifls_test(
	'admin: every state-changing handler checks capability and nonce',
	function () {
		$src = file_get_contents( dirname( __DIR__ ) . '/inc/class-ifls-diagnostics-admin.php' );

		foreach ( array( 'handle_test_email', 'handle_clear_log', 'handle_locate_ip' ) as $handler ) {
			$start = strpos( $src, 'function ' . $handler );
			ifls_assert( false !== $start, "handler {$handler} is missing" );

			$body = substr( $src, $start, 900 );
			ifls_assert( false !== strpos( $body, 'current_user_can' ), "{$handler} has no capability check" );
			ifls_assert( false !== strpos( $body, 'check_admin_referer' ), "{$handler} has no nonce check" );
		}
	}
);

ifls_test(
	'admin: locate only accepts a valid IP address',
	function () {
		ifls_assert_eq( '', IFLS_Diagnostics_Admin::locate_ip( 'not-an-ip' ), 'a non-IP must be rejected' );
		ifls_assert_eq( '', IFLS_Diagnostics_Admin::locate_ip( '' ), 'an empty value must be rejected' );
		ifls_assert_eq( '', IFLS_Diagnostics_Admin::locate_ip( '1.2.3.4; rm -rf /' ), 'an injection attempt must be rejected' );
	}
);

ifls_test(
	'admin: locate results are cached per IP',
	function () {
		// A documentation-range address; the lookup will fail or return nothing,
		// but the negative result must still be cached so clicking twice does
		// not make two outbound calls.
		delete_transient( 'ifls_geo_' . md5( '192.0.2.1' ) );
		IFLS_Diagnostics_Admin::locate_ip( '192.0.2.1' );

		ifls_assert(
			false !== get_transient( 'ifls_geo_' . md5( '192.0.2.1' ) ),
			'lookup result was not cached'
		);
	}
);

ifls_test(
	'admin: the menu registers under the shared Foundation parent',
	function () {
		$src = file_get_contents( dirname( __DIR__ ) . '/inc/class-ifls-diagnostics-admin.php' );
		ifls_assert( false !== strpos( $src, 'foundation-by-inkfire' ), 'must hang off the shared Foundation menu' );
		ifls_assert( false !== strpos( $src, 'manage_options' ), 'must require manage_options' );
	}
);
