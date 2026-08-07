<?php
/**
 * Fail-safety gate.
 *
 * This is the most important file in the suite. This feature runs on every
 * authentication on every site the plugin is installed on, so it must be
 * architecturally incapable of breaking login even when it is itself broken.
 *
 * If anything here fails, do not release.
 *
 * @package Inkfire_Login_Styler
 */

ifls_test(
	'FAIL-SAFE: authentication hooks all survive a dropped events table',
	function () {
		global $wpdb;

		$table = IFLS_Event_Log::table();
		$wpdb->query( "DROP TABLE IF EXISTS {$table}" );
		$suppress = $wpdb->suppress_errors( true );

		$user = get_user_by( 'id', 1 );

		// A valid nonce, because register_post also carries the plugin's CSRF
		// gate and we are testing logging here, not that gate.
		$restore                  = isset( $_POST['ifls_form_nonce'] ) ? $_POST['ifls_form_nonce'] : null;
		$_POST['ifls_form_nonce'] = wp_create_nonce( 'ifls_form_action' );

		// Every hook a real login touches. Any throw here means a broken table
		// takes authentication down with it.
		do_action( 'wp_login', $user->user_login, $user );
		do_action( 'wp_login_failed', 'someone' );
		do_action( 'wp_logout', 1 );
		do_action( 'retrieve_password', $user->user_login );
		do_action( 'after_password_reset', $user, 'irrelevant' );
		do_action( 'register_post', 'someone' );

		if ( null === $restore ) {
			unset( $_POST['ifls_form_nonce'] );
		} else {
			$_POST['ifls_form_nonce'] = $restore;
		}

		$wpdb->suppress_errors( $suppress );
		IFLS_Event_Log::install();

		ifls_assert( true, 'all authentication hooks survived a missing table' );
	}
);

ifls_test(
	'FAIL-SAFE: the incident reporter survives a dropped events table',
	function () {
		global $wpdb;

		$table = IFLS_Event_Log::table();
		$wpdb->query( "DROP TABLE IF EXISTS {$table}" );
		$suppress = $wpdb->suppress_errors( true );

		IFLS_Incident_Reporter::check_thresholds();
		IFLS_Incident_Reporter::raise( 'mail_failure', 'table is gone' );
		IFLS_Incident_Reporter::dispatch();

		$wpdb->suppress_errors( $suppress );
		IFLS_Event_Log::install();
		IFLS_Incident_Reporter::clear();

		ifls_assert( true, 'incident reporting survived a missing table' );
	}
);

ifls_test(
	'FAIL-SAFE: the login form still renders with the events table dropped',
	function () {
		global $wpdb;

		$table = IFLS_Event_Log::table();
		$wpdb->query( "DROP TABLE IF EXISTS {$table}" );
		$suppress = $wpdb->suppress_errors( true );

		$login = ifls_render_inline_form( 'login' );
		$lost  = ifls_render_inline_form( 'lostpassword' );

		$wpdb->suppress_errors( $suppress );
		IFLS_Event_Log::install();

		ifls_assert( false !== strpos( $login, 'if_card_loginform' ), 'the login form must still render' );
		ifls_assert( false !== strpos( $lost, 'if_lostpasswordform' ), 'the lost-password form must still render' );
	}
);

ifls_test(
	'FAIL-SAFE: a corrupt settings option does not break authentication',
	function () {
		update_option( 'ifls_diagnostics_settings', 'not-an-array' );

		$user = get_user_by( 'id', 1 );
		do_action( 'wp_login', $user->user_login, $user );
		do_action( 'wp_login_failed', 'someone' );

		delete_option( 'ifls_diagnostics_settings' );

		ifls_assert( true, 'a corrupt settings option was survived' );
	}
);

ifls_test(
	'FAIL-SAFE: a corrupt incident store does not break authentication',
	function () {
		update_option( 'ifls_incidents', 'not-an-array' );

		IFLS_Incident_Reporter::raise( 'mail_failure', 'corrupt store' );
		IFLS_Incident_Reporter::dispatch();

		IFLS_Incident_Reporter::clear();

		ifls_assert( true, 'a corrupt incident store was survived' );
	}
);

ifls_test(
	'FAIL-SAFE: the kill switch is checked before any work',
	function () {
		$files = array( 'inc/class-ifls-event-log.php', 'inc/class-ifls-incident-reporter.php' );

		foreach ( $files as $file ) {
			$src = file_get_contents( dirname( __DIR__ ) . '/' . $file );
			ifls_assert(
				false !== strpos( $src, 'ifls_diag_enabled()' ),
				"{$file} does not honour the kill switch"
			);
		}

		// And the switch itself must be a single wp-config constant.
		$settings = file_get_contents( dirname( __DIR__ ) . '/inc/ifls-diagnostics-settings.php' );
		ifls_assert(
			false !== strpos( $settings, 'IFLS_DISABLE_DIAGNOSTICS' ),
			'the kill switch constant is missing'
		);
	}
);

ifls_test(
	'FAIL-SAFE: every entry point that does real work swallows Throwable',
	function () {
		// Named methods rather than a magic count, so adding a method that
		// touches the database without a guard fails this test by name.
		$guarded = array(
			'inc/class-ifls-event-log.php'         => array( 'record', 'query', 'count_since', 'prune', 'clear' ),
			'inc/class-ifls-incident-reporter.php' => array( 'raise', 'check_thresholds', 'dispatch' ),
		);

		foreach ( $guarded as $file => $methods ) {
			$src = file_get_contents( dirname( __DIR__ ) . '/' . $file );

			foreach ( $methods as $method ) {
				$start = strpos( $src, 'function ' . $method . '(' );
				ifls_assert( false !== $start, "{$file}: method {$method}() not found" );

				// Body runs to the start of the next method declaration.
				$next = strpos( $src, "\n    ", $start );
				$end  = strpos( $src, 'function ', $start + 10 );
				$body = false === $end ? substr( $src, $start ) : substr( $src, $start, $end - $start );

				ifls_assert(
					false !== strpos( $body, 'catch (\Throwable' ),
					"{$file}: {$method}() has no Throwable guard - a fault there could break authentication"
				);
			}
		}
	}
);

ifls_test(
	'FAIL-SAFE: CONSTRAINT - incident dispatch never runs on wp-login.php',
	function () {
		$src = file_get_contents( dirname( __DIR__ ) . '/inkfire-login-styler.php' );

		ifls_assert(
			false !== strpos( $src, "'wp-login.php' === \$GLOBALS['pagenow']" ),
			'the shutdown dispatch must bail on wp-login.php, or a slow SMTP server blocks every login'
		);
	}
);

ifls_test(
	'FAIL-SAFE: raise() performs no mail I/O at all',
	function () {
		ifls_reset_mail();
		IFLS_Incident_Reporter::clear();

		for ( $i = 0; $i < 25; $i++ ) {
			IFLS_Incident_Reporter::raise( 'mail_failure', 'no io please ' . $i );
		}

		ifls_assert_eq( 0, count( ifls_sent_mail() ), 'raise() attempted mail on the request path' );

		IFLS_Incident_Reporter::clear();
	}
);

ifls_test(
	'FAIL-SAFE: the fatal handler ignores errors from other plugins',
	function () {
		$src = file_get_contents( dirname( __DIR__ ) . '/inkfire-login-styler.php' );

		ifls_assert(
			false !== strpos( $src, "strpos(\$error['file'], 'foundation-inkfire-login-styler')" ),
			'the shutdown fatal handler must only report errors from this plugin'
		);
	}
);

ifls_test(
	'FAIL-SAFE: pruning a large backlog is batched',
	function () {
		$src = file_get_contents( dirname( __DIR__ ) . '/inc/class-ifls-event-log.php' );

		ifls_assert(
			false !== strpos( $src, 'LIMIT 1000' ),
			'prune must delete in batches or a big backlog will exhaust max_execution_time'
		);
	}
);
