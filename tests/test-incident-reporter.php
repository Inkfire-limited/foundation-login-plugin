<?php
/**
 * Incident detection, deduplication, storage and queued dispatch.
 *
 * The two constraints that matter most:
 *   1. raise() must never send mail - sending inline would block every failed
 *      login for the SMTP timeout on sites whose mail is already broken.
 *   2. The incident must be stored BEFORE any send is attempted, because when
 *      the incident IS mail failure the local copy is the only record.
 *
 * @package Inkfire_Login_Styler
 */

ifls_test(
	'incidents: raise stores locally with pending status',
	function () {
		IFLS_Incident_Reporter::clear();
		ifls_reset_mail();

		IFLS_Incident_Reporter::raise( 'mail_failure', 'wp_mail returned false' );

		$all = IFLS_Incident_Reporter::incidents();
		ifls_assert_eq( 1, count( $all ) );
		ifls_assert_eq( 'pending', $all[0]['status'] );
		ifls_assert_eq( 'mail_failure', $all[0]['type'] );
		ifls_assert_eq( 1, $all[0]['count'] );
	}
);

ifls_test(
	'incidents: CONSTRAINT - raise() sends no mail inline',
	function () {
		IFLS_Incident_Reporter::clear();
		ifls_reset_mail();

		for ( $i = 0; $i < 10; $i++ ) {
			IFLS_Incident_Reporter::raise( 'mail_failure', 'inline check ' . $i );
		}

		ifls_assert_eq(
			0,
			count( ifls_sent_mail() ),
			'raise() sent mail on the request path - this would block failed logins for the SMTP timeout'
		);
	}
);

ifls_test(
	'incidents: dispatch sends queued incidents and marks them sent',
	function () {
		IFLS_Incident_Reporter::clear();
		ifls_reset_mail();

		IFLS_Incident_Reporter::raise( 'mail_failure', 'test reason' );
		IFLS_Incident_Reporter::dispatch();

		ifls_assert_eq( 1, count( ifls_sent_mail() ), 'dispatch should send exactly one email' );

		$all = IFLS_Incident_Reporter::incidents();
		ifls_assert_eq( 'sent', $all[0]['status'] );
	}
);

ifls_test(
	'incidents: dispatch does not resend an already-sent incident',
	function () {
		IFLS_Incident_Reporter::clear();
		ifls_reset_mail();

		IFLS_Incident_Reporter::raise( 'mail_failure', 'once only' );
		IFLS_Incident_Reporter::dispatch();
		IFLS_Incident_Reporter::dispatch();
		IFLS_Incident_Reporter::dispatch();

		ifls_assert_eq( 1, count( ifls_sent_mail() ), 'incident was resent on subsequent dispatches' );
	}
);

ifls_test(
	'incidents: the email subject names the site',
	function () {
		IFLS_Incident_Reporter::clear();
		ifls_reset_mail();

		IFLS_Incident_Reporter::raise( 'mail_failure', 'subject check' );
		IFLS_Incident_Reporter::dispatch();

		$mail = ifls_sent_mail();
		$host = wp_parse_url( home_url(), PHP_URL_HOST );

		ifls_assert( false !== strpos( $mail[0]['subject'], $host ), 'subject must identify which site alerted' );
	}
);

ifls_test(
	'incidents: the email goes to the configured recipient',
	function () {
		IFLS_Incident_Reporter::clear();
		ifls_reset_mail();
		update_option( 'ifls_diagnostics_settings', array( 'reporting_enabled' => true, 'report_email' => 'alerts@example.com' ) );

		IFLS_Incident_Reporter::raise( 'mail_failure', 'recipient check' );
		IFLS_Incident_Reporter::dispatch();

		$mail = ifls_sent_mail();
		delete_option( 'ifls_diagnostics_settings' );

		$to = is_array( $mail[0]['to'] ) ? implode( ',', $mail[0]['to'] ) : $mail[0]['to'];
		ifls_assert_eq( 'alerts@example.com', $to );
	}
);

ifls_test(
	'incidents: PRIVACY - no end-user IP or email address reaches the alert',
	function () {
		IFLS_Incident_Reporter::clear();
		ifls_reset_mail();

		IFLS_Incident_Reporter::raise(
			'reset_storm',
			'5 reset failures',
			array(
				'ip'       => '203.0.113.45',
				'username' => 'gillian',
				'email'    => 'gillian@example.org',
				'note'     => 'seen from 198.51.100.7 for user bob@example.org',
				'counts'   => array( 'reset_failed' => 5 ),
			)
		);
		IFLS_Incident_Reporter::dispatch();

		$body = ifls_sent_mail()[0]['message'];
		// Strip the site's own URL first so its host cannot cause a false hit.
		$scan = str_replace( home_url(), '', $body );

		ifls_assert( false === strpos( $scan, '203.0.113.45' ), 'an end-user IP leaked into the alert' );
		ifls_assert( false === strpos( $scan, '198.51.100.7' ), 'an embedded IP leaked into the alert' );
		ifls_assert( false === strpos( $scan, 'gillian@example.org' ), 'an end-user email leaked into the alert' );
		ifls_assert( false === strpos( $scan, 'bob@example.org' ), 'an embedded email leaked into the alert' );
		ifls_assert( false !== strpos( $scan, 'reset_failed' ), 'the useful counts should survive' );
	}
);

ifls_test(
	'incidents: identical incidents dedupe within the cooldown',
	function () {
		IFLS_Incident_Reporter::clear();
		ifls_reset_mail();

		for ( $i = 0; $i < 100; $i++ ) {
			IFLS_Incident_Reporter::raise( 'mail_failure', 'same reason every time' );
		}
		IFLS_Incident_Reporter::dispatch();

		$all = IFLS_Incident_Reporter::incidents();
		ifls_assert_eq( 1, count( $all ), '100 occurrences should collapse to one incident' );
		ifls_assert_eq( 100, $all[0]['count'], 'occurrences should still be counted' );
		ifls_assert_eq( 1, count( ifls_sent_mail() ), 'exactly one email for 100 occurrences' );
	}
);

ifls_test(
	'incidents: numbers in the reason do not defeat deduplication',
	function () {
		IFLS_Incident_Reporter::clear();
		ifls_reset_mail();

		// These differ only by a count, and must be treated as the same incident.
		IFLS_Incident_Reporter::raise( 'csrf_storm', '5 blocked security checks in 60 minutes' );
		IFLS_Incident_Reporter::raise( 'csrf_storm', '9 blocked security checks in 60 minutes' );
		IFLS_Incident_Reporter::raise( 'csrf_storm', '17 blocked security checks in 60 minutes' );

		ifls_assert_eq( 1, count( IFLS_Incident_Reporter::incidents() ), 'varying counts should not create new incidents' );
	}
);

ifls_test(
	'incidents: different incident types do NOT dedupe together',
	function () {
		IFLS_Incident_Reporter::clear();

		IFLS_Incident_Reporter::raise( 'mail_failure', 'a problem' );
		IFLS_Incident_Reporter::raise( 'csrf_storm', 'a problem' );

		ifls_assert_eq( 2, count( IFLS_Incident_Reporter::incidents() ), 'distinct types must stay distinct' );
	}
);

ifls_test(
	'incidents: threshold does NOT fire below the limit',
	function () {
		IFLS_Event_Log::clear();
		IFLS_Incident_Reporter::clear();

		for ( $i = 0; $i < 4; $i++ ) {
			IFLS_Event_Log::record( 'csrf_blocked', array() );
		}
		IFLS_Incident_Reporter::check_thresholds();

		ifls_assert_eq( 0, count( IFLS_Incident_Reporter::incidents() ), '4 occurrences must not alert' );
	}
);

ifls_test(
	'incidents: threshold fires at the limit',
	function () {
		IFLS_Event_Log::clear();
		IFLS_Incident_Reporter::clear();

		for ( $i = 0; $i < 5; $i++ ) {
			IFLS_Event_Log::record( 'csrf_blocked', array() );
		}
		IFLS_Incident_Reporter::check_thresholds();

		$all = IFLS_Incident_Reporter::incidents();
		ifls_assert_eq( 1, count( $all ), '5 occurrences must alert' );
		ifls_assert_eq( 'csrf_storm', $all[0]['type'] );
	}
);

ifls_test(
	'incidents: KEY BEHAVIOUR - a reset storm stays silent when a reset succeeded',
	function () {
		IFLS_Event_Log::clear();
		IFLS_Incident_Reporter::clear();

		// Ten people clicked stale links, but resets demonstrably work.
		for ( $i = 0; $i < 10; $i++ ) {
			IFLS_Event_Log::record( 'reset_failed', array() );
		}
		IFLS_Event_Log::record( 'reset_completed', array( 'username' => 'alice' ) );

		IFLS_Incident_Reporter::check_thresholds();

		ifls_assert_eq(
			0,
			count( IFLS_Incident_Reporter::incidents() ),
			'a successful reset in the window means resets work - stale links are not an incident'
		);
	}
);

ifls_test(
	'incidents: a reset storm DOES fire when nothing succeeds',
	function () {
		IFLS_Event_Log::clear();
		IFLS_Incident_Reporter::clear();

		for ( $i = 0; $i < 10; $i++ ) {
			IFLS_Event_Log::record( 'reset_failed', array() );
		}
		IFLS_Incident_Reporter::check_thresholds();

		$types = wp_list_pluck( IFLS_Incident_Reporter::incidents(), 'type' );
		ifls_assert( in_array( 'reset_storm', $types, true ), 'a genuine reset outage must alert' );
	}
);

ifls_test(
	'incidents: CRITICAL - the incident is stored even when sending fails',
	function () {
		IFLS_Incident_Reporter::clear();

		ifls_force_mail_failure( true );
		IFLS_Incident_Reporter::raise( 'mail_failure', 'delivery is down' );
		IFLS_Incident_Reporter::dispatch();
		ifls_force_mail_failure( false );

		$all = IFLS_Incident_Reporter::incidents();
		ifls_assert_eq( 1, count( $all ), 'the incident must persist when email is the broken thing' );
		ifls_assert_eq( 'failed', $all[0]['status'], 'failed sends must be marked for retry and surfaced' );
	}
);

ifls_test(
	'incidents: a failed send is retried on the next dispatch',
	function () {
		IFLS_Incident_Reporter::clear();

		ifls_force_mail_failure( true );
		IFLS_Incident_Reporter::raise( 'mail_failure', 'retry me' );
		IFLS_Incident_Reporter::dispatch();
		ifls_force_mail_failure( false );

		ifls_reset_mail();
		IFLS_Incident_Reporter::dispatch();

		ifls_assert_eq( 1, count( ifls_sent_mail() ), 'a previously failed incident should be retried' );
		ifls_assert_eq( 'sent', IFLS_Incident_Reporter::incidents()[0]['status'] );
	}
);

ifls_test(
	'incidents: the store is capped',
	function () {
		IFLS_Incident_Reporter::clear();

		for ( $i = 0; $i < 80; $i++ ) {
			IFLS_Incident_Reporter::raise( 'mail_failure', 'unique reason ' . $i . ' zzz' );
		}

		ifls_assert(
			count( IFLS_Incident_Reporter::incidents() ) <= 50,
			'the incident store must be capped so it cannot grow without bound'
		);
	}
);

ifls_test(
	'incidents: reporting can be switched off',
	function () {
		IFLS_Incident_Reporter::clear();
		update_option( 'ifls_diagnostics_settings', array( 'reporting_enabled' => false ) );

		IFLS_Incident_Reporter::raise( 'mail_failure', 'should not record' );

		delete_option( 'ifls_diagnostics_settings' );

		ifls_assert_eq( 0, count( IFLS_Incident_Reporter::incidents() ) );
	}
);

ifls_test(
	'incidents: FAIL-SAFE - raise never throws on an absurd payload',
	function () {
		IFLS_Incident_Reporter::clear();

		IFLS_Incident_Reporter::raise( 'mail_failure', str_repeat( 'x', 200000 ) );
		IFLS_Incident_Reporter::raise( '', '' );
		IFLS_Incident_Reporter::raise( 'mail_failure', 'ok', array( 'deep' => array( 'a' => array( 'b' => array( 'c' => 'd' ) ) ) ) );

		ifls_assert( true, 'raise() survived hostile input' );
	}
);

ifls_test(
	'incidents: FAIL-SAFE - a corrupt option store does not throw',
	function () {
		update_option( 'ifls_incidents', 'not-an-array' );

		$all = IFLS_Incident_Reporter::incidents();
		ifls_assert( is_array( $all ), 'incidents() must always return an array' );

		IFLS_Incident_Reporter::raise( 'mail_failure', 'after corruption' );
		IFLS_Incident_Reporter::clear();

		ifls_assert( true, 'survived a corrupt store' );
	}
);
