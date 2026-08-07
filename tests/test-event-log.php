<?php
/**
 * Event log storage, querying, pruning and fail-safety.
 *
 * @package Inkfire_Login_Styler
 */

ifls_test(
	'event log: table is installed',
	function () {
		global $wpdb;
		IFLS_Event_Log::install();
		$table = IFLS_Event_Log::table();
		ifls_assert_eq( $table, $wpdb->get_var( "SHOW TABLES LIKE '{$table}'" ), 'table missing after install()' );
	}
);

ifls_test(
	'event log: install is idempotent',
	function () {
		IFLS_Event_Log::install();
		IFLS_Event_Log::install();
		IFLS_Event_Log::install();
		ifls_assert( true, 'repeated install must not error' );
	}
);

ifls_test(
	'event log: records and reads back an event',
	function () {
		IFLS_Event_Log::clear();
		IFLS_Event_Log::record( 'login_success', array( 'username' => 'alice', 'user_id' => 7 ) );

		$rows = IFLS_Event_Log::query( array( 'event' => 'login_success' ) );

		ifls_assert_eq( 1, count( $rows ) );
		ifls_assert_eq( 'alice', $rows[0]->username );
		ifls_assert_eq( 7, (int) $rows[0]->user_id );
		ifls_assert_eq( 'success', $rows[0]->outcome );
	}
);

ifls_test(
	'event log: every event type gets a sensible outcome',
	function () {
		// A wrong default here is not cosmetic: filtering the log by
		// outcome=failure would surface legitimate activity as failures.
		$expected = array(
			'login_success'   => 'success',
			'logout'          => 'success',
			'registration'    => 'success',
			'reset_requested' => 'success',
			'reset_completed' => 'success',
			'login_failed'    => 'failure',
			'reset_failed'    => 'failure',
			'csrf_blocked'    => 'blocked',
			'lockout'         => 'blocked',
		);

		// Every declared event must be covered by this test.
		foreach ( IFLS_Event_Log::EVENTS as $event ) {
			ifls_assert( isset( $expected[ $event ] ), "event {$event} has no expected outcome in this test" );
		}

		foreach ( $expected as $event => $outcome ) {
			IFLS_Event_Log::clear();
			IFLS_Event_Log::record( $event, array( 'username' => 'x' ) );

			$rows = IFLS_Event_Log::query( array( 'event' => $event ) );
			ifls_assert_eq( 1, count( $rows ), "{$event} was not recorded" );
			ifls_assert_eq( $outcome, $rows[0]->outcome, "wrong outcome for {$event}:" );
		}
	}
);

ifls_test(
	'event log: rejects an unknown event name',
	function () {
		IFLS_Event_Log::clear();
		IFLS_Event_Log::record( 'not_a_real_event', array() );
		ifls_assert_eq( 0, count( IFLS_Event_Log::query( array() ) ), 'unknown events must not be stored' );
	}
);

ifls_test(
	'event log: SECURITY - a reset key is never stored even if passed one',
	function () {
		IFLS_Event_Log::clear();
		IFLS_Event_Log::record(
			'reset_failed',
			array(
				'username' => 'bob',
				'detail'   => array(
					'rp_key' => 'SECRETRESETKEY',
					'pass1'  => 'hunter2',
					'reason' => 'invalidkey',
				),
			)
		);

		$rows = IFLS_Event_Log::query( array() );

		ifls_assert( false === strpos( $rows[0]->detail, 'SECRETRESETKEY' ), 'reset key leaked into the log - account takeover vector' );
		ifls_assert( false === strpos( $rows[0]->detail, 'hunter2' ), 'password leaked into the log' );
		ifls_assert( false !== strpos( $rows[0]->detail, 'invalidkey' ), 'the useful reason should survive' );
	}
);

ifls_test(
	'event log: long user agents are truncated rather than erroring',
	function () {
		IFLS_Event_Log::clear();
		$original                    = isset( $_SERVER['HTTP_USER_AGENT'] ) ? $_SERVER['HTTP_USER_AGENT'] : '';
		$_SERVER['HTTP_USER_AGENT']  = str_repeat( 'A', 5000 );

		IFLS_Event_Log::record( 'login_failed', array( 'username' => 'x' ) );

		$_SERVER['HTTP_USER_AGENT'] = $original;

		$rows = IFLS_Event_Log::query( array() );
		ifls_assert_eq( 1, count( $rows ), 'row should still be written' );
		ifls_assert( strlen( $rows[0]->user_agent ) <= 255, 'user agent not truncated' );
	}
);

ifls_test(
	'event log: query filters by event and outcome',
	function () {
		IFLS_Event_Log::clear();
		IFLS_Event_Log::record( 'login_success', array( 'username' => 'a' ) );
		IFLS_Event_Log::record( 'login_failed', array( 'username' => 'b' ) );

		ifls_assert_eq( 1, count( IFLS_Event_Log::query( array( 'event' => 'login_success' ) ) ) );
		ifls_assert_eq( 1, count( IFLS_Event_Log::query( array( 'outcome' => 'failure' ) ) ) );
		ifls_assert_eq( 2, count( IFLS_Event_Log::query( array() ) ) );
	}
);

ifls_test(
	'event log: search is escaped against LIKE wildcards and injection',
	function () {
		IFLS_Event_Log::clear();
		IFLS_Event_Log::record( 'login_failed', array( 'username' => 'realuser' ) );

		// A bare % must not act as a wildcard matching everything.
		ifls_assert_eq( 0, count( IFLS_Event_Log::query( array( 'search' => '%' ) ) ), 'LIKE wildcard not escaped' );

		// A quote must not break the query.
		$rows = IFLS_Event_Log::query( array( 'search' => "' OR 1=1 -- " ) );
		ifls_assert_eq( 0, count( $rows ), 'SQL injection in search' );

		ifls_assert_eq( 1, count( IFLS_Event_Log::query( array( 'search' => 'realuser' ) ) ) );
	}
);

ifls_test(
	'event log: count_since respects the window',
	function () {
		global $wpdb;
		IFLS_Event_Log::clear();
		IFLS_Event_Log::record( 'csrf_blocked', array() );

		$wpdb->query(
			$wpdb->prepare(
				'INSERT INTO ' . IFLS_Event_Log::table() . ' (created_at, event, user_id, username, ip, user_agent, outcome, detail) VALUES (%s, %s, 0, %s, %s, %s, %s, %s)',
				gmdate( 'Y-m-d H:i:s', time() - 7200 ),
				'csrf_blocked',
				'',
				'',
				'',
				'blocked',
				'{}'
			)
		);

		ifls_assert_eq( 1, IFLS_Event_Log::count_since( 'csrf_blocked', 60 ), 'only the recent row is inside a 60m window' );
		ifls_assert_eq( 2, IFLS_Event_Log::count_since( 'csrf_blocked', 180 ), 'both rows are inside a 180m window' );
	}
);

ifls_test(
	'event log: prune removes only rows past retention',
	function () {
		global $wpdb;
		IFLS_Event_Log::clear();
		IFLS_Event_Log::record( 'login_success', array( 'username' => 'keep' ) );

		$wpdb->query(
			$wpdb->prepare(
				'INSERT INTO ' . IFLS_Event_Log::table() . ' (created_at, event, user_id, username, ip, user_agent, outcome, detail) VALUES (%s, %s, 0, %s, %s, %s, %s, %s)',
				gmdate( 'Y-m-d H:i:s', time() - ( 200 * DAY_IN_SECONDS ) ),
				'login_success',
				'drop',
				'',
				'',
				'success',
				'{}'
			)
		);

		IFLS_Event_Log::prune();

		$rows = IFLS_Event_Log::query( array() );
		ifls_assert_eq( 1, count( $rows ), 'exactly one row should survive' );
		ifls_assert_eq( 'keep', $rows[0]->username );
	}
);

ifls_test(
	'event log: logging can be switched off',
	function () {
		IFLS_Event_Log::clear();
		update_option( 'ifls_diagnostics_settings', array( 'logging_enabled' => false ) );

		IFLS_Event_Log::record( 'login_success', array( 'username' => 'nope' ) );

		delete_option( 'ifls_diagnostics_settings' );

		ifls_assert_eq( 0, count( IFLS_Event_Log::query( array() ) ), 'nothing should be logged when disabled' );
	}
);

ifls_test(
	'event log: FAIL-SAFE - recording with the table dropped does not throw',
	function () {
		global $wpdb;
		$table = IFLS_Event_Log::table();

		$wpdb->query( "DROP TABLE IF EXISTS {$table}" );
		$suppress = $wpdb->suppress_errors( true );
		$show     = $wpdb->hide_errors();

		// Any of these throwing would mean a broken table breaks login.
		IFLS_Event_Log::record( 'login_success', array( 'username' => 'nobody' ) );
		IFLS_Event_Log::count_since( 'login_success', 60 );
		IFLS_Event_Log::query( array() );
		IFLS_Event_Log::prune();

		$wpdb->suppress_errors( $suppress );
		IFLS_Event_Log::install();

		ifls_assert( true, 'event log survived a missing table' );
	}
);

ifls_test(
	'event log: FAIL-SAFE - query returns an array even when broken',
	function () {
		global $wpdb;
		$table = IFLS_Event_Log::table();

		$wpdb->query( "DROP TABLE IF EXISTS {$table}" );
		$suppress = $wpdb->suppress_errors( true );

		$rows  = IFLS_Event_Log::query( array() );
		$count = IFLS_Event_Log::count_since( 'login_success', 60 );

		$wpdb->suppress_errors( $suppress );
		IFLS_Event_Log::install();

		ifls_assert( is_array( $rows ), 'query() must always return an array' );
		ifls_assert_eq( 0, $count, 'count_since() must return 0 when unavailable' );
	}
);
