<?php
/**
 * Mail transport diagnostics.
 *
 * Exists because diagnosing "the reset email never arrived" previously meant
 * hand-writing throwaway scripts against a live site.
 *
 * @package Inkfire_Login_Styler
 */

ifls_test(
	'mail diag: a test send reports success and transport details',
	function () {
		ifls_reset_mail();

		$result = IFLS_Mail_Diagnostics::send_test( 'nobody@example.com' );

		ifls_assert_eq( true, $result['sent'] );
		ifls_assert_eq( 'nobody@example.com', $result['to'] );
		ifls_assert( is_array( $result['transport'] ), 'transport info missing' );
		ifls_assert_eq( 1, count( ifls_sent_mail() ), 'exactly one message should be attempted' );
	}
);

ifls_test(
	'mail diag: a test send reports failure without throwing',
	function () {
		ifls_force_mail_failure( true );
		$result = IFLS_Mail_Diagnostics::send_test( 'nobody@example.com' );
		ifls_force_mail_failure( false );

		ifls_assert_eq( false, $result['sent'] );
		ifls_assert( is_array( $result ), 'must still return a structured result' );
	}
);

ifls_test(
	'mail diag: an invalid recipient is rejected rather than attempted',
	function () {
		ifls_reset_mail();

		$result = IFLS_Mail_Diagnostics::send_test( 'not-an-email' );

		ifls_assert_eq( false, $result['sent'] );
		ifls_assert( '' !== $result['error'], 'should explain why it refused' );
		ifls_assert_eq( 0, count( ifls_sent_mail() ), 'nothing should be attempted for an invalid address' );
	}
);

ifls_test(
	'mail diag: transport_info returns the expected shape',
	function () {
		$info = IFLS_Mail_Diagnostics::transport_info();

		foreach ( array( 'sendmail_path', 'wp_mail_from', 'admin_email' ) as $key ) {
			ifls_assert( array_key_exists( $key, $info ), "missing {$key}" );
		}
	}
);

ifls_test(
	'mail diag: dns_info returns the expected shape',
	function () {
		$dns = IFLS_Mail_Diagnostics::dns_info();

		foreach ( array( 'mx', 'spf', 'dmarc', 'available' ) as $key ) {
			ifls_assert( array_key_exists( $key, $dns ), "missing {$key}" );
		}
		ifls_assert( is_array( $dns['mx'] ), 'mx must be an array' );
	}
);

ifls_test(
	'mail diag: dns_info is cached so the admin page does not re-resolve',
	function () {
		$domain = wp_parse_url( home_url(), PHP_URL_HOST );
		delete_transient( 'ifls_dns_' . md5( $domain ) );

		IFLS_Mail_Diagnostics::dns_info();

		ifls_assert(
			false !== get_transient( 'ifls_dns_' . md5( $domain ) ),
			'DNS result was not cached'
		);
	}
);

ifls_test(
	'mail diag: KEY WARNING - external MX with local sending is flagged',
	function () {
		$warnings = IFLS_Mail_Diagnostics::warnings(
			array( 'mailer' => 'mail', 'sender' => 'x@example.com' ),
			array( 'mx' => array( 'baseuk-org01b.mail.protection.outlook.com' ), 'spf' => '', 'dmarc' => '' )
		);

		ifls_assert( count( $warnings ) > 0, 'the base-uk.org pattern must be flagged' );
		ifls_assert(
			false !== stripos( implode( ' ', $warnings ), 'externally' ),
			'warning should explain that email is hosted externally'
		);
	}
);

ifls_test(
	'mail diag: an empty envelope sender is flagged',
	function () {
		$warnings = IFLS_Mail_Diagnostics::warnings(
			array( 'mailer' => 'mail', 'sender' => '' ),
			array( 'mx' => array(), 'spf' => '', 'dmarc' => '' )
		);

		ifls_assert(
			false !== stripos( implode( ' ', $warnings ), 'return-path' ),
			'an empty envelope sender should be flagged - it breaks DMARC alignment'
		);
	}
);

ifls_test(
	'mail diag: a clean SMTP setup produces no warnings',
	function () {
		$warnings = IFLS_Mail_Diagnostics::warnings(
			array( 'mailer' => 'smtp', 'sender' => 'noreply@example.com', 'smtp_auth' => true ),
			array( 'mx' => array( 'mail.protection.outlook.com' ), 'spf' => 'v=spf1 -all', 'dmarc' => 'v=DMARC1; p=none' )
		);

		ifls_assert_eq( 0, count( $warnings ), 'a properly configured SMTP setup should not warn' );
	}
);

ifls_test(
	'mail diag: local sending with local MX is not flagged as external',
	function () {
		$warnings = IFLS_Mail_Diagnostics::warnings(
			array( 'mailer' => 'mail', 'sender' => 'x@example.com' ),
			array( 'mx' => array( 'mail.myownserver.co.uk' ), 'spf' => '', 'dmarc' => '' )
		);

		ifls_assert(
			false === stripos( implode( ' ', $warnings ), 'externally' ),
			'a self-hosted MX must not be reported as an external provider'
		);
	}
);

ifls_test(
	'mail diag: FAIL-SAFE - warnings survives malformed input',
	function () {
		$warnings = IFLS_Mail_Diagnostics::warnings( array(), array() );
		ifls_assert( is_array( $warnings ), 'must always return an array' );
	}
);
