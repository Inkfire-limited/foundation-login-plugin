<?php
/**
 * Diagnostics settings: defaults, precedence, sanitisation.
 *
 * Sanitisation matters more than it looks: this option is written from a form
 * post, so anything that reaches update_option() unchecked is an injection
 * surface and a way to break the site's own cron and alerting.
 *
 * @package Inkfire_Login_Styler
 */

ifls_test(
	'settings: defaults are returned when nothing is stored',
	function () {
		delete_option( 'ifls_diagnostics_settings' );
		ifls_assert_eq( 90, ifls_diag_setting( 'retention_days' ) );
		ifls_assert_eq( 'webmaster@inkfire.co.uk', ifls_diag_setting( 'report_email' ) );
		ifls_assert_eq( 5, ifls_diag_setting( 'threshold_count' ) );
		ifls_assert_eq( 60, ifls_diag_setting( 'threshold_minutes' ) );
		ifls_assert_eq( 6, ifls_diag_setting( 'cooldown_hours' ) );
		ifls_assert_eq( true, ifls_diag_setting( 'logging_enabled' ) );
		ifls_assert_eq( true, ifls_diag_setting( 'reporting_enabled' ) );
	}
);

ifls_test(
	'settings: an unknown key returns null rather than a notice',
	function () {
		ifls_assert_eq( null, ifls_diag_setting( 'no_such_setting' ) );
	}
);

ifls_test(
	'settings: stored values override defaults',
	function () {
		update_option( 'ifls_diagnostics_settings', array( 'retention_days' => 30 ) );
		ifls_assert_eq( 30, ifls_diag_setting( 'retention_days' ) );
		// Keys absent from the stored array still fall back to defaults.
		ifls_assert_eq( 5, ifls_diag_setting( 'threshold_count' ) );
		delete_option( 'ifls_diagnostics_settings' );
	}
);

ifls_test(
	'settings: a corrupt option does not break the accessor',
	function () {
		update_option( 'ifls_diagnostics_settings', 'not-an-array' );
		ifls_assert_eq( 90, ifls_diag_setting( 'retention_days' ), 'should fall back to defaults' );
		delete_option( 'ifls_diagnostics_settings' );
	}
);

ifls_test(
	'settings: sanitise rejects a malformed email',
	function () {
		$out = ifls_diag_sanitize( array( 'report_email' => 'not-an-email' ) );
		ifls_assert_eq( 'webmaster@inkfire.co.uk', $out['report_email'], 'bad email must fall back to the default' );
	}
);

ifls_test(
	'settings: sanitise accepts a valid email',
	function () {
		$out = ifls_diag_sanitize( array( 'report_email' => 'alerts@example.com' ) );
		ifls_assert_eq( 'alerts@example.com', $out['report_email'] );
	}
);

ifls_test(
	'settings: sanitise makes mail header injection impossible',
	function () {
		// The property that matters is that no CR or LF can reach the
		// recipient - that is what would let an extra header be injected.
		// Residual text from the payload is inert once the CRLF is gone.
		$payloads = array(
			"a@b.com\nBcc: evil@example.com",
			"a@b.com\r\nBcc: evil@example.com",
			"a@b.com\rCc: evil@example.com",
		);

		foreach ( $payloads as $payload ) {
			$out = ifls_diag_sanitize( array( 'report_email' => $payload ) );

			ifls_assert(
				! preg_match( '/[\r\n]/', $out['report_email'] ),
				'CR/LF survived into the recipient - header injection possible'
			);
			ifls_assert_eq(
				1,
				substr_count( $out['report_email'], '@' ),
				'recipient must resolve to a single address'
			);
		}
	}
);

ifls_test(
	'settings: sanitise clamps absurd and negative numbers',
	function () {
		$out = ifls_diag_sanitize(
			array(
				'retention_days'    => 99999,
				'threshold_count'   => 0,
				'threshold_minutes' => -5,
				'cooldown_hours'    => 100000,
			)
		);
		ifls_assert_eq( 365, $out['retention_days'], 'retention should clamp to 365' );
		ifls_assert_eq( 1, $out['threshold_count'], 'threshold should clamp to at least 1' );
		ifls_assert_eq( 5, $out['threshold_minutes'], 'window should clamp to at least 5' );
		ifls_assert_eq( 168, $out['cooldown_hours'], 'cooldown should clamp to 168' );
	}
);

ifls_test(
	'settings: sanitise casts checkboxes, treating absent as off',
	function () {
		$out = ifls_diag_sanitize( array( 'logging_enabled' => 'on', 'reporting_enabled' => '1' ) );
		ifls_assert_eq( true, $out['logging_enabled'] );
		ifls_assert_eq( true, $out['reporting_enabled'] );

		$out = ifls_diag_sanitize( array() );
		ifls_assert_eq( false, $out['logging_enabled'], 'an unchecked box means false' );
		ifls_assert_eq( false, $out['reporting_enabled'] );
	}
);

ifls_test(
	'settings: sanitise ignores unknown keys entirely',
	function () {
		$out = ifls_diag_sanitize( array( 'evil_key' => 'payload', 'retention_days' => 10 ) );
		ifls_assert( ! array_key_exists( 'evil_key', $out ), 'unknown keys must not be persisted' );
		ifls_assert_eq( 10, $out['retention_days'] );
	}
);

ifls_test(
	'settings: sanitise survives a non-array input',
	function () {
		$out = ifls_diag_sanitize( 'garbage' );
		ifls_assert( is_array( $out ), 'must always return an array' );
		ifls_assert_eq( 90, $out['retention_days'] );
	}
);

ifls_test(
	'settings: the kill switch reports enabled by default',
	function () {
		ifls_assert_eq( true, ifls_diag_enabled() );
	}
);

ifls_test(
	'settings: lock state is reported for constant-pinned fields',
	function () {
		// No constants defined in this process, so nothing should be locked.
		ifls_assert_eq( false, ifls_diag_is_locked( 'report_email' ) );
		ifls_assert_eq( false, ifls_diag_is_locked( 'retention_days' ) );
	}
);
