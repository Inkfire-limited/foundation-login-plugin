<?php
/**
 * Regression tests for the four maintenance issues found in the 2.0.28 audit.
 *
 * @package Inkfire_Login_Styler
 */

$ifls_plugin_src = file_get_contents( dirname( __DIR__ ) . '/inkfire-login-styler.php' );
$ifls_uninst_src = file_get_contents( dirname( __DIR__ ) . '/uninstall.php' );

// Call the callback directly rather than firing admin_enqueue_scripts, which
// would also run every other plugin's callbacks and fail on missing admin
// context. This is why the callback is a named function, not a closure.
ifls_test(
	'fix A: login stylesheet is not enqueued on unrelated admin pages',
	function () {
		wp_dequeue_style( 'inkfire-login' );
		wp_deregister_style( 'inkfire-login' );

		ifls_enqueue_admin_assets( 'edit.php' );

		ifls_assert(
			! wp_style_is( 'inkfire-login', 'enqueued' ),
			'login CSS leaked onto edit.php - it should only load on this plugin\'s own screens'
		);
	}
);

ifls_test(
	'fix A: login stylesheet IS still enqueued on the plugin\'s own screen',
	function () {
		wp_dequeue_style( 'inkfire-login' );
		wp_deregister_style( 'inkfire-login' );

		ifls_enqueue_admin_assets( 'foundation_page_foundation-login-styler' );

		ifls_assert(
			wp_style_is( 'inkfire-login', 'enqueued' ),
			'login CSS should still load on the plugin\'s own admin screen'
		);
	}
);

ifls_test(
	'fix B: no external CDN is referenced anywhere in the plugin',
	function () use ( $ifls_plugin_src ) {
		ifls_assert( false === strpos( $ifls_plugin_src, 'cdnjs.cloudflare.com' ), 'Font Awesome CDN still referenced' );
		ifls_assert( false === strpos( $ifls_plugin_src, 'fa-brands' ), 'Font Awesome icon classes still used' );
	}
);

ifls_test(
	'fix B: social icons render as inline SVG',
	function () {
		$svg = ifls_social_icon( 'facebook' );
		ifls_assert( 0 === strpos( $svg, '<svg' ), 'expected inline SVG markup' );
		ifls_assert( false !== strpos( $svg, 'aria-hidden="true"' ), 'decorative icon must be aria-hidden' );
		ifls_assert( false !== strpos( $svg, 'focusable="false"' ), 'SVG must not be focusable in IE/Edge' );
	}
);

ifls_test(
	'fix B: every social network used on the login page has an icon',
	function () {
		foreach ( array( 'facebook', 'instagram', 'linkedin', 'x', 'tiktok' ) as $network ) {
			ifls_assert( '' !== ifls_social_icon( $network ), "missing icon for {$network}" );
		}
	}
);

ifls_test(
	'fix B: an unknown network returns an empty string, not a broken tag',
	function () {
		ifls_assert_eq( '', ifls_social_icon( 'myspace' ) );
	}
);

ifls_test(
	'fix B: icon markup is well-formed and the path data is escaped',
	function () {
		foreach ( array( 'facebook', 'instagram', 'linkedin', 'x', 'tiktok' ) as $network ) {
			$svg = ifls_social_icon( $network );

			ifls_assert_eq( 1, substr_count( $svg, '<svg' ), "{$network}: expected exactly one svg element" );
			ifls_assert_eq( 1, substr_count( $svg, '<path' ), "{$network}: expected exactly one path element" );
			ifls_assert( '</svg>' === substr( $svg, -6 ), "{$network}: markup is not closed" );

			// The d attribute must contain no raw quote that could close it early.
			ifls_assert(
				(bool) preg_match( '/ d="([^"]*)"/', $svg, $m ),
				"{$network}: path data attribute not found or unterminated"
			);
			ifls_assert( false === strpos( $m[1], '<' ), "{$network}: unescaped markup inside path data" );

			// Must parse as valid XML.
			$prev = libxml_use_internal_errors( true );
			$doc  = simplexml_load_string( $svg );
			libxml_clear_errors();
			libxml_use_internal_errors( $prev );
			ifls_assert( false !== $doc, "{$network}: SVG is not well-formed XML" );
		}
	}
);

ifls_test(
	'fix C: uninstall cleans up transients via the API, not just raw SQL',
	function () use ( $ifls_uninst_src ) {
		ifls_assert(
			false !== strpos( $ifls_uninst_src, 'delete_transient' ),
			'uninstall must use delete_transient() - raw SQL is a no-op with a persistent object cache'
		);
	}
);

ifls_test(
	'fix C: uninstall removes the 2.1.0 additions',
	function () use ( $ifls_uninst_src ) {
		foreach ( array( 'ifls_diagnostics_settings', 'ifls_incidents', 'ifls_events_db_version', 'ifls_events' ) as $needle ) {
			ifls_assert( false !== strpos( $ifls_uninst_src, $needle ), "uninstall does not clean up {$needle}" );
		}
		ifls_assert( false !== strpos( $ifls_uninst_src, 'wp_clear_scheduled_hook' ), 'uninstall must clear scheduled events' );
	}
);

ifls_test(
	'fix D: the no-op login_footer hook is gone',
	function () use ( $ifls_plugin_src ) {
		ifls_assert(
			false === strpos( $ifls_plugin_src, "login_footer', '__return_null'" ),
			'no-op login_footer hook still present - it removes nothing'
		);
	}
);
