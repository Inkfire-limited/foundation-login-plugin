<?php
/**
 * Test runner for Foundation - Inkfire Login.
 *
 * Usage: php tests/run.php <wp-root> [filter]
 *
 * Exit code 0 when everything passes, 1 on any failure, 2 on bad usage.
 *
 * @package Inkfire_Login_Styler
 */

require_once __DIR__ . '/bootstrap.php';

$wp_root = isset( $argv[1] ) ? $argv[1] : '';
$filter  = isset( $argv[2] ) ? $argv[2] : '';

if ( ! $wp_root ) {
	fwrite( STDERR, "usage: php tests/run.php <wp-root> [filter]\n" );
	exit( 2 );
}

$GLOBALS['ifls_results'] = array(
	'pass'     => 0,
	'fail'     => 0,
	'failures' => array(),
);

/**
 * Run one test case.
 *
 * @param string   $name Human-readable name.
 * @param callable $fn   Test body; throws on failure.
 */
function ifls_test( $name, callable $fn ) {
	try {
		$fn();
		$GLOBALS['ifls_results']['pass']++;
		printf( "  [ok]   %s\n", $name );
	} catch ( Throwable $e ) {
		$GLOBALS['ifls_results']['fail']++;
		$GLOBALS['ifls_results']['failures'][] = $name . ' -- ' . $e->getMessage();
		printf( "  [FAIL] %s\n         %s\n", $name, $e->getMessage() );
	}
}

/**
 * Assert a condition is truthy.
 *
 * @param mixed  $cond Condition.
 * @param string $msg  Failure message.
 */
function ifls_assert( $cond, $msg = 'assertion failed' ) {
	if ( ! $cond ) {
		throw new RuntimeException( $msg );
	}
}

/**
 * Assert strict equality.
 *
 * @param mixed  $expected Expected value.
 * @param mixed  $actual   Actual value.
 * @param string $msg      Context for the failure message.
 */
function ifls_assert_eq( $expected, $actual, $msg = '' ) {
	if ( $expected !== $actual ) {
		throw new RuntimeException(
			sprintf(
				'%s expected %s, got %s',
				$msg,
				var_export( $expected, true ),
				var_export( $actual, true )
			)
		);
	}
}

ifls_test_boot( $wp_root );

printf( "\nFoundation Inkfire Login test suite\n" );
printf( "WordPress %s / PHP %s / plugin %s\n", get_bloginfo( 'version' ), PHP_VERSION, defined( 'IFLS_VERSION' ) ? IFLS_VERSION : 'not loaded' );

$files = glob( __DIR__ . '/test-*.php' );
sort( $files );

foreach ( $files as $file ) {
	if ( '' !== $filter && false === strpos( basename( $file ), $filter ) ) {
		continue;
	}
	printf( "\n%s\n", basename( $file ) );
	require $file;
}

$results = $GLOBALS['ifls_results'];

printf( "\n=== %d passed, %d failed ===\n", $results['pass'], $results['fail'] );

foreach ( $results['failures'] as $failure ) {
	printf( "FAILED: %s\n", $failure );
}

exit( $results['fail'] > 0 ? 1 : 0 );
