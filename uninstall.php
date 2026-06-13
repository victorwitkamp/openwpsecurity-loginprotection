<?php
/**
 * Runs when the plugin is deleted from the Plugins screen.
 * Drops all plugin-owned database tables and removes all plugin options.
 */

declare(strict_types=1);

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

global $wpdb;

$tables = array(
	$wpdb->prefix . 'openwpsecurity_loginprotection_login_attempts',
	$wpdb->prefix . 'openwpsecurity_loginprotection_login_lockouts',
	$wpdb->prefix . 'openwpsecurity_loginprotection_temporary_bans',
	$wpdb->prefix . 'openwpsecurity_loginprotection_temporary_ban_counts',
	$wpdb->prefix . 'openwpsecurity_loginprotection_permanent_bans',
);

foreach ( $tables as $table ) {
	$wpdb->query( "DROP TABLE IF EXISTS `{$table}`" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
}

$options = array(
	'openwpsecurity_loginprotection_settings',
	'openwpsecurity_loginprotection_login_attempts_db_version',
	'openwpsecurity_loginprotection_login_lockouts_db_version',
	'openwpsecurity_loginprotection_temporary_bans_db_version',
	'openwpsecurity_loginprotection_temporary_ban_counts_db_version',
	'openwpsecurity_loginprotection_permanent_bans_db_version',
	'openwpsecurity_loginprotection_failed_login_streaks',
);

foreach ( $options as $option ) {
	delete_option( $option );
}

wp_clear_scheduled_hook( 'openwpsecurity_loginprotection_purge_expired_temporary_bans' );
wp_clear_scheduled_hook( 'openwpsecurity_loginprotection_delete_expired_rows' );
