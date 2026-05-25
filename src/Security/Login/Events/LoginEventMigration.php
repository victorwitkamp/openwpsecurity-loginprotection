<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\Events;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class LoginEventMigration {
	private const OPTION_NAME = 'openwpsecurity_loginprotection_login_events_migrated';

	private LoginEventTable $login_event_table;

	public function __construct( LoginEventTable $login_event_table ) {
		$this->login_event_table = $login_event_table;
	}

	public function maybe_migrate(): void {
		if ( '1' === (string) get_option( self::OPTION_NAME, '' ) ) {
			return;
		}

		$this->migrate_from_legacy_login_events();
		$this->migrate_from_general_events();
		update_option( self::OPTION_NAME, '1', false );
	}

	private function migrate_from_legacy_login_events(): void {
		global $wpdb;

		$legacy_login_table = $wpdb->prefix . 'vw_firewall_login_events';

		if ( ! $this->table_exists( $legacy_login_table ) ) {
			return;
		}

		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table names are generated internally from $wpdb->prefix.
		$wpdb->query(
			"INSERT INTO {$this->login_event_table->name()} (
				created_at,
				event_type,
				ip_address,
				country_code,
				country_name,
				username,
				password_value,
				password_mask,
				password_hash,
				user_agent,
				request_uri,
				lockout_expires_at,
				details
			)
			SELECT
				created_at,
				event_type,
				ip_address,
				country_code,
				country_name,
				username,
				password_value,
				password_mask,
				password_hash,
				user_agent,
				request_uri,
				lockout_expires_at,
				details
			FROM {$legacy_login_table}"
		);
		// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared
	}

	private function migrate_from_general_events(): void {
		global $wpdb;

		$legacy_event_table = $wpdb->prefix . 'vw_firewall_events';

		if ( ! $this->table_exists( $legacy_event_table ) ) {
			return;
		}

		$legacy_source_pattern   = '%"source":"login_lockout"%';
		$current_source_pattern  = '%"source":"login_protection"%';
		$legacy_source_fragment  = '"source":"login_lockout"';
		$current_source_fragment = '"source":"login_protection"';

		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table names are generated internally from $wpdb->prefix.
		$wpdb->query(
			$wpdb->prepare(
				"INSERT INTO {$this->login_event_table->name()} (
					created_at,
					event_type,
					ip_address,
					country_code,
					country_name,
					username,
					password_value,
					password_mask,
					password_hash,
					user_agent,
					request_uri,
					lockout_expires_at,
					details
				)
				SELECT
					created_at,
					event_type,
					ip_address,
					country_code,
					country_name,
					username,
					password_value,
					password_mask,
					password_hash,
					user_agent,
					request_uri,
					lockout_expires_at,
					CASE
						WHEN event_type = %s AND details LIKE %s THEN REPLACE(details, %s, %s)
						ELSE details
					END AS details
				FROM {$legacy_event_table}
				WHERE event_type IN ('success_login', 'failed_login', 'blocked_login', 'login_lockout')
					OR (event_type = %s AND (details LIKE %s OR details LIKE %s))",
				'permanent_ban_created',
				$legacy_source_pattern,
				$legacy_source_fragment,
				$current_source_fragment,
				'permanent_ban_created',
				$legacy_source_pattern,
				$current_source_pattern
			)
		);

		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$legacy_event_table}
				WHERE event_type IN ('success_login', 'failed_login', 'blocked_login', 'login_lockout')
					OR (event_type = %s AND (details LIKE %s OR details LIKE %s))",
				'permanent_ban_created',
				$legacy_source_pattern,
				$current_source_pattern
			)
		);
		// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared
	}

	private function table_exists( string $table_name ): bool {
		global $wpdb;

		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Table name is prepared immediately before execution.
		$found_table = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table_name ) );

		return $found_table === $table_name;
	}
}
