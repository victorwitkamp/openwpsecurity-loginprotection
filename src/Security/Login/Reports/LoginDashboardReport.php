<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\Reports;

use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\Events\LoginEventLookup;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\Events\LoginEventTable;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class LoginDashboardReport {
	private LoginEventLookup $login_event_lookup;
	private LoginEventTable $login_event_table;

	public function __construct( LoginEventLookup $login_event_lookup, LoginEventTable $login_event_table ) {
		$this->login_event_lookup = $login_event_lookup;
		$this->login_event_table  = $login_event_table;
	}

	public function summary( ?int $period_seconds ): array {
		global $wpdb;

		$table  = $this->login_event_table->name();
		$params = array();
		$sql    = "SELECT
				SUM(CASE WHEN event_type IN ('success_login', 'failed_login', 'blocked_login') THEN 1 ELSE 0 END) AS total_attempts,
				SUM(CASE WHEN event_type = 'success_login' THEN 1 ELSE 0 END) AS successful_attempts,
				SUM(CASE WHEN event_type = 'failed_login' THEN 1 ELSE 0 END) AS failed_attempts,
				SUM(CASE WHEN event_type = 'blocked_login' THEN 1 ELSE 0 END) AS blocked_attempts,
				SUM(CASE WHEN event_type = 'login_lockout' THEN 1 ELSE 0 END) AS lockouts,
				SUM(CASE WHEN event_type = 'permanent_ban_created' THEN 1 ELSE 0 END) AS permanent_bans,
				COUNT(DISTINCT CASE WHEN event_type IN ('success_login', 'failed_login', 'blocked_login') THEN ip_address ELSE NULL END) AS unique_ips
			FROM {$table}
			WHERE 1=1";

		if ( null !== $period_seconds ) {
			$sql     .= ' AND created_at >= %s';
			$params[] = gmdate( 'Y-m-d H:i:s', time() - $period_seconds );
		}

		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name is generated internally from $wpdb->prefix.
		if ( empty( $params ) ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Query contains no untrusted input when no period filter is applied.
			$row = $wpdb->get_row( $sql, ARRAY_A );
		} else {
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Query is prepared immediately before execution.
			$row = $wpdb->get_row( $wpdb->prepare( $sql, $params ), ARRAY_A );
		}
		// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared

		return array(
			'total_attempts'      => isset( $row['total_attempts'] ) ? (int) $row['total_attempts'] : 0,
			'successful_attempts' => isset( $row['successful_attempts'] ) ? (int) $row['successful_attempts'] : 0,
			'failed_attempts'     => isset( $row['failed_attempts'] ) ? (int) $row['failed_attempts'] : 0,
			'blocked_attempts'    => isset( $row['blocked_attempts'] ) ? (int) $row['blocked_attempts'] : 0,
			'lockouts'            => isset( $row['lockouts'] ) ? (int) $row['lockouts'] : 0,
			'permanent_bans'      => isset( $row['permanent_bans'] ) ? (int) $row['permanent_bans'] : 0,
			'unique_ips'          => isset( $row['unique_ips'] ) ? (int) $row['unique_ips'] : 0,
		);
	}

	public function countries_for_metric( string $metric, ?int $period_seconds, int $limit = 8 ): array {
		return $this->login_event_lookup->country_totals_matching_types( $this->metric_event_types( $metric ), array(), $period_seconds, $limit );
	}

	public function recent_successful_logins( ?int $period_seconds, int $limit = 10 ): array {
		return $this->login_event_lookup->find_rows_matching_types(
			array( 'success_login' ),
			array(),
			$period_seconds,
			$limit,
			0
		);
	}

	public function recent_failed_logins( ?int $period_seconds, int $limit = 10 ): array {
		return $this->login_event_lookup->find_rows_matching_types(
			array( 'failed_login' ),
			array(),
			$period_seconds,
			$limit,
			0
		);
	}

	public function recent_blocked_logins( ?int $period_seconds, int $limit = 10 ): array {
		return $this->login_event_lookup->find_rows_matching_types(
			array( 'blocked_login' ),
			array(),
			$period_seconds,
			$limit,
			0
		);
	}

	public function recent_permanent_bans( ?int $period_seconds, int $limit = 10 ): array {
		return $this->login_event_lookup->find_rows_matching_types(
			array( 'permanent_ban_created' ),
			array(),
			$period_seconds,
			$limit,
			0
		);
	}

	private function metric_event_types( string $metric ): array {
		if ( 'failed_attempts' === $metric ) {
			return array( 'failed_login', 'blocked_login' );
		}

		if ( 'successful_attempts' === $metric ) {
			return array( 'success_login' );
		}

		return array( 'success_login', 'failed_login', 'blocked_login' );
	}
}
