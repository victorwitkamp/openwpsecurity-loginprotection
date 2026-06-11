<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\Reports;

use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Ban\PermanentBanRepository;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\LoginAttemptRepository;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\LoginLockoutRepository;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class LoginActivityLookup {
	private LoginAttemptRepository $login_attempts;
	private LoginLockoutRepository $login_lockouts;
	private PermanentBanRepository $permanent_bans;

	public function __construct( LoginAttemptRepository $login_attempts, LoginLockoutRepository $login_lockouts, PermanentBanRepository $permanent_bans ) {
		$this->login_attempts = $login_attempts;
		$this->login_lockouts = $login_lockouts;
		$this->permanent_bans = $permanent_bans;
	}

	public function count( array $event_types, array $filters = array(), ?int $period_seconds = null ): int {
		global $wpdb;

		$query = $this->union_query( $event_types, $filters, $period_seconds );

		if ( '' === $query['sql'] ) {
			return 0;
		}

		$sql = 'SELECT COUNT(*) FROM (' . $query['sql'] . ') activity_rows';

		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Query is built from internal table names and prepared immediately before execution.
		return (int) $wpdb->get_var( $wpdb->prepare( $sql, $query['params'] ) );
	}

	public function rows( array $event_types, array $filters = array(), ?int $period_seconds = null, ?int $limit = null, int $offset = 0 ): array {
		global $wpdb;

		$query = $this->union_query( $event_types, $filters, $period_seconds );

		if ( '' === $query['sql'] ) {
			return array();
		}

		$sql    = 'SELECT * FROM (' . $query['sql'] . ') activity_rows ORDER BY created_at DESC';
		$params = $query['params'];

		if ( null !== $limit ) {
			$sql     .= ' LIMIT %d OFFSET %d';
			$params[] = max( 1, $limit );
			$params[] = max( 0, $offset );
		}

		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Query is built from internal table names and prepared immediately before execution.
		$rows = $wpdb->get_results( $wpdb->prepare( $sql, $params ), ARRAY_A );

		return is_array( $rows ) ? $rows : array();
	}

	public function country_totals( array $event_types, array $filters = array(), ?int $period_seconds = null, ?int $limit = 8 ): array {
		global $wpdb;

		$query = $this->union_query( $event_types, $filters, $period_seconds );

		if ( '' === $query['sql'] ) {
			return array();
		}

		$params = $query['params'];
		$sql    = "SELECT
				CASE WHEN country_code = '' THEN '--' ELSE country_code END AS country_code,
				CASE WHEN country_name = '' THEN 'Unknown' ELSE country_name END AS country_name,
				COUNT(*) AS total
			FROM ({$query['sql']}) activity_rows
			GROUP BY
				CASE WHEN country_code = '' THEN '--' ELSE country_code END,
				CASE WHEN country_name = '' THEN 'Unknown' ELSE country_name END
			ORDER BY total DESC";

		if ( null !== $limit ) {
			$sql     .= ' LIMIT %d';
			$params[] = max( 1, $limit );
		}

		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Query is built from internal table names and prepared immediately before execution.
		$rows = $wpdb->get_results( $wpdb->prepare( $sql, $params ), ARRAY_A );

		if ( ! is_array( $rows ) ) {
			return array();
		}

		return array_map(
			static function ( array $row ): array {
				return array(
					'country_code' => (string) ( $row['country_code'] ?? '--' ),
					'country_name' => (string) ( $row['country_name'] ?? 'Unknown' ),
					'total'        => (int) ( $row['total'] ?? 0 ),
				);
			},
			$rows
		);
	}

	public function country_options( array $event_types, array $filters = array(), ?int $period_seconds = null ): array {
		return array_map(
			static function ( array $row ): array {
				return array(
					'code'  => (string) $row['country_code'],
					'label' => trim( (string) $row['country_code'] . ' ' . (string) $row['country_name'] ),
				);
			},
			$this->country_totals( $event_types, $filters, $period_seconds, null )
		);
	}

	private function union_query( array $event_types, array $filters, ?int $period_seconds ): array {
		$queries = array();
		$params  = array();

		if ( array_intersect( $event_types, array( 'success_login', 'failed_login', 'blocked_login' ) ) ) {
			$queries[] = $this->attempt_query( $event_types, $filters, $period_seconds, $params );
		}

		if ( in_array( 'login_lockout', $event_types, true ) ) {
			$queries[] = $this->lockout_query( $filters, $period_seconds, $params );
		}

		if ( in_array( 'permanent_ban_created', $event_types, true ) ) {
			$queries[] = $this->permanent_ban_query( $filters, $period_seconds, $params );
		}

		$queries = array_filter( $queries );

		return array(
			'sql'    => implode( ' UNION ALL ', $queries ),
			'params' => $params,
		);
	}

	private function attempt_query( array $event_types, array $filters, ?int $period_seconds, array &$params ): string {
		$attempt_types = array_values( array_intersect( $event_types, array( 'success_login', 'failed_login', 'blocked_login' ) ) );

		if ( ! empty( $filters['event_type'] ) ) {
			if ( ! in_array( (string) $filters['event_type'], $attempt_types, true ) ) {
				return '';
			}

			$attempt_types = array( (string) $filters['event_type'] );
		}

		$placeholder = implode( ', ', array_fill( 0, count( $attempt_types ), '%s' ) );
		array_push( $params, ...$attempt_types );

		$sql = "SELECT created_at, attempt_type AS event_type, ip_address, country_code, country_name, username, password_value, password_mask, user_agent, request_uri, lockout_expires_at, evidence_json AS details
			FROM {$this->login_attempts->name()}
			WHERE attempt_type IN ({$placeholder})";

		return $this->apply_common_filters( $sql, $params, $filters, $period_seconds, false );
	}

	private function lockout_query( array $filters, ?int $period_seconds, array &$params ): string {
		if ( ! empty( $filters['event_type'] ) && 'login_lockout' !== (string) $filters['event_type'] ) {
			return '';
		}

		$sql = "SELECT created_at, 'login_lockout' AS event_type, ip_address, country_code, country_name, username, '' AS password_value, '' AS password_mask, user_agent, request_uri, expires_at AS lockout_expires_at, evidence_json AS details
			FROM {$this->login_lockouts->name()}
			WHERE 1=1";

		return $this->apply_common_filters( $sql, $params, $filters, $period_seconds, false );
	}

	private function permanent_ban_query( array $filters, ?int $period_seconds, array &$params ): string {
		if ( ! empty( $filters['event_type'] ) && 'permanent_ban_created' !== (string) $filters['event_type'] ) {
			return '';
		}

		$sql = "SELECT created_at, 'permanent_ban_created' AS event_type, ip_address, country_code, country_name, '' AS username, '' AS password_value, '' AS password_mask, user_agent, request_uri, NULL AS lockout_expires_at, evidence_json AS details
			FROM {$this->permanent_bans->name()}
			WHERE 1=1";

		return $this->apply_common_filters( $sql, $params, $filters, $period_seconds, true );
	}

	private function apply_common_filters( string $sql, array &$params, array $filters, ?int $period_seconds, bool $skip_username_filter ): string {
		global $wpdb;

		if ( null !== $period_seconds ) {
			$sql     .= ' AND created_at >= %s';
			$params[] = gmdate( 'Y-m-d H:i:s', time() - $period_seconds );
		}

		if ( ! empty( $filters['country_code'] ) ) {
			$sql     .= ' AND country_code = %s';
			$params[] = (string) $filters['country_code'];
		}

		if ( ! empty( $filters['ip_address'] ) ) {
			$sql     .= ' AND ip_address LIKE %s';
			$params[] = '%' . $wpdb->esc_like( (string) $filters['ip_address'] ) . '%';
		}

		if ( $skip_username_filter && ! empty( $filters['username'] ) ) {
			$sql .= ' AND 1=0';
		}

		if ( ! $skip_username_filter && ! empty( $filters['username'] ) ) {
			$sql     .= ' AND username LIKE %s';
			$params[] = '%' . $wpdb->esc_like( (string) $filters['username'] ) . '%';
		}

		if ( ! empty( $filters['request_uri'] ) ) {
			$sql     .= ' AND request_uri LIKE %s';
			$params[] = '%' . $wpdb->esc_like( (string) $filters['request_uri'] ) . '%';
		}

		return $sql;
	}
}
