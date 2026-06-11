<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\Reports;

use VictorWitkamp\OpenWPSecurity\Core\Security\Ban\PermanentBanStore;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\LoginAttemptRepository;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\LoginLockoutRepository;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class LoginDashboardReport {
	private LoginAttemptRepository $login_attempts;
	private LoginLockoutRepository $login_lockouts;
	private PermanentBanStore $ban_store;

	public function __construct( LoginAttemptRepository $login_attempts, LoginLockoutRepository $login_lockouts, PermanentBanStore $ban_store ) {
		$this->login_attempts = $login_attempts;
		$this->login_lockouts = $login_lockouts;
		$this->ban_store      = $ban_store;
	}

	public function summary( int $period_seconds ): array {
		global $wpdb;

		$attempt_table = $this->login_attempts->name();
		$lockout_table = $this->login_lockouts->name();
		$since         = gmdate( 'Y-m-d H:i:s', time() - $period_seconds );
		$sql           = "SELECT
				COUNT(*) AS total_attempts,
				SUM(CASE WHEN attempt_type = 'success_login' THEN 1 ELSE 0 END) AS successful_attempts,
				SUM(CASE WHEN attempt_type = 'failed_login' THEN 1 ELSE 0 END) AS failed_attempts,
				SUM(CASE WHEN attempt_type = 'blocked_login' THEN 1 ELSE 0 END) AS blocked_attempts,
				COUNT(DISTINCT ip_address) AS unique_ips
			FROM {$attempt_table}
			WHERE created_at >= %s";
		$lockout_sql   = "SELECT COUNT(*) FROM {$lockout_table} WHERE created_at >= %s";

		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name is generated internally from $wpdb->prefix.
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Query is prepared immediately before execution.
		$row = $wpdb->get_row( $wpdb->prepare( $sql, $since ), ARRAY_A );
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Query is prepared immediately before execution.
		$lockouts = (int) $wpdb->get_var( $wpdb->prepare( $lockout_sql, $since ) );
		// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared

		return array(
			'total_attempts'      => isset( $row['total_attempts'] ) ? (int) $row['total_attempts'] : 0,
			'successful_attempts' => isset( $row['successful_attempts'] ) ? (int) $row['successful_attempts'] : 0,
			'failed_attempts'     => isset( $row['failed_attempts'] ) ? (int) $row['failed_attempts'] : 0,
			'blocked_attempts'    => isset( $row['blocked_attempts'] ) ? (int) $row['blocked_attempts'] : 0,
			'lockouts'            => $lockouts,
			'permanent_bans'      => $this->ban_store->count_since( $period_seconds ),
			'unique_ips'          => isset( $row['unique_ips'] ) ? (int) $row['unique_ips'] : 0,
		);
	}
}
