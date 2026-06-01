<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\Reports;

use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\Events\LoginEventTable;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class LoginCredentialCorrelationReport {
	private const ATTACK_EVENT_TYPES = array(
		'failed_login',
		'blocked_login',
		'login_lockout',
	);

	private const HIGH_VARIETY_PASSWORD_THRESHOLD = 10;

	private LoginEventTable $login_event_table;

	public function __construct( LoginEventTable $login_event_table ) {
		$this->login_event_table = $login_event_table;
	}

	public function summary( ?int $period_seconds ): array {
		return array_merge(
			$this->attempt_summary( $period_seconds ),
			$this->fingerprint_reuse_summary( $period_seconds ),
			array(
				'high_variety_ips'     => $this->high_variety_ip_count( $period_seconds ),
				'network_campaigns'    => $this->network_campaign_count( $period_seconds ),
				'user_agent_campaigns' => $this->user_agent_campaign_count( $period_seconds ),
			)
		);
	}

	public function reused_password_fingerprints( ?int $period_seconds, int $limit = 10 ): array {
		$params     = array();
		$period_sql = $this->period_sql( $period_seconds, $params );
		$params[]   = max( 1, $limit );
		$table      = $this->login_event_table->name();
		$sql        = "SELECT
				MIN(password_value) AS password_value,
				COUNT(*) AS attempts,
				COUNT(DISTINCT ip_address) AS ips,
				COUNT(DISTINCT username) AS usernames,
				COUNT(DISTINCT country_code) AS countries,
				MIN(created_at) AS first_seen,
				MAX(created_at) AS last_seen
			FROM {$table}
			WHERE {$this->attack_event_type_sql()}
				AND password_hash <> ''
				AND password_value IS NOT NULL
				AND password_value <> ''
				{$period_sql}
			GROUP BY password_hash
			HAVING attempts > 1
			ORDER BY ips DESC, attempts DESC
			LIMIT %d";

		return $this->get_results( $sql, $params );
	}

	public function common_passwords( ?int $period_seconds, int $limit = 10 ): array {
		$params     = array();
		$period_sql = $this->period_sql( $period_seconds, $params );
		$params[]   = max( 1, $limit );
		$table      = $this->login_event_table->name();
		$sql        = "SELECT
				password_value,
				COUNT(*) AS attempts,
				COUNT(DISTINCT ip_address) AS ips,
				COUNT(DISTINCT username) AS usernames,
				COUNT(DISTINCT country_code) AS countries,
				COUNT(DISTINCT CASE WHEN user_agent IS NOT NULL AND user_agent <> '' THEN SHA2(user_agent, 256) END) AS user_agent_fingerprints,
				MIN(created_at) AS first_seen,
				MAX(created_at) AS last_seen
			FROM {$table}
			WHERE {$this->attack_event_type_sql()}
				AND password_value IS NOT NULL
				AND password_value <> ''
				{$period_sql}
			GROUP BY password_value
			ORDER BY attempts DESC, ips DESC
			LIMIT %d";

		return $this->get_results( $sql, $params );
	}

	public function high_variety_ips( ?int $period_seconds, int $limit = 10 ): array {
		$params     = array();
		$period_sql = $this->period_sql( $period_seconds, $params );
		$params[]   = self::HIGH_VARIETY_PASSWORD_THRESHOLD;
		$params[]   = max( 1, $limit );
		$table      = $this->login_event_table->name();
		$sql        = "SELECT
				ip_address,
				country_code,
				country_name,
				COUNT(*) AS attempts,
				COUNT(DISTINCT password_hash) AS password_fingerprints,
				COUNT(DISTINCT password_mask) AS password_lengths,
				COUNT(DISTINCT username) AS usernames,
				COUNT(DISTINCT user_agent) AS user_agents,
				SUM(CASE WHEN event_type = 'blocked_login' THEN 1 ELSE 0 END) AS blocked,
				SUM(CASE WHEN event_type = 'login_lockout' THEN 1 ELSE 0 END) AS lockouts,
				MIN(created_at) AS first_seen,
				MAX(created_at) AS last_seen
			FROM {$table}
			WHERE {$this->attack_event_type_sql()}
				AND password_hash <> ''
				{$period_sql}
			GROUP BY ip_address, country_code, country_name
			HAVING password_fingerprints >= %d
			ORDER BY password_fingerprints DESC, attempts DESC
			LIMIT %d";

		return $this->get_results( $sql, $params );
	}

	public function ipv4_network_campaigns( ?int $period_seconds, int $limit = 10 ): array {
		$params     = array();
		$period_sql = $this->period_sql( $period_seconds, $params );
		$params[]   = max( 1, $limit );
		$table      = $this->login_event_table->name();
		$sql        = "SELECT
				CONCAT(SUBSTRING_INDEX(ip_address, '.', 3), '.0/24') AS network,
				COUNT(*) AS attempts,
				COUNT(DISTINCT ip_address) AS ips,
				COUNT(DISTINCT CASE WHEN password_hash <> '' THEN password_hash END) AS password_fingerprints,
				COUNT(DISTINCT username) AS usernames,
				COUNT(DISTINCT country_code) AS countries,
				MIN(created_at) AS first_seen,
				MAX(created_at) AS last_seen
			FROM {$table}
			WHERE {$this->attack_event_type_sql()}
				AND ip_address REGEXP '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$'
				{$period_sql}
			GROUP BY SUBSTRING_INDEX(ip_address, '.', 3)
			HAVING ips > 1
			ORDER BY attempts DESC
			LIMIT %d";

		return $this->get_results( $sql, $params );
	}

	public function user_agent_campaigns( ?int $period_seconds, int $limit = 10 ): array {
		$params     = array();
		$period_sql = $this->period_sql( $period_seconds, $params );
		$params[]   = max( 1, $limit );
		$table      = $this->login_event_table->name();
		$sql        = "SELECT
				LEFT(SHA2(user_agent, 256), 16) AS user_agent_fingerprint,
				user_agent,
				COUNT(*) AS attempts,
				COUNT(DISTINCT ip_address) AS ips,
				COUNT(DISTINCT CASE WHEN password_hash <> '' THEN password_hash END) AS password_fingerprints,
				COUNT(DISTINCT CASE WHEN password_value IS NOT NULL AND password_value <> '' THEN password_value END) AS passwords,
				COUNT(DISTINCT username) AS usernames,
				MIN(created_at) AS first_seen,
				MAX(created_at) AS last_seen
			FROM {$table}
			WHERE {$this->attack_event_type_sql()}
				AND user_agent IS NOT NULL
				AND user_agent <> ''
				{$period_sql}
			GROUP BY SHA2(user_agent, 256), user_agent
			HAVING ips > 1
			ORDER BY attempts DESC
			LIMIT %d";

		return array_map( array( $this, 'with_user_agent_details' ), $this->get_results( $sql, $params ) );
	}

	public function password_strategy_counts( ?int $period_seconds ): array {
		$results = array();
		foreach ( $this->strategy_conditions() as $strategy => $condition ) {
			$row       = $this->strategy_count( $condition, $period_seconds );
			$results[] = array(
				'strategy'  => $strategy,
				'label'     => $this->strategy_label( $strategy ),
				'attempts'  => isset( $row['attempts'] ) ? (int) $row['attempts'] : 0,
				'ips'       => isset( $row['ips'] ) ? (int) $row['ips'] : 0,
				'usernames' => isset( $row['usernames'] ) ? (int) $row['usernames'] : 0,
			);
		}

		usort(
			$results,
			static function ( array $a, array $b ): int {
				return $b['attempts'] <=> $a['attempts'];
			}
		);

		return $results;
	}

	public function password_feature_signatures( ?int $period_seconds, int $limit = 10 ): array {
		$params     = array();
		$period_sql = $this->period_sql( $period_seconds, $params );
		$params[]   = max( 1, $limit );
		$table      = $this->login_event_table->name();
		$sql        = "SELECT
				CONCAT(
					'length ', length_bucket,
					', ', character_classes,
					', trailing digits ', trailing_digit_bucket,
					', ', contains_year,
					', ', contains_username
				) AS feature,
				COUNT(*) AS attempts,
				COUNT(DISTINCT ip_address) AS ips,
				COUNT(DISTINCT username) AS usernames,
				COUNT(DISTINCT CASE WHEN password_hash <> '' THEN password_hash END) AS password_fingerprints
			FROM (
				SELECT
					ip_address,
					username,
					password_hash,
					{$this->length_bucket_sql()} AS length_bucket,
					{$this->character_classes_sql()} AS character_classes,
					{$this->trailing_digit_bucket_sql()} AS trailing_digit_bucket,
					{$this->contains_year_sql()} AS contains_year,
					{$this->contains_username_sql()} AS contains_username
				FROM {$table}
				WHERE {$this->attack_event_type_sql()}
					AND password_value IS NOT NULL
					AND password_value <> ''
					{$period_sql}
			) feature_rows
			GROUP BY length_bucket, character_classes, trailing_digit_bucket, contains_year, contains_username
			ORDER BY attempts DESC
			LIMIT %d";

		return $this->get_results( $sql, $params );
	}

	private function attempt_summary( ?int $period_seconds ): array {
		$params     = array();
		$period_sql = $this->period_sql( $period_seconds, $params );
		$table      = $this->login_event_table->name();
		$sql        = "SELECT
				COUNT(*) AS correlated_attempts,
				COUNT(DISTINCT ip_address) AS correlated_ips,
				COUNT(DISTINCT username) AS correlated_usernames,
				COUNT(DISTINCT CASE WHEN password_hash <> '' THEN password_hash END) AS password_fingerprints
			FROM {$table}
			WHERE {$this->attack_event_type_sql()}
				{$period_sql}";
		$row        = $this->get_row( $sql, $params );

		return array(
			'correlated_attempts'   => isset( $row['correlated_attempts'] ) ? (int) $row['correlated_attempts'] : 0,
			'correlated_ips'        => isset( $row['correlated_ips'] ) ? (int) $row['correlated_ips'] : 0,
			'correlated_usernames'  => isset( $row['correlated_usernames'] ) ? (int) $row['correlated_usernames'] : 0,
			'password_fingerprints' => isset( $row['password_fingerprints'] ) ? (int) $row['password_fingerprints'] : 0,
		);
	}

	private function fingerprint_reuse_summary( ?int $period_seconds ): array {
		$params     = array();
		$period_sql = $this->period_sql( $period_seconds, $params );
		$table      = $this->login_event_table->name();
		$sql        = "SELECT
				COUNT(*) AS fingerprints,
				SUM(CASE WHEN attempts > 1 THEN 1 ELSE 0 END) AS repeated_fingerprints,
				SUM(CASE WHEN ips > 1 THEN 1 ELSE 0 END) AS multi_ip_fingerprints,
				SUM(CASE WHEN ips >= 5 THEN 1 ELSE 0 END) AS fingerprints_seen_on_5plus_ips,
				MAX(attempts) AS max_attempts_same_fingerprint,
				MAX(ips) AS max_ips_same_fingerprint
			FROM (
				SELECT password_hash, COUNT(*) AS attempts, COUNT(DISTINCT ip_address) AS ips
				FROM {$table}
				WHERE {$this->attack_event_type_sql()}
					AND password_hash <> ''
					{$period_sql}
				GROUP BY password_hash
			) grouped";
		$row        = $this->get_row( $sql, $params );

		return array(
			'repeated_fingerprints'          => isset( $row['repeated_fingerprints'] ) ? (int) $row['repeated_fingerprints'] : 0,
			'multi_ip_fingerprints'          => isset( $row['multi_ip_fingerprints'] ) ? (int) $row['multi_ip_fingerprints'] : 0,
			'fingerprints_seen_on_5plus_ips' => isset( $row['fingerprints_seen_on_5plus_ips'] ) ? (int) $row['fingerprints_seen_on_5plus_ips'] : 0,
			'max_attempts_same_fingerprint'  => isset( $row['max_attempts_same_fingerprint'] ) ? (int) $row['max_attempts_same_fingerprint'] : 0,
			'max_ips_same_fingerprint'       => isset( $row['max_ips_same_fingerprint'] ) ? (int) $row['max_ips_same_fingerprint'] : 0,
		);
	}

	private function high_variety_ip_count( ?int $period_seconds ): int {
		$params     = array();
		$period_sql = $this->period_sql( $period_seconds, $params );
		$params[]   = self::HIGH_VARIETY_PASSWORD_THRESHOLD;
		$table      = $this->login_event_table->name();
		$sql        = "SELECT COUNT(*) FROM (
				SELECT ip_address, COUNT(DISTINCT password_hash) AS password_fingerprints
				FROM {$table}
				WHERE {$this->attack_event_type_sql()}
					AND password_hash <> ''
					{$period_sql}
				GROUP BY ip_address
				HAVING password_fingerprints >= %d
			) grouped";

		return $this->get_var( $sql, $params );
	}

	private function network_campaign_count( ?int $period_seconds ): int {
		$params     = array();
		$period_sql = $this->period_sql( $period_seconds, $params );
		$table      = $this->login_event_table->name();
		$sql        = "SELECT COUNT(*) FROM (
				SELECT SUBSTRING_INDEX(ip_address, '.', 3) AS network, COUNT(DISTINCT ip_address) AS ips
				FROM {$table}
				WHERE {$this->attack_event_type_sql()}
					AND ip_address REGEXP '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$'
					{$period_sql}
				GROUP BY SUBSTRING_INDEX(ip_address, '.', 3)
				HAVING ips > 1
			) grouped";

		return $this->get_var( $sql, $params );
	}

	private function user_agent_campaign_count( ?int $period_seconds ): int {
		$params     = array();
		$period_sql = $this->period_sql( $period_seconds, $params );
		$table      = $this->login_event_table->name();
		$sql        = "SELECT COUNT(*) FROM (
				SELECT SHA2(user_agent, 256) AS user_agent_fingerprint, COUNT(DISTINCT ip_address) AS ips
				FROM {$table}
				WHERE {$this->attack_event_type_sql()}
					AND user_agent IS NOT NULL
					AND user_agent <> ''
					{$period_sql}
				GROUP BY SHA2(user_agent, 256)
				HAVING ips > 1
			) grouped";

		return $this->get_var( $sql, $params );
	}

	private function with_user_agent_details( array $row ): array {
		return array_merge( $row, $this->parse_user_agent( (string) ( $row['user_agent'] ?? '' ) ) );
	}

	private function parse_user_agent( string $user_agent ): array {
		$user_agent = trim( $user_agent );

		if ( '' === $user_agent ) {
			return array(
				'browser_family'     => 'Unknown',
				'browser_version'    => '',
				'platform'           => 'Unknown',
				'device_type'        => 'Unknown',
				'user_agent_summary' => 'Unknown',
			);
		}

		$browser  = $this->browser_details( $user_agent );
		$platform = $this->platform_details( $user_agent );
		$device   = $this->device_type( $user_agent, $browser['family'] );
		$summary  = trim( $browser['family'] . ( '' !== $browser['version'] ? ' ' . $browser['version'] : '' ) . ' on ' . $platform . ' (' . $device . ')' );

		return array(
			'browser_family'     => $browser['family'],
			'browser_version'    => $browser['version'],
			'platform'           => $platform,
			'device_type'        => $device,
			'user_agent_summary' => $summary,
		);
	}

	private function browser_details( string $user_agent ): array {
		$browser_patterns = array(
			'WPScan'            => '/WPScan/i',
			'WordPress'         => '/WordPress\/([0-9.]+)/i',
			'curl'              => '/curl\/([0-9.]+)/i',
			'Python Requests'   => '/python-requests\/([0-9.]+)/i',
			'Go HTTP Client'    => '/Go-http-client\/([0-9.]+)/i',
			'Java'              => '/Java\/([0-9._]+)/i',
			'Googlebot'         => '/Googlebot\/([0-9.]+)/i',
			'Bingbot'           => '/bingbot\/([0-9.]+)/i',
			'AhrefsBot'         => '/AhrefsBot\/([0-9.]+)/i',
			'SemrushBot'        => '/SemrushBot\/([0-9.]+)/i',
			'YandexBot'         => '/YandexBot\/([0-9.]+)/i',
			'Edge'              => '/Edg\/([0-9.]+)/',
			'Opera'             => '/OPR\/([0-9.]+)/',
			'Chrome'            => '/(?:Chrome|CriOS)\/([0-9.]+)/',
			'Firefox'           => '/(?:Firefox|FxiOS)\/([0-9.]+)/',
			'Safari'            => '/Version\/([0-9.]+).*Safari/',
			'Internet Explorer' => '/(?:MSIE |rv:)([0-9.]+)/',
		);

		foreach ( $browser_patterns as $family => $pattern ) {
			if ( preg_match( $pattern, $user_agent, $matches ) ) {
				return array(
					'family'  => $family,
					'version' => (string) ( $matches[1] ?? '' ),
				);
			}
		}

		return array(
			'family'  => 'Unknown',
			'version' => '',
		);
	}

	private function platform_details( string $user_agent ): string {
		$platform_patterns = array(
			'Windows 11/10' => '/Windows NT 10\.0/i',
			'Windows 8.1'   => '/Windows NT 6\.3/i',
			'Windows 8'     => '/Windows NT 6\.2/i',
			'Windows 7'     => '/Windows NT 6\.1/i',
			'iOS'           => '/iPhone|iPad|iPod/i',
			'macOS'         => '/Mac OS X/i',
			'Android'       => '/Android/i',
			'Linux'         => '/Linux/i',
		);

		foreach ( $platform_patterns as $platform => $pattern ) {
			if ( preg_match( $pattern, $user_agent ) ) {
				return $platform;
			}
		}

		return 'Unknown';
	}

	private function device_type( string $user_agent, string $browser_family ): string {
		if ( preg_match( '/bot|crawler|spider|WPScan|curl|python-requests|Go-http-client|Java\//i', $user_agent ) ) {
			return 'Bot/Tool';
		}

		if ( preg_match( '/iPad|Tablet/i', $user_agent ) ) {
			return 'Tablet';
		}

		if ( preg_match( '/Mobile|Android|iPhone|iPod/i', $user_agent ) ) {
			return 'Mobile';
		}

		if ( in_array( $browser_family, array( 'Unknown' ), true ) ) {
			return 'Unknown';
		}

		return 'Desktop';
	}

	private function period_sql( ?int $period_seconds, array &$params ): string {
		if ( null === $period_seconds ) {
			return '';
		}

		$params[] = gmdate( 'Y-m-d H:i:s', time() - $period_seconds );

		return 'AND created_at >= %s';
	}

	private function attack_event_type_sql(): string {
		return "event_type IN ('" . implode( "', '", self::ATTACK_EVENT_TYPES ) . "')";
	}

	private function strategy_label( string $strategy ): string {
		$labels = array(
			'contains_username' => 'Password contains submitted username',
			'contains_year'     => 'Password contains a year',
			'trailing_digits'   => 'Password ends with digits',
			'digits_only'       => 'Digits only',
			'letters_only'      => 'Letters only',
			'symbols_present'   => 'Contains symbols',
			'short_1_4'         => 'Very short password',
			'long_17_plus'      => 'Long password',
		);

		return $labels[ $strategy ] ?? $strategy;
	}

	private function strategy_conditions(): array {
		return array(
			'contains_username' => $this->contains_username_condition_sql(),
			'contains_year'     => "password_value REGEXP '(19|20)[0-9][0-9]'",
			'trailing_digits'   => "password_value REGEXP '[0-9]+$'",
			'digits_only'       => "password_value REGEXP '^[0-9]+$'",
			'letters_only'      => "password_value REGEXP '^[a-zA-Z]+$'",
			'symbols_present'   => "password_value REGEXP '[^a-zA-Z0-9]'",
			'short_1_4'         => 'CHAR_LENGTH(password_value) <= 4',
			'long_17_plus'      => 'CHAR_LENGTH(password_value) >= 17',
		);
	}

	private function strategy_count( string $condition, ?int $period_seconds ): array {
		$params     = array();
		$period_sql = $this->period_sql( $period_seconds, $params );
		$table      = $this->login_event_table->name();
		$sql        = "SELECT
				COUNT(*) AS attempts,
				COUNT(DISTINCT ip_address) AS ips,
				COUNT(DISTINCT username) AS usernames
			FROM {$table}
			WHERE {$this->attack_event_type_sql()}
				AND password_value IS NOT NULL
				AND password_value <> ''
				AND {$condition}
				{$period_sql}";

		return $this->get_row( $sql, $params );
	}

	private function length_bucket_sql(): string {
		return "CASE
			WHEN CHAR_LENGTH(password_value) <= 4 THEN '1-4'
			WHEN CHAR_LENGTH(password_value) <= 8 THEN '5-8'
			WHEN CHAR_LENGTH(password_value) <= 12 THEN '9-12'
			WHEN CHAR_LENGTH(password_value) <= 16 THEN '13-16'
			WHEN CHAR_LENGTH(password_value) <= 24 THEN '17-24'
			ELSE '25+'
		END";
	}

	private function character_classes_sql(): string {
		return "CONCAT_WS(' + ',
			CASE WHEN BINARY password_value REGEXP '[a-z]' THEN 'lowercase' END,
			CASE WHEN BINARY password_value REGEXP '[A-Z]' THEN 'uppercase' END,
			CASE WHEN password_value REGEXP '[0-9]' THEN 'digits' END,
			CASE WHEN password_value REGEXP '[^a-zA-Z0-9]' THEN 'symbols' END
		)";
	}

	private function trailing_digit_bucket_sql(): string {
		return "CASE
			WHEN password_value REGEXP '[0-9]{5,}$' THEN '5+'
			WHEN password_value REGEXP '[0-9]{3,4}$' THEN '3-4'
			WHEN password_value REGEXP '[0-9]{1,2}$' THEN '1-2'
			ELSE 'none'
		END";
	}

	private function contains_year_sql(): string {
		return "CASE WHEN password_value REGEXP '(19|20)[0-9][0-9]' THEN 'year' ELSE 'no year' END";
	}

	private function contains_username_sql(): string {
		return "CASE WHEN {$this->contains_username_condition_sql()} THEN 'username' ELSE 'no username' END";
	}

	private function contains_username_condition_sql(): string {
		return 'CHAR_LENGTH(username) >= 3 AND LOCATE(LOWER(username), LOWER(password_value)) > 0';
	}

	private function get_results( string $sql, array $params = array() ): array {
		global $wpdb;

		if ( ! empty( $params ) ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Query is built from internal fragments and prepared immediately before execution.
			$sql = $wpdb->prepare( $sql, $params );
		}

		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Query table and fragments are generated internally.
		$rows = $wpdb->get_results( $sql, ARRAY_A );

		return is_array( $rows ) ? $rows : array();
	}

	private function get_row( string $sql, array $params = array() ): array {
		global $wpdb;

		if ( ! empty( $params ) ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Query is built from internal fragments and prepared immediately before execution.
			$sql = $wpdb->prepare( $sql, $params );
		}

		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Query table and fragments are generated internally.
		$row = $wpdb->get_row( $sql, ARRAY_A );

		return is_array( $row ) ? $row : array();
	}

	private function get_var( string $sql, array $params = array() ): int {
		global $wpdb;

		if ( ! empty( $params ) ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Query is built from internal fragments and prepared immediately before execution.
			$sql = $wpdb->prepare( $sql, $params );
		}

		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Query table and fragments are generated internally.
		return (int) $wpdb->get_var( $sql );
	}
}
