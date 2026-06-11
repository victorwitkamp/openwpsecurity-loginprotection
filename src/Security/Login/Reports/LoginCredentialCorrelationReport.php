<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\Reports;

use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\LoginAttemptRepository;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class LoginCredentialCorrelationReport {
	private const ATTACK_EVENT_TYPES = array(
		'failed_login',
		'blocked_login',
	);

	private const HIGH_VARIETY_PASSWORD_THRESHOLD = 10;

	private LoginAttemptRepository $login_attempts;

	public function __construct( LoginAttemptRepository $login_attempts ) {
		$this->login_attempts = $login_attempts;
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

	public function key_findings( ?int $period_seconds ): array {
		$findings                = array();
		$top_username            = $this->targeted_usernames( $period_seconds, 1 )[0] ?? null;
		$top_password            = $this->important_passwords( $period_seconds, 1 )[0] ?? null;
		$top_high_variety_ip     = $this->high_variety_ips( $period_seconds, 1 )[0] ?? null;
		$username_context_signal = $this->username_context_signal( $period_seconds );

		if ( is_array( $top_username ) ) {
			$findings[] = array(
				'label'  => 'Primary target',
				'value'  => (string) $top_username['username'],
				'detail' => sprintf(
					'%s attempts from %s IPs using %s passwords.',
					number_format_i18n( (int) $top_username['attempts'] ),
					number_format_i18n( (int) $top_username['ips'] ),
					number_format_i18n( (int) $top_username['passwords'] )
				),
			);
		}

		if ( is_array( $username_context_signal ) && (int) $username_context_signal['attempts'] > 0 ) {
			$findings[] = array(
				'label'  => 'Username-based guesses',
				'value'  => $this->format_percent_value( (float) $username_context_signal['attempt_share'] ),
				'detail' => sprintf(
					'%s attempts used passwords containing the submitted username.',
					number_format_i18n( (int) $username_context_signal['attempts'] )
				),
			);
		}

		if ( is_array( $top_password ) ) {
			$findings[] = array(
				'label'  => 'Most distributed password',
				'value'  => (string) $top_password['password_value'],
				'detail' => sprintf(
					'%s attempts across %s IPs, %s countries, and %s user agents.',
					number_format_i18n( (int) $top_password['attempts'] ),
					number_format_i18n( (int) $top_password['ips'] ),
					number_format_i18n( (int) $top_password['countries'] ),
					number_format_i18n( (int) $top_password['user_agent_fingerprints'] )
				),
			);
		}

		if ( is_array( $top_high_variety_ip ) ) {
			$findings[] = array(
				'label'  => 'Highest password variety',
				'value'  => (string) $top_high_variety_ip['ip_address'],
				'detail' => sprintf(
					'%s distinct password fingerprints, %s attempts, %s blocked requests.',
					number_format_i18n( (int) $top_high_variety_ip['password_fingerprints'] ),
					number_format_i18n( (int) $top_high_variety_ip['attempts'] ),
					number_format_i18n( (int) $top_high_variety_ip['blocked'] )
				),
			);
		}

		return $findings;
	}

	public function important_passwords( ?int $period_seconds, int $limit = 12 ): array {
		$params     = array();
		$period_sql = $this->period_sql( $period_seconds, $params );
		$params[]   = max( 1, $limit );
		$table      = $this->login_attempts->name();
		$sql        = "SELECT
				password_value,
				COUNT(*) AS attempts,
				COUNT(DISTINCT CASE WHEN ip_address <> '' THEN ip_address END) AS ips,
				COUNT(DISTINCT CASE WHEN username <> '' THEN username END) AS usernames,
				COUNT(DISTINCT CASE WHEN country_code <> '' THEN country_code END) AS countries,
				COUNT(DISTINCT CASE WHEN user_agent IS NOT NULL AND user_agent <> '' THEN SHA2(user_agent, 256) END) AS user_agent_fingerprints,
				(
					COUNT(*) +
					COUNT(DISTINCT CASE WHEN ip_address <> '' THEN ip_address END) * 5 +
					COUNT(DISTINCT CASE WHEN username <> '' THEN username END) * 3 +
					COUNT(DISTINCT CASE WHEN country_code <> '' THEN country_code END) * 2 +
					COUNT(DISTINCT CASE WHEN user_agent IS NOT NULL AND user_agent <> '' THEN SHA2(user_agent, 256) END) * 2
				) AS priority_score,
				MIN(created_at) AS first_seen,
				MAX(created_at) AS last_seen
			FROM {$table}
			WHERE {$this->attack_event_type_sql()}
				AND password_value IS NOT NULL
				AND password_value <> ''
				{$period_sql}
			GROUP BY password_value
			ORDER BY priority_score DESC, attempts DESC, ips DESC
			LIMIT %d";

		return array_map( array( $this, 'with_password_intelligence' ), $this->get_results( $sql, $params ) );
	}

	public function targeted_usernames( ?int $period_seconds, int $limit = 8 ): array {
		$params     = array();
		$period_sql = $this->period_sql( $period_seconds, $params );
		$params[]   = max( 1, $limit );
		$table      = $this->login_attempts->name();
		$sql        = "SELECT
				username,
				COUNT(*) AS attempts,
				COUNT(DISTINCT CASE WHEN ip_address <> '' THEN ip_address END) AS ips,
				COUNT(DISTINCT CASE WHEN password_value IS NOT NULL AND password_value <> '' THEN password_value END) AS passwords,
				COUNT(DISTINCT CASE WHEN country_code <> '' THEN country_code END) AS countries,
				COUNT(DISTINCT CASE WHEN user_agent IS NOT NULL AND user_agent <> '' THEN SHA2(user_agent, 256) END) AS user_agent_fingerprints,
				SUM(CASE WHEN attempt_type = 'blocked_login' THEN 1 ELSE 0 END) AS blocked,
				SUM(CASE WHEN password_value IS NOT NULL AND password_value <> '' AND {$this->contains_username_condition_sql()} THEN 1 ELSE 0 END) AS username_in_password_attempts,
				MIN(created_at) AS first_seen,
				MAX(created_at) AS last_seen
			FROM {$table}
			WHERE {$this->attack_event_type_sql()}
				AND username <> ''
				{$period_sql}
			GROUP BY username
			ORDER BY attempts DESC, ips DESC, passwords DESC
			LIMIT %d";

		return array_map( array( $this, 'with_targeted_username_intelligence' ), $this->get_results( $sql, $params ) );
	}

	public function high_variety_ips( ?int $period_seconds, int $limit = 10 ): array {
		$params     = array();
		$period_sql = $this->period_sql( $period_seconds, $params );
		$params[]   = self::HIGH_VARIETY_PASSWORD_THRESHOLD;
		$params[]   = max( 1, $limit );
		$table      = $this->login_attempts->name();
		$sql        = "SELECT
				ip_address,
				country_code,
				country_name,
				COUNT(*) AS attempts,
				COUNT(DISTINCT password_hash) AS password_fingerprints,
				COUNT(DISTINCT password_mask) AS password_lengths,
				COUNT(DISTINCT username) AS usernames,
				COUNT(DISTINCT user_agent) AS user_agents,
				SUM(CASE WHEN attempt_type = 'blocked_login' THEN 1 ELSE 0 END) AS blocked,
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
		$table      = $this->login_attempts->name();
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
		$table      = $this->login_attempts->name();
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

	public function password_characteristics( ?int $period_seconds ): array {
		$total_attempts = $this->password_attempt_total( $period_seconds );
		$rows           = array();

		foreach ( $this->password_characteristic_conditions() as $group ) {
			foreach ( $group['conditions'] as $condition ) {
				$row      = $this->password_characteristic_count( (string) $condition['sql'], $period_seconds );
				$attempts = isset( $row['attempts'] ) ? (int) $row['attempts'] : 0;

				if ( 0 === $attempts ) {
					continue;
				}

				$rows[] = array(
					'group'           => (string) $group['group'],
					'group_label'     => (string) $group['label'],
					'label'           => (string) $condition['label'],
					'attempts'        => $attempts,
					'attempt_share'   => $total_attempts > 0 ? round( ( $attempts / $total_attempts ) * 100, 1 ) : 0.0,
					'ips'             => isset( $row['ips'] ) ? (int) $row['ips'] : 0,
					'usernames'       => isset( $row['usernames'] ) ? (int) $row['usernames'] : 0,
					'password_values' => isset( $row['password_values'] ) ? (int) $row['password_values'] : 0,
				);
			}
		}

		return $rows;
	}

	private function attempt_summary( ?int $period_seconds ): array {
		$params     = array();
		$period_sql = $this->period_sql( $period_seconds, $params );
		$table      = $this->login_attempts->name();
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
		$table      = $this->login_attempts->name();
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
		$table      = $this->login_attempts->name();
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
		$table      = $this->login_attempts->name();
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
		$table      = $this->login_attempts->name();
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

	private function with_password_intelligence( array $row ): array {
		$signals = array();

		if ( (int) ( $row['ips'] ?? 0 ) > 1 ) {
			$signals[] = 'multi-IP';
		}

		if ( (int) ( $row['usernames'] ?? 0 ) > 1 ) {
			$signals[] = 'multi-user';
		}

		if ( (int) ( $row['countries'] ?? 0 ) > 1 ) {
			$signals[] = 'multi-country';
		}

		if ( (int) ( $row['user_agent_fingerprints'] ?? 0 ) > 1 ) {
			$signals[] = 'multi-UA';
		}

		$row['spread_signals'] = count( $signals );
		$row['spread_summary'] = ! empty( $signals ) ? implode( ', ', $signals ) : ( (int) ( $row['attempts'] ?? 0 ) > 1 ? 'same source repeat' : 'single attempt' );

		return $row;
	}

	private function with_targeted_username_intelligence( array $row ): array {
		$attempts                      = max( 0, (int) ( $row['attempts'] ?? 0 ) );
		$username_in_password_attempts = max( 0, (int) ( $row['username_in_password_attempts'] ?? 0 ) );

		$row['username_in_password_share'] = $attempts > 0 ? round( ( $username_in_password_attempts / $attempts ) * 100, 1 ) : 0.0;
		$row['target_summary']             = sprintf(
			'%s IPs, %s passwords, %s user agents',
			number_format_i18n( (int) ( $row['ips'] ?? 0 ) ),
			number_format_i18n( (int) ( $row['passwords'] ?? 0 ) ),
			number_format_i18n( (int) ( $row['user_agent_fingerprints'] ?? 0 ) )
		);

		return $row;
	}

	private function username_context_signal( ?int $period_seconds ): array {
		$characteristics = $this->password_characteristics( $period_seconds );
		$combined        = array(
			'attempts'      => 0,
			'attempt_share' => 0.0,
		);

		foreach ( $characteristics as $row ) {
			if ( 'context' !== (string) $row['group'] ) {
				continue;
			}

			if ( ! in_array( (string) $row['label'], array( 'Contains username and year', 'Contains submitted username' ), true ) ) {
				continue;
			}

			$combined['attempts']      += (int) $row['attempts'];
			$combined['attempt_share'] += (float) $row['attempt_share'];
		}

		return $combined;
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
		return "attempt_type IN ('" . implode( "', '", self::ATTACK_EVENT_TYPES ) . "')";
	}

	private function password_characteristic_conditions(): array {
		$contains_username = $this->contains_username_condition_sql();
		$contains_year     = "password_value REGEXP '(19|20)[0-9][0-9]'";

		return array(
			array(
				'group'      => 'case_style',
				'label'      => 'Case style',
				'conditions' => array(
					array(
						'label' => 'lowercase letters',
						'sql'   => "BINARY password_value REGEXP '[a-z]' AND NOT BINARY password_value REGEXP '[A-Z]'",
					),
					array(
						'label' => 'UPPERCASE letters',
						'sql'   => "BINARY password_value REGEXP '[A-Z]' AND NOT BINARY password_value REGEXP '[a-z]'",
					),
					array(
						'label' => 'Mixed case letters',
						'sql'   => "BINARY password_value REGEXP '[a-z]' AND BINARY password_value REGEXP '[A-Z]'",
					),
					array(
						'label' => 'No letters',
						'sql'   => "NOT BINARY password_value REGEXP '[A-Za-z]'",
					),
				),
			),
			array(
				'group'      => 'character_makeup',
				'label'      => 'Character makeup',
				'conditions' => array(
					array(
						'label' => 'Letters only',
						'sql'   => "BINARY password_value REGEXP '^[A-Za-z]+$'",
					),
					array(
						'label' => 'Digits only',
						'sql'   => "password_value REGEXP '^[0-9]+$'",
					),
					array(
						'label' => 'Letters + digits',
						'sql'   => "BINARY password_value REGEXP '[A-Za-z]' AND password_value REGEXP '[0-9]' AND NOT password_value REGEXP '[^A-Za-z0-9]'",
					),
					array(
						'label' => 'Contains symbols',
						'sql'   => "password_value REGEXP '[^A-Za-z0-9]'",
					),
				),
			),
			array(
				'group'      => 'length',
				'label'      => 'Length',
				'conditions' => array(
					array(
						'label' => '1-4 characters',
						'sql'   => 'CHAR_LENGTH(password_value) <= 4',
					),
					array(
						'label' => '5-8 characters',
						'sql'   => 'CHAR_LENGTH(password_value) BETWEEN 5 AND 8',
					),
					array(
						'label' => '9-12 characters',
						'sql'   => 'CHAR_LENGTH(password_value) BETWEEN 9 AND 12',
					),
					array(
						'label' => '13-16 characters',
						'sql'   => 'CHAR_LENGTH(password_value) BETWEEN 13 AND 16',
					),
					array(
						'label' => '17-24 characters',
						'sql'   => 'CHAR_LENGTH(password_value) BETWEEN 17 AND 24',
					),
					array(
						'label' => '25+ characters',
						'sql'   => 'CHAR_LENGTH(password_value) >= 25',
					),
				),
			),
			array(
				'group'      => 'trailing_digits',
				'label'      => 'Trailing digits',
				'conditions' => array(
					array(
						'label' => 'No trailing digits',
						'sql'   => "NOT password_value REGEXP '[0-9]$'",
					),
					array(
						'label' => '1-2 trailing digits',
						'sql'   => "password_value REGEXP '[0-9]{1,2}$' AND NOT password_value REGEXP '[0-9]{3,}$'",
					),
					array(
						'label' => '3-4 trailing digits',
						'sql'   => "password_value REGEXP '[0-9]{3,4}$' AND NOT password_value REGEXP '[0-9]{5,}$'",
					),
					array(
						'label' => '5+ trailing digits',
						'sql'   => "password_value REGEXP '[0-9]{5,}$'",
					),
				),
			),
			array(
				'group'      => 'context',
				'label'      => 'Username/year context',
				'conditions' => array(
					array(
						'label' => 'Contains username and year',
						'sql'   => "({$contains_username}) AND ({$contains_year})",
					),
					array(
						'label' => 'Contains submitted username',
						'sql'   => "({$contains_username}) AND NOT ({$contains_year})",
					),
					array(
						'label' => 'Contains year',
						'sql'   => "NOT ({$contains_username}) AND ({$contains_year})",
					),
					array(
						'label' => 'No username/year signal',
						'sql'   => "NOT ({$contains_username}) AND NOT ({$contains_year})",
					),
				),
			),
		);
	}

	private function password_characteristic_count( string $condition, ?int $period_seconds ): array {
		$params     = array();
		$period_sql = $this->period_sql( $period_seconds, $params );
		$table      = $this->login_attempts->name();
		$sql        = "SELECT
				COUNT(*) AS attempts,
				COUNT(DISTINCT CASE WHEN ip_address <> '' THEN ip_address END) AS ips,
				COUNT(DISTINCT CASE WHEN username <> '' THEN username END) AS usernames,
				COUNT(DISTINCT password_value) AS password_values
			FROM {$table}
			WHERE {$this->attack_event_type_sql()}
				AND password_value IS NOT NULL
				AND password_value <> ''
				AND {$condition}
				{$period_sql}";

		return $this->get_row( $sql, $params );
	}

	private function password_attempt_total( ?int $period_seconds ): int {
		$params     = array();
		$period_sql = $this->period_sql( $period_seconds, $params );
		$table      = $this->login_attempts->name();
		$sql        = "SELECT COUNT(*)
			FROM {$table}
			WHERE {$this->attack_event_type_sql()}
				AND password_value IS NOT NULL
				AND password_value <> ''
				{$period_sql}";

		return $this->get_var( $sql, $params );
	}

	private function contains_username_condition_sql(): string {
		return 'CHAR_LENGTH(username) >= 3 AND LOCATE(LOWER(username), LOWER(password_value)) > 0';
	}

	private function format_percent_value( float $percentage ): string {
		return number_format_i18n( $percentage, 1 ) . '%';
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
