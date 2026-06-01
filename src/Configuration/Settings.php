<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\LoginProtection\Configuration;

use VictorWitkamp\OpenWPSecurity\Core\Configuration\OptionBackedSettingsStore;
use VictorWitkamp\OpenWPSecurity\Core\Configuration\SettingsInputSanitizer;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Settings extends OptionBackedSettingsStore {
	private const OPTION_NAME = 'openwpsecurity_loginprotection_settings';

	private SettingsInputSanitizer $input_sanitizer;

	public function __construct( SettingsInputSanitizer $input_sanitizer ) {
		$this->input_sanitizer = $input_sanitizer;
	}

	public function option_name(): string {
		return self::OPTION_NAME;
	}

	public function sanitize_submission( array $submission ): array {
		return array_merge( $this->sanitize_login_submission( $submission ), $this->sanitize_infrastructure_submission( $submission ) );
	}

	public function sanitize_login_submission( array $submission ): array {
		return array(
			'login_max_attempts'                         => max( 1, (int) ( $submission['login_max_attempts'] ?? 3 ) ),
			'login_window_minutes'                       => max( 1, (int) ( $submission['login_window_minutes'] ?? 15 ) ),
			'login_lockout_minutes'                      => max( 1, (int) ( $submission['login_lockout_minutes'] ?? 30 ) ),
			'login_lockouts_before_permanent_ban'        => max( 0, (int) ( $submission['login_lockouts_before_permanent_ban'] ?? 2 ) ),
			'login_failed_attempts_before_permanent_ban' => max( 0, (int) ( $submission['login_failed_attempts_before_permanent_ban'] ?? 10 ) ),
		);
	}

	public function sanitize_infrastructure_submission( array $submission ): array {
		return array(
			'event_retention_days' => max( 0, (int) ( $submission['event_retention_days'] ?? 90 ) ),
			'trusted_ip_headers'   => $this->input_sanitizer->headers( (string) ( $submission['trusted_ip_headers'] ?? 'REMOTE_ADDR' ) ),
			'whitelist_ips'        => $this->input_sanitizer->ip_addresses(
				$this->input_sanitizer->lines( (string) ( $submission['whitelist_ips'] ?? '' ) )
			),
			'enable_remote_geoip'  => empty( $submission['enable_remote_geoip'] ) ? 0 : 1,
		);
	}

	protected function default_settings(): array {
		return array(
			'login_max_attempts'                         => 3,
			'login_window_minutes'                       => 15,
			'login_lockout_minutes'                      => 30,
			'login_lockouts_before_permanent_ban'        => 2,
			'login_failed_attempts_before_permanent_ban' => 10,
			'event_retention_days'                       => 90,
			'trusted_ip_headers'                         => array( 'REMOTE_ADDR' ),
			'whitelist_ips'                              => array(),
			'enable_remote_geoip'                        => 0,
		);
	}

	protected function default_settings_filter(): string {
		return 'openwpsecurity_loginprotection_default_settings';
	}

	protected function normalize( array $settings ): array {
		$settings['login_max_attempts']                         = max( 1, (int) $settings['login_max_attempts'] );
		$settings['login_window_minutes']                       = max( 1, (int) $settings['login_window_minutes'] );
		$settings['login_lockout_minutes']                      = max( 1, (int) $settings['login_lockout_minutes'] );
		$settings['login_lockouts_before_permanent_ban']        = max( 0, (int) $settings['login_lockouts_before_permanent_ban'] );
		$settings['login_failed_attempts_before_permanent_ban'] = max( 0, (int) $settings['login_failed_attempts_before_permanent_ban'] );
		$settings['event_retention_days']                       = max( 0, (int) $settings['event_retention_days'] );
		$settings['trusted_ip_headers']                         = $this->input_sanitizer->headers( implode( ',', (array) $settings['trusted_ip_headers'] ) );
		$settings['whitelist_ips']                              = $this->input_sanitizer->ip_addresses( (array) $settings['whitelist_ips'] );
		$settings['enable_remote_geoip']                        = empty( $settings['enable_remote_geoip'] ) ? 0 : 1;

		if ( ! in_array( 'REMOTE_ADDR', $settings['trusted_ip_headers'], true ) ) {
			$settings['trusted_ip_headers'][] = 'REMOTE_ADDR';
		}

		return $settings;
	}
}
