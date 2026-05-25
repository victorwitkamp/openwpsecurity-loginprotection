<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Ban;

use VictorWitkamp\OpenWPSecurity\Core\Http\IpAddressInspector;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\Events\LoginEventLogger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class PermanentBanStore {
	private const OPTION_NAME              = 'openwpsecurity_loginprotection_permanent_bans';
	private const LEGACY_LOGIN_OPTION_NAME = 'vw_login_protection_2026_permanent_bans';
	private const LEGACY_OPTION_NAME       = 'vw_firewall_2026_permanent_bans';

	private LoginEventLogger $login_event_logger;
	private IpAddressInspector $ip_address_inspector;

	public function __construct( LoginEventLogger $login_event_logger, IpAddressInspector $ip_address_inspector ) {
		$this->login_event_logger   = $login_event_logger;
		$this->ip_address_inspector = $ip_address_inspector;
	}

	public function ensure_storage(): void {
		if ( get_option( self::OPTION_NAME, null ) === null ) {
			add_option( self::OPTION_NAME, array(), '', false );
		}

		$this->migrate_legacy_login_bans();
		$this->migrate_legacy_firewall_bans();
		$this->normalize_legacy_sources();
	}

	public function get_all_bans(): array {
		$bans = get_option( self::OPTION_NAME, array() );
		$bans = is_array( $bans ) ? $bans : array();

		foreach ( $bans as $ip => $ban ) {
			if ( ! is_array( $ban ) ) {
				unset( $bans[ $ip ] );
			}
		}

		return $bans;
	}

	public function get_ban_for_ip( string $ip ): array {
		$bans = $this->get_all_bans();

		return isset( $bans[ $ip ] ) && is_array( $bans[ $ip ] ) ? $bans[ $ip ] : array();
	}

	public function is_banned( string $ip ): bool {
		return array() !== $this->get_ban_for_ip( $ip );
	}

	public function create_ban( string $ip, string $reason, string $source = 'login_protection', array $context = array() ): void {
		if ( '' === $ip || $this->ip_address_inspector->is_private( $ip ) ) {
			return;
		}

		$source = $this->normalized_source( $source );
		$bans   = $this->get_all_bans();

		if ( isset( $bans[ $ip ] ) ) {
			return;
		}

		$bans[ $ip ] = array(
			'ip_address' => $ip,
			'banned_at'  => current_time( 'mysql', true ),
			'reason'     => $reason,
			'source'     => $source,
		);
		update_option( self::OPTION_NAME, $bans, false );

		$this->login_event_logger->log(
			'permanent_ban_created',
			$ip,
			'',
			'',
			array(
				'details' => array_merge(
					array(
						'reason' => $reason,
						'source' => $source,
					),
					$context
				),
			)
		);
	}

	private function normalize_legacy_sources(): void {
		$bans    = $this->get_all_bans();
		$changed = false;

		foreach ( $bans as $ip => $ban ) {
			$source = isset( $ban['source'] ) ? $this->normalized_source( (string) $ban['source'] ) : '';

			if ( $source !== (string) ( $ban['source'] ?? '' ) ) {
				$bans[ $ip ]['source'] = $source;
				$changed               = true;
			}
		}

		if ( $changed ) {
			update_option( self::OPTION_NAME, $bans, false );
		}
	}

	private function migrate_legacy_firewall_bans(): void {
		$legacy_bans = get_option( self::LEGACY_OPTION_NAME, array() );

		if ( ! is_array( $legacy_bans ) || array() === $legacy_bans ) {
			return;
		}

		$current_bans = $this->get_all_bans();
		$changed      = false;

		foreach ( $legacy_bans as $ip => $ban ) {
			if ( ! is_array( $ban ) ) {
				continue;
			}

			$source = isset( $ban['source'] ) ? $this->normalized_source( (string) $ban['source'] ) : '';

			if ( ! $this->is_login_ban_source( $source ) ) {
				continue;
			}

			if ( ! isset( $current_bans[ $ip ] ) || ! is_array( $current_bans[ $ip ] ) ) {
				$ban['source']       = $source;
				$current_bans[ $ip ] = $ban;
			}

			$changed = true;
		}

		if ( ! $changed ) {
			return;
		}

		update_option( self::OPTION_NAME, $current_bans, false );
	}

	private function migrate_legacy_login_bans(): void {
		$legacy_bans = get_option( self::LEGACY_LOGIN_OPTION_NAME, array() );

		if ( ! is_array( $legacy_bans ) || array() === $legacy_bans ) {
			return;
		}

		$current_bans = $this->get_all_bans();
		$changed      = false;

		foreach ( $legacy_bans as $ip => $ban ) {
			if ( ! is_array( $ban ) || isset( $current_bans[ $ip ] ) ) {
				continue;
			}

			$source = isset( $ban['source'] ) ? $this->normalized_source( (string) $ban['source'] ) : '';

			if ( ! $this->is_login_ban_source( $source ) ) {
				continue;
			}

			$ban['source']       = $source;
			$current_bans[ $ip ] = $ban;
			$changed             = true;
		}

		if ( $changed ) {
			update_option( self::OPTION_NAME, $current_bans, false );
		}
	}

	private function is_login_ban_source( string $source ): bool {
		return in_array( $source, array( 'login_protection', 'login_lockout' ), true );
	}

	private function normalized_source( string $source ): string {
		return 'login_lockout' === $source ? 'login_protection' : $source;
	}
}
