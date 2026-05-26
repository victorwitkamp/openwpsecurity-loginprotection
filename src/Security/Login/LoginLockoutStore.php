<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class LoginLockoutStore {
	private const ACTIVE_LOCKOUTS_OPTION_NAME = 'openwpsecurity_loginprotection_active_lockouts';
	private const LOCKOUT_COUNTS_OPTION_NAME  = 'openwpsecurity_loginprotection_lockout_counts';

	public function ensure_storage(): void {
		$this->ensure_active_lockouts_option();
		$this->ensure_lockout_counts_option();
	}

	public function get_active_lockouts(): array {
		$lockouts = get_option( self::ACTIVE_LOCKOUTS_OPTION_NAME, array() );
		$lockouts = is_array( $lockouts ) ? $lockouts : array();
		$now      = time();
		$changed  = false;

		foreach ( $lockouts as $ip => $expires ) {
			if ( (int) $expires <= $now ) {
				unset( $lockouts[ $ip ] );
				$changed = true;
			}
		}

		if ( $changed ) {
			update_option( self::ACTIVE_LOCKOUTS_OPTION_NAME, $lockouts, false );
		}

		return $lockouts;
	}

	public function lockout_expires_at( string $ip ): int {
		$lockouts = $this->get_active_lockouts();

		return isset( $lockouts[ $ip ] ) ? (int) $lockouts[ $ip ] : 0;
	}

	public function create_lockout( string $ip, int $duration_seconds ): int {
		$expires         = time() + max( 1, $duration_seconds );
		$lockouts        = $this->get_active_lockouts();
		$lockouts[ $ip ] = $expires;
		update_option( self::ACTIVE_LOCKOUTS_OPTION_NAME, $lockouts, false );

		return $expires;
	}

	public function clear_lockout( string $ip ): void {
		$lockouts = $this->get_active_lockouts();

		if ( isset( $lockouts[ $ip ] ) ) {
			unset( $lockouts[ $ip ] );
			update_option( self::ACTIVE_LOCKOUTS_OPTION_NAME, $lockouts, false );
		}
	}

	public function lockout_count( string $ip ): int {
		$counts = $this->get_lockout_counts();

		return isset( $counts[ $ip ] ) ? (int) $counts[ $ip ] : 0;
	}

	public function record_lockout( string $ip ): int {
		$counts          = $this->get_lockout_counts();
		$current_lockout = $this->lockout_count( $ip ) + 1;
		$counts[ $ip ]   = $current_lockout;

		update_option( self::LOCKOUT_COUNTS_OPTION_NAME, $counts, false );

		return $current_lockout;
	}

	private function ensure_active_lockouts_option(): void {
		if ( get_option( self::ACTIVE_LOCKOUTS_OPTION_NAME, null ) === null ) {
			add_option( self::ACTIVE_LOCKOUTS_OPTION_NAME, array(), '', false );
		}
	}

	private function ensure_lockout_counts_option(): void {
		if ( get_option( self::LOCKOUT_COUNTS_OPTION_NAME, null ) === null ) {
			add_option( self::LOCKOUT_COUNTS_OPTION_NAME, array(), '', false );
		}
	}

	private function get_lockout_counts(): array {
		$counts = get_option( self::LOCKOUT_COUNTS_OPTION_NAME, array() );

		return is_array( $counts ) ? $counts : array();
	}
}
