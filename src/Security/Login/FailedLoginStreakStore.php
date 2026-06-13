<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class FailedLoginStreakStore {
	private const OPTION_NAME = 'openwpsecurity_loginprotection_failed_login_streaks';

	public function ensure_storage(): void {
		if ( get_option( self::OPTION_NAME, null ) === null ) {
			add_option( self::OPTION_NAME, array(), '', false );
		}
	}

	public function failed_login_streak( string $ip ): int {
		$streaks = $this->failed_login_streaks();

		return isset( $streaks[ $ip ] ) ? (int) $streaks[ $ip ] : 0;
	}

	public function record_failed_login( string $ip ): int {
		$streaks               = $this->failed_login_streaks();
		$current_failed_streak = $this->failed_login_streak( $ip ) + 1;
		$streaks[ $ip ]        = $current_failed_streak;

		update_option( self::OPTION_NAME, $streaks, false );

		return $current_failed_streak;
	}

	public function clear_failed_login_streak( string $ip ): void {
		$streaks = $this->failed_login_streaks();

		if ( isset( $streaks[ $ip ] ) ) {
			unset( $streaks[ $ip ] );
			update_option( self::OPTION_NAME, $streaks, false );
		}
	}

	/**
	 * @return array<string, int>
	 */
	private function failed_login_streaks(): array {
		$streaks = get_option( self::OPTION_NAME, array() );

		return is_array( $streaks ) ? $streaks : array();
	}
}
