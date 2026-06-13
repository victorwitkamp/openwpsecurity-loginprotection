<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login;

use VictorWitkamp\OpenWPSecurity\LoginProtection\Configuration\Settings;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Runtime\TransientKeyBuilder;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class AttemptCounter {
	private Settings $settings;
	private TransientKeyBuilder $transient_key_builder;

	public function __construct( Settings $settings, TransientKeyBuilder $transient_key_builder ) {
		$this->settings              = $settings;
		$this->transient_key_builder = $transient_key_builder;
	}

	/**
	 * @return array{count: int, started_at: int}
	 */
	public function current( string $ip ): array {
		$state = get_transient( $this->transient_key_builder->login_attempt( $ip ) );

		if ( ! is_array( $state ) ) {
			return array(
				'count'      => 0,
				'started_at' => time(),
			);
		}

		return array(
			'count'      => isset( $state['count'] ) ? (int) $state['count'] : 0,
			'started_at' => isset( $state['started_at'] ) ? (int) $state['started_at'] : time(),
		);
	}

	/**
	 * @return array{count: int, started_at: int}
	 */
	public function increment( string $ip ): array {
		$settings = $this->settings->get();
		$state    = $this->current( $ip );

		if ( time() - (int) $state['started_at'] > ( $settings['login_window_minutes'] * MINUTE_IN_SECONDS ) ) {
			$state = array(
				'count'      => 0,
				'started_at' => time(),
			);
		}

		$state['count'] = (int) $state['count'] + 1;

		set_transient(
			$this->transient_key_builder->login_attempt( $ip ),
			$state,
			$settings['login_window_minutes'] * MINUTE_IN_SECONDS
		);

		return $state;
	}

	public function clear( string $ip ): void {
		delete_transient( $this->transient_key_builder->login_attempt( $ip ) );
	}
}
