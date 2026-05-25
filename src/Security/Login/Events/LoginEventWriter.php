<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\Events;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class LoginEventWriter {
	private LoginEventTable $login_event_table;

	public function __construct( LoginEventTable $login_event_table ) {
		$this->login_event_table = $login_event_table;
	}

	public function insert( array $event ): void {
		global $wpdb;

		$defaults = array(
			'created_at'         => current_time( 'mysql', true ),
			'event_type'         => '',
			'ip_address'         => '',
			'country_code'       => '',
			'country_name'       => '',
			'username'           => '',
			'password_value'     => '',
			'password_mask'      => '',
			'password_hash'      => '',
			'user_agent'         => '',
			'request_uri'        => '',
			'lockout_expires_at' => null,
			'details'            => '',
		);

		$event = wp_parse_args( $event, $defaults );

		$wpdb->insert(
			$this->login_event_table->name(),
			$event,
			array(
				'%s',
				'%s',
				'%s',
				'%s',
				'%s',
				'%s',
				'%s',
				'%s',
				'%s',
				'%s',
				'%s',
				'%s',
				'%s',
			)
		);
	}
}
