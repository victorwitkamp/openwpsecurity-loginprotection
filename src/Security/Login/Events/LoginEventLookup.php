<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\Events;

use VictorWitkamp\OpenWPSecurity\Core\Logging\EventLookup as CoreEventLookup;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class LoginEventLookup extends CoreEventLookup {
	public function __construct( LoginEventTable $login_event_table ) {
		parent::__construct(
			$login_event_table,
			array(
				'created_at',
				'event_type',
				'ip_address',
				'country_code',
				'country_name',
				'username',
				'password_value',
				'password_mask',
				'user_agent',
				'request_uri',
				'lockout_expires_at',
				'details',
			),
			array(
				'event_type',
				'country_code',
				'ip_address',
				'username',
				'request_uri',
			)
		);
	}
}
