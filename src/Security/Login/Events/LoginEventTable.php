<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\Events;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class LoginEventTable {
	public function name(): string {
		global $wpdb;

		return $wpdb->prefix . 'openwpsecurity_loginprotection_events';
	}
}
