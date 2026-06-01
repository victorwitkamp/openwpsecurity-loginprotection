<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\Events;

use VictorWitkamp\OpenWPSecurity\Core\Logging\EventTableReference;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class LoginEventTable implements EventTableReference {
	public function name(): string {
		global $wpdb;

		return $wpdb->prefix . 'openwpsecurity_loginprotection_events';
	}
}
