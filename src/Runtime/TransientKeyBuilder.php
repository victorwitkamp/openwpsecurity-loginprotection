<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\LoginProtection\Runtime;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class TransientKeyBuilder {
	public function login_attempt( string $ip_address ): string {
		return 'vwlp_login_attempt_' . md5( $ip_address );
	}
}
