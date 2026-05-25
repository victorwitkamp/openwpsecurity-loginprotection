<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\LoginProtection\Logging;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class CredentialFormatter {
	public function password_value( string $password ): string {
		// Intentionally retained for password/IP correlation reports.
		return $password;
	}

	public function mask_password( string $password ): string {
		$password_length = strlen( $password );

		if ( 0 === $password_length ) {
			return '';
		}

		return str_repeat( '*', min( $password_length, 12 ) ) . sprintf( ' (%d chars)', $password_length );
	}

	public function password_fingerprint( string $password ): string {
		if ( '' === $password ) {
			return '';
		}

		return hash( 'sha256', wp_salt( 'auth' ) . '|' . $password );
	}
}
