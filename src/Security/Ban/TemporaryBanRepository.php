<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Ban;

use VictorWitkamp\OpenWPSecurity\Core\Database\TableSchemaInstaller;
use VictorWitkamp\OpenWPSecurity\Core\Security\Ban\AbstractTemporaryBanRepository;
use VictorWitkamp\OpenWPSecurity\Core\Security\Ban\TemporaryBan;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class TemporaryBanRepository extends AbstractTemporaryBanRepository {
	public function __construct( TableSchemaInstaller $schema_installer ) {
		parent::__construct(
			$schema_installer,
			'openwpsecurity_loginprotection_temporary_bans_db_version',
			'openwpsecurity_loginprotection_temporary_bans'
		);
	}

	public function name(): string {
		global $wpdb;

		return $wpdb->prefix . 'openwpsecurity_loginprotection_temporary_bans';
	}

	public function temporary_ban_expires_at( string $ip_address ): int {
		$temporary_ban = $this->find_active_temporary_ban( $ip_address );

		return null === $temporary_ban ? 0 : $temporary_ban->expires_at();
	}

	public function create_temporary_ban( string $ip_address, int $duration_seconds, int $ban_count ): int {
		$created_at    = time();
		$expires_at    = $created_at + max( 1, $duration_seconds );
		$temporary_ban = new TemporaryBan(
			$ip_address,
			$created_at,
			$expires_at,
			'login_protection',
			'WordPress login flow',
			'Too many failed login attempts.',
			'Temporary ban number ' . $ban_count . ' for this IP address.',
			(string) wp_json_encode( array( 'temporary_ban_count' => $ban_count ) )
		);

		$this->save_temporary_ban( $temporary_ban );

		return $expires_at;
	}
}
