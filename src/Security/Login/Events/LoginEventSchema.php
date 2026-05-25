<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\Events;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class LoginEventSchema {
	private const DB_VERSION        = '1.0.0';
	private const DB_VERSION_OPTION = 'openwpsecurity_loginprotection_login_db_version';

	private LoginEventTable $login_event_table;

	public function __construct( LoginEventTable $login_event_table ) {
		$this->login_event_table = $login_event_table;
	}

	public function maybe_upgrade_schema(): void {
		$current_version = (string) get_option( self::DB_VERSION_OPTION, '' );

		if ( $current_version !== self::DB_VERSION ) {
			$this->create_table();
			update_option( self::DB_VERSION_OPTION, self::DB_VERSION, false );
		}
	}

	private function create_table(): void {
		global $wpdb;

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$table_name      = $this->login_event_table->name();
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE {$table_name} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			created_at datetime NOT NULL,
			event_type varchar(50) NOT NULL,
			ip_address varchar(45) NOT NULL,
			country_code varchar(12) NOT NULL DEFAULT '',
			country_name varchar(191) NOT NULL DEFAULT '',
			username varchar(191) NOT NULL DEFAULT '',
			password_value text NULL,
			password_mask varchar(191) NOT NULL DEFAULT '',
			password_hash char(64) NOT NULL DEFAULT '',
			user_agent text NULL,
			request_uri text NULL,
			lockout_expires_at datetime NULL,
			details longtext NULL,
			PRIMARY KEY  (id),
			KEY event_type_created_at (event_type, created_at),
			KEY ip_address_created_at (ip_address, created_at)
		) {$charset_collate};";

		dbDelta( $sql );
	}
}
