<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\Events;

use VictorWitkamp\OpenWPSecurity\Core\Database\TableColumn;
use VictorWitkamp\OpenWPSecurity\Core\Database\TableIndex;
use VictorWitkamp\OpenWPSecurity\Core\Database\TableSchemaInstaller;
use VictorWitkamp\OpenWPSecurity\Core\Logging\EventSchema as CoreEventSchema;
use VictorWitkamp\OpenWPSecurity\Core\Logging\EventTableSchemaFactory;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class LoginEventSchema extends CoreEventSchema {
	private const DB_VERSION        = '1.1.0';
	private const DB_VERSION_OPTION = 'openwpsecurity_loginprotection_login_db_version';

	public function __construct( TableSchemaInstaller $schema_installer, EventTableSchemaFactory $schema_factory, LoginEventTable $login_event_table ) {
		parent::__construct(
			$schema_installer,
			$schema_factory->create(
				$login_event_table,
				self::DB_VERSION_OPTION,
				self::DB_VERSION,
				self::password_columns(),
				self::password_indexes()
			)
		);
	}

	private static function password_columns(): array {
		return array(
			new TableColumn( 'password_value', 'password_value text NULL', '', '%s' ),
			new TableColumn( 'password_mask', "password_mask varchar(191) NOT NULL DEFAULT ''", '', '%s' ),
			new TableColumn( 'password_hash', "password_hash char(64) NOT NULL DEFAULT ''", '', '%s' ),
		);
	}

	private static function password_indexes(): array {
		return array(
			new TableIndex( 'KEY created_at (created_at)' ),
			new TableIndex( 'KEY password_hash_created_at (password_hash, created_at)' ),
			new TableIndex( 'KEY event_type_password_hash (event_type, password_hash)' ),
			new TableIndex( 'KEY event_type_ip_created_at (event_type, ip_address, created_at)' ),
		);
	}
}
