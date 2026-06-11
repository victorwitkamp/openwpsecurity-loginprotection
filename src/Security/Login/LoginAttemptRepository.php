<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login;

use VictorWitkamp\OpenWPSecurity\Core\Database\TableColumn;
use VictorWitkamp\OpenWPSecurity\Core\Database\TableIndex;
use VictorWitkamp\OpenWPSecurity\Core\Database\TableReference;
use VictorWitkamp\OpenWPSecurity\Core\Database\TableSchema;
use VictorWitkamp\OpenWPSecurity\Core\Database\TableSchemaInstaller;
use VictorWitkamp\OpenWPSecurity\Core\Database\TableWriter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class LoginAttemptRepository implements TableReference {
	private const DB_VERSION = '1.0.0';

	private TableSchemaInstaller $schema_installer;
	private TableWriter $writer;

	public function __construct( TableSchemaInstaller $schema_installer ) {
		$this->schema_installer = $schema_installer;
		$this->writer           = new TableWriter( $this, $this->table_schema() );
	}

	public function name(): string {
		global $wpdb;

		return $wpdb->prefix . 'openwpsecurity_loginprotection_login_attempts';
	}

	public function maybe_upgrade_schema(): void {
		$this->schema_installer->maybe_upgrade_schema( $this->table_schema() );
	}

	public function insert( LoginAttempt $login_attempt ): bool {
		return $this->writer->insert( $login_attempt->to_row() );
	}

	public function table_schema(): TableSchema {
		return new TableSchema(
			$this,
			'openwpsecurity_loginprotection_login_attempts_db_version',
			self::DB_VERSION,
			array(
				new TableColumn( 'id', 'id bigint(20) unsigned NOT NULL AUTO_INCREMENT' ),
				new TableColumn( 'created_at', 'created_at datetime NOT NULL', '', '%s' ),
				new TableColumn( 'attempt_type', "attempt_type varchar(50) NOT NULL DEFAULT ''", '', '%s' ),
				new TableColumn( 'ip_address', 'ip_address varchar(45) NOT NULL', '', '%s' ),
				new TableColumn( 'country_code', "country_code varchar(12) NOT NULL DEFAULT ''", '', '%s' ),
				new TableColumn( 'country_name', "country_name varchar(191) NOT NULL DEFAULT ''", '', '%s' ),
				new TableColumn( 'username', "username varchar(191) NOT NULL DEFAULT ''", '', '%s' ),
				new TableColumn( 'password_value', 'password_value text NULL', '', '%s' ),
				new TableColumn( 'password_mask', "password_mask varchar(191) NOT NULL DEFAULT ''", '', '%s' ),
				new TableColumn( 'password_hash', "password_hash char(64) NOT NULL DEFAULT ''", '', '%s' ),
				new TableColumn( 'user_agent', 'user_agent text NULL', '', '%s' ),
				new TableColumn( 'request_uri', 'request_uri text NULL', '', '%s' ),
				new TableColumn( 'lockout_expires_at', 'lockout_expires_at datetime NULL', null, '%s' ),
				new TableColumn( 'evidence_json', 'evidence_json longtext NULL', '', '%s' ),
			),
			array(
				new TableIndex( 'PRIMARY KEY  (id)' ),
				new TableIndex( 'KEY created_at (created_at)' ),
				new TableIndex( 'KEY attempt_type_created_at (attempt_type, created_at)' ),
				new TableIndex( 'KEY ip_created_at (ip_address, created_at)' ),
				new TableIndex( 'KEY username_created_at (username, created_at)' ),
				new TableIndex( 'KEY country_created_at (country_code, created_at)' ),
				new TableIndex( 'KEY password_hash_created_at (password_hash, created_at)' ),
				new TableIndex( 'KEY attempt_type_password_hash (attempt_type, password_hash)' ),
				new TableIndex( 'KEY attempt_type_ip_created_at (attempt_type, ip_address, created_at)' ),
			)
		);
	}
}
