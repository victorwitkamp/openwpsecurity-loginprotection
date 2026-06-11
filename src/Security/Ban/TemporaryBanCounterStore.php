<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Ban;

use VictorWitkamp\OpenWPSecurity\Core\Database\TableSchemaInstaller;
use VictorWitkamp\OpenWPSecurity\Core\Security\Ban\AbstractTemporaryBanCounterStore;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class TemporaryBanCounterStore extends AbstractTemporaryBanCounterStore {
	public function __construct( TableSchemaInstaller $schema_installer ) {
		parent::__construct( $schema_installer, 'openwpsecurity_loginprotection_temporary_ban_counts_db_version' );
	}

	public function name(): string {
		global $wpdb;

		return $wpdb->prefix . 'openwpsecurity_loginprotection_temporary_ban_counts';
	}
}
