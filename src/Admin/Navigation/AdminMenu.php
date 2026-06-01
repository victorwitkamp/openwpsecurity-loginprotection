<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\LoginProtection\Admin\Navigation;

use VictorWitkamp\OpenWPSecurity\Core\Admin\Navigation\AdminMenuRegistrar;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Admin\Pages\ActivityPage;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Admin\Pages\AnalysisPage;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Admin\Pages\DashboardPage;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Admin\Pages\PermanentBansPage;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Admin\Pages\SettingsPage;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class AdminMenu {
	private const PAGE_TABS = array(
		'openwpsecurity-loginprotection'          => 'Dashboard',
		'openwpsecurity-loginprotection-activity' => 'Activity',
		'openwpsecurity-loginprotection-analysis' => 'Analysis',
		'openwpsecurity-loginprotection-bans'     => 'Permanent Bans',
		'openwpsecurity-loginprotection-settings' => 'Settings',
	);

	private AdminMenuRegistrar $registrar;

	public function __construct( DashboardPage $dashboard_page, ActivityPage $activity_page, AnalysisPage $analysis_page, PermanentBansPage $permanent_bans_page, SettingsPage $settings_page ) {
		$this->registrar = new AdminMenuRegistrar(
			'OpenWPSecurity - Login Protection',
			'OpenWPSecurity - Login Protection',
			'manage_options',
			'openwpsecurity-loginprotection',
			array( $dashboard_page, 'render' ),
			'dashicons-shield-alt',
			74,
			array(
				$this->submenu_page( 'openwpsecurity-loginprotection', 'Dashboard', array( $dashboard_page, 'render' ) ),
				$this->submenu_page( 'openwpsecurity-loginprotection-activity', 'Activity', array( $activity_page, 'render' ) ),
				$this->submenu_page( 'openwpsecurity-loginprotection-analysis', 'Analysis', array( $analysis_page, 'render' ) ),
				$this->submenu_page( 'openwpsecurity-loginprotection-bans', 'Permanent Bans', array( $permanent_bans_page, 'render' ) ),
				$this->submenu_page( 'openwpsecurity-loginprotection-settings', 'Settings', array( $settings_page, 'render' ) ),
			),
			'openwpsecurity-loginprotection',
			'openwpsecurity-loginprotection-admin',
			OPENWPSECURITY_LOGINPROTECTION_URL . 'assets/css/admin.css',
			'openwpsecurity-loginprotection-admin',
			OPENWPSECURITY_LOGINPROTECTION_URL . 'assets/js/admin.js',
			OPENWPSECURITY_LOGINPROTECTION_VERSION
		);
	}

	public function register_hooks(): void {
		$this->registrar->register_hooks();
	}

	public static function page_tabs(): array {
		return self::PAGE_TABS;
	}

	private function submenu_page( string $slug, string $label, array $callback ): array {
		return array(
			'slug'       => $slug,
			'page_title' => $label,
			'menu_title' => $label,
			'callback'   => $callback,
		);
	}
}
