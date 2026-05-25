<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\LoginProtection\Admin\Navigation;

use VictorWitkamp\OpenWPSecurity\LoginProtection\Admin\Pages\LoginProtectionPage;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class AdminMenu {
	private LoginProtectionPage $login_protection_page;

	public function __construct( LoginProtectionPage $login_protection_page ) {
		$this->login_protection_page = $login_protection_page;
	}

	public function register_hooks(): void {
		add_action( 'admin_menu', array( $this, 'register_menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
	}

	public function register_menu(): void {
		add_menu_page(
			'OpenWPSecurity - Login Protection',
			'OpenWPSecurity - Login Protection',
			'manage_options',
			'openwpsecurity-loginprotection',
			array( $this->login_protection_page, 'render' ),
			'dashicons-shield-alt',
			74
		);

		add_submenu_page(
			'openwpsecurity-loginprotection',
			'Login Protection',
			'Login Protection',
			'manage_options',
			'openwpsecurity-loginprotection',
			array( $this->login_protection_page, 'render' )
		);
	}

	public function enqueue_assets( string $hook_suffix ): void {
		if ( strpos( $hook_suffix, 'openwpsecurity-loginprotection' ) === false ) {
			return;
		}

		wp_enqueue_style(
			'openwpsecurity-loginprotection-admin',
			OPENWPSECURITY_LOGINPROTECTION_URL . 'assets/css/admin.css',
			array(),
			OPENWPSECURITY_LOGINPROTECTION_VERSION
		);

		wp_enqueue_script(
			'openwpsecurity-loginprotection-admin',
			OPENWPSECURITY_LOGINPROTECTION_URL . 'assets/js/admin.js',
			array(),
			OPENWPSECURITY_LOGINPROTECTION_VERSION,
			true
		);
	}
}
