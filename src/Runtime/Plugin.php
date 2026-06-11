<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\LoginProtection\Runtime;

use VictorWitkamp\OpenWPSecurity\Core\Runtime\PluginLifecycle;
use VictorWitkamp\OpenWPSecurity\Core\Database\CreatedAtRetention;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Admin\Navigation\AdminMenu;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Configuration\Settings;
use VictorWitkamp\OpenWPSecurity\Core\Security\Ban\PermanentBanStore;
use VictorWitkamp\OpenWPSecurity\Core\Security\Ban\TemporaryBanCleanup;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Ban\TemporaryBanCounterStore;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Ban\TemporaryBanRepository;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\FailedLoginStreakStore;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\LoginAttemptGuard;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\LoginAttemptRepository;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\LoginLockoutRepository;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Plugin implements PluginLifecycle {
	private Settings $settings;
	private LoginAttemptRepository $login_attempts;
	private LoginLockoutRepository $login_lockouts;
	private CreatedAtRetention $retention;
	private FailedLoginStreakStore $failed_login_streak_store;
	private TemporaryBanRepository $temporary_ban_repository;
	private TemporaryBanCounterStore $temporary_ban_counter_store;
	private TemporaryBanCleanup $temporary_ban_cleanup;
	private PermanentBanStore $ban_store;
	private LoginAttemptGuard $login_guard;
	private AdminMenu $admin_menu;
	private bool $runtime_initialized = false;

	public function __construct(
		Settings $settings,
		LoginAttemptRepository $login_attempts,
		LoginLockoutRepository $login_lockouts,
		CreatedAtRetention $retention,
		FailedLoginStreakStore $failed_login_streak_store,
		TemporaryBanRepository $temporary_ban_repository,
		TemporaryBanCounterStore $temporary_ban_counter_store,
		TemporaryBanCleanup $temporary_ban_cleanup,
		PermanentBanStore $ban_store,
		LoginAttemptGuard $login_guard,
		AdminMenu $admin_menu
	) {
		$this->settings                    = $settings;
		$this->login_attempts              = $login_attempts;
		$this->login_lockouts              = $login_lockouts;
		$this->retention                   = $retention;
		$this->failed_login_streak_store   = $failed_login_streak_store;
		$this->temporary_ban_repository    = $temporary_ban_repository;
		$this->temporary_ban_counter_store = $temporary_ban_counter_store;
		$this->temporary_ban_cleanup       = $temporary_ban_cleanup;
		$this->ban_store                   = $ban_store;
		$this->login_guard                 = $login_guard;
		$this->admin_menu                  = $admin_menu;
	}

	public function activate(): void {
		$this->prepare_storage();
		$this->retention->activate();
		$this->temporary_ban_cleanup->activate();
	}

	public function deactivate(): void {
		$this->retention->deactivate();
		$this->temporary_ban_cleanup->deactivate();
	}

	public function initialize_runtime(): void {
		if ( $this->runtime_initialized ) {
			return;
		}

		$this->prepare_storage();
		$this->login_guard->register_hooks();
		$this->retention->register_hooks();
		$this->temporary_ban_cleanup->register_hooks();

		if ( is_admin() ) {
			$this->admin_menu->register_hooks();
		}

		$this->runtime_initialized = true;
	}

	private function prepare_storage(): void {
		$this->settings->ensure_defaults();
		$this->failed_login_streak_store->ensure_storage();
		$this->temporary_ban_repository->maybe_upgrade_schema();
		$this->temporary_ban_counter_store->maybe_upgrade_schema();
		$this->ban_store->ensure_storage();
		$this->login_attempts->maybe_upgrade_schema();
		$this->login_lockouts->maybe_upgrade_schema();
	}
}
