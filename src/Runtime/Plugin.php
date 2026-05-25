<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\LoginProtection\Runtime;

use VictorWitkamp\OpenWPSecurity\LoginProtection\Admin\Navigation\AdminMenu;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Configuration\Settings;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Logging\EventRetention;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Ban\PermanentBanStore;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\Events\LoginEventMigration;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\Events\LoginEventSchema;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\FailedLoginStreakStore;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\LoginAttemptGuard;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\LoginLockoutStore;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Plugin {
	private Settings $settings;
	private LoginEventSchema $login_event_schema;
	private LoginEventMigration $login_event_migration;
	private EventRetention $event_retention;
	private FailedLoginStreakStore $failed_login_streak_store;
	private LoginLockoutStore $lockout_store;
	private PermanentBanStore $ban_store;
	private LoginAttemptGuard $login_guard;
	private AdminMenu $admin_menu;
	private bool $runtime_initialized = false;

	public function __construct(
		Settings $settings,
		LoginEventSchema $login_event_schema,
		LoginEventMigration $login_event_migration,
		EventRetention $event_retention,
		FailedLoginStreakStore $failed_login_streak_store,
		LoginLockoutStore $lockout_store,
		PermanentBanStore $ban_store,
		LoginAttemptGuard $login_guard,
		AdminMenu $admin_menu
	) {
		$this->settings                  = $settings;
		$this->login_event_schema        = $login_event_schema;
		$this->login_event_migration     = $login_event_migration;
		$this->event_retention           = $event_retention;
		$this->failed_login_streak_store = $failed_login_streak_store;
		$this->lockout_store             = $lockout_store;
		$this->ban_store                 = $ban_store;
		$this->login_guard               = $login_guard;
		$this->admin_menu                = $admin_menu;
	}

	public function activate(): void {
		$this->prepare_storage();
		$this->event_retention->activate();
	}

	public function deactivate(): void {
		$this->event_retention->deactivate();
	}

	public function initialize_runtime(): void {
		if ( $this->runtime_initialized ) {
			return;
		}

		$this->prepare_storage();
		$this->login_guard->register_hooks();
		$this->event_retention->register_hooks();

		if ( is_admin() ) {
			$this->admin_menu->register_hooks();
		}

		$this->runtime_initialized = true;
	}

	private function prepare_storage(): void {
		$this->settings->ensure_defaults();
		$this->failed_login_streak_store->ensure_storage();
		$this->lockout_store->ensure_storage();
		$this->ban_store->ensure_storage();
		$this->login_event_schema->maybe_upgrade_schema();
		$this->login_event_migration->maybe_migrate();
	}
}
