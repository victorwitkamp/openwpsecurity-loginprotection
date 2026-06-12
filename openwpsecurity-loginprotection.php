<?php
/**
 * Plugin Name: OpenWPSecurity - Login Protection
 * Plugin URI:  https://github.com/victorwitkamp/openwpsecurity-loginprotection
 * Description: Login protection for WordPress with failed-login tracking, temporary bans, permanent bans, and login-event reporting.
 * Version:     0.3.0
 * Requires at least: 6.5
 * Tested up to: 6.9.4
 * Requires PHP: 8.2
 * Author:      Victor Witkamp
 * Author URI:  https://victorwitkamp.nl/
 * License:     GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: openwpsecurity-loginprotection
 */

declare(strict_types=1);

use Psr\Http\Message\ServerRequestInterface;
use VictorWitkamp\OpenWPSecurity\Core\Admin\Reporting\EventReportFormatter;
use VictorWitkamp\OpenWPSecurity\Core\Database\CreatedAtRetention;
use VictorWitkamp\OpenWPSecurity\Core\Database\TableSchemaInstaller;
use VictorWitkamp\OpenWPSecurity\Core\Http\IpAddressInspector;
use VictorWitkamp\OpenWPSecurity\Core\Http\RequestContext;
use VictorWitkamp\OpenWPSecurity\Core\Presentation\Templates\TemplateRenderer;
use VictorWitkamp\OpenWPSecurity\Core\Runtime\WordPressPluginIntegration;
use VictorWitkamp\OpenWPSecurity\Core\Security\Ban\PermanentBanSchema;
use VictorWitkamp\OpenWPSecurity\Core\Security\Ban\PermanentBanStore;
use VictorWitkamp\OpenWPSecurity\Core\Security\Ban\TemporaryBanCleanup;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Configuration\Settings;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Runtime\Plugin;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Ban\PermanentBanRepository;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Ban\TemporaryBanRepository;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\Events\LoginEventLogger;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\LoginAttemptRepository;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\LoginLockoutRepository;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'OPENWPSECURITY_LOGINPROTECTION_VERSION', '0.3.0' );
define( 'OPENWPSECURITY_LOGINPROTECTION_FILE', __FILE__ );
define( 'OPENWPSECURITY_LOGINPROTECTION_DIR', plugin_dir_path( __FILE__ ) );
define( 'OPENWPSECURITY_LOGINPROTECTION_URL', plugin_dir_url( __FILE__ ) );

$composer_autoload = OPENWPSECURITY_LOGINPROTECTION_DIR . 'vendor/autoload.php';

if ( ! file_exists( $composer_autoload ) ) {
	add_action(
		'admin_notices',
		static function (): void {
			echo '<div class="notice notice-error"><p>OpenWPSecurity - Login Protection is missing Composer dependencies. Run <code>composer install --no-dev</code> in the plugin directory.</p></div>';
		}
	);
	return;
}

require_once $composer_autoload;

$wordpress_integration = new WordPressPluginIntegration(
	Plugin::class,
	'Login Protection',
	array(
		RequestContext::class       => static function ( Settings $settings, IpAddressInspector $ip_address_inspector, ServerRequestInterface $request ): RequestContext {
			return new RequestContext( $settings, $ip_address_inspector, $request, 'openwpsecurity_loginprotection_is_ip_whitelisted' );
		},
		TemplateRenderer::class     => static function (): TemplateRenderer {
			return new TemplateRenderer(
				OPENWPSECURITY_LOGINPROTECTION_DIR . 'templates/',
				'Login Protection template file was not found.',
				'openwpsecurity-loginprotection-runtime',
				OPENWPSECURITY_LOGINPROTECTION_URL . 'assets/css/runtime.css',
				'openwpsecurity-loginprotection-runtime',
				OPENWPSECURITY_LOGINPROTECTION_URL . 'assets/js/runtime.js',
				OPENWPSECURITY_LOGINPROTECTION_VERSION
			);
		},
		CreatedAtRetention::class   => static function ( Settings $settings, LoginAttemptRepository $login_attempts, LoginLockoutRepository $login_lockouts ): CreatedAtRetention {
			return new CreatedAtRetention(
				$settings,
				array(
					$login_attempts,
					$login_lockouts,
				),
				'openwpsecurity_loginprotection_delete_expired_rows'
			);
		},
		PermanentBanStore::class    => static function ( PermanentBanRepository $permanent_bans, TableSchemaInstaller $schema_installer, LoginEventLogger $login_event_logger, IpAddressInspector $ip_address_inspector ): PermanentBanStore {
			$ban_schema = new PermanentBanSchema( $schema_installer, $permanent_bans, 'openwpsecurity_loginprotection_permanent_bans_db_version' );

			return new PermanentBanStore(
				$permanent_bans,
				$ban_schema,
				$ip_address_inspector,
				static function ( string $ip, string $reason, string $source, array $context ) use ( $login_event_logger ): void {
					$login_event_logger->log(
						'permanent_ban_created',
						$ip,
						'',
						'',
						array(
							'details' => array_merge(
								array(
									'reason' => $reason,
									'source' => $source,
								),
								$context
							),
						)
					);
				},
				'login_protection'
			);
		},
		TemporaryBanCleanup::class  => static function ( TemporaryBanRepository $temporary_ban_repository ): TemporaryBanCleanup {
			return new TemporaryBanCleanup( $temporary_ban_repository, 'openwpsecurity_loginprotection_purge_expired_temporary_bans' );
		},
		EventReportFormatter::class => static function (): EventReportFormatter {
			return new EventReportFormatter(
				array(
					'success_login'         => 'Successful Login',
					'failed_login'          => 'Failed Login',
					'blocked_login'         => 'Blocked Login',
					'login_lockout'         => 'Temporary Ban Created',
					'permanent_ban_created' => 'Permanent Ban Created',
				),
				array(
					'login_protection' => 'Login Protection',
					'login_lockout'    => 'Login Protection',
					'manual'           => 'Manual',
				)
			);
		},
	)
);

register_activation_hook( OPENWPSECURITY_LOGINPROTECTION_FILE, array( $wordpress_integration, 'activate' ) );
register_deactivation_hook( OPENWPSECURITY_LOGINPROTECTION_FILE, array( $wordpress_integration, 'deactivate' ) );

add_action( 'plugins_loaded', array( $wordpress_integration, 'initialize_runtime' ) );
