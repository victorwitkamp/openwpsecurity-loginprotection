<?php
/**
 * Plugin Name: OpenWPSecurity - Login Protection
 * Plugin URI:  https://victorwitkamp.nl/
 * Description: Login protection for WordPress with failed-login tracking, lockouts, permanent bans, and login-event reporting.
 * Version:     0.2.0
 * Requires at least: 6.5
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
use VictorWitkamp\OpenWPSecurity\Core\Http\IpAddressInspector;
use VictorWitkamp\OpenWPSecurity\Core\Http\RequestContext;
use VictorWitkamp\OpenWPSecurity\Core\Logging\EventRetention;
use VictorWitkamp\OpenWPSecurity\Core\Presentation\Templates\TemplateRenderer;
use VictorWitkamp\OpenWPSecurity\Core\Runtime\WordPressPluginIntegration;
use VictorWitkamp\OpenWPSecurity\Core\Security\Ban\PermanentBanStore;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Configuration\Settings;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Runtime\Plugin;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\Events\LoginEventLogger;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\Events\LoginEventTable;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'OPENWPSECURITY_LOGINPROTECTION_VERSION', '0.2.0' );
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
		EventRetention::class       => static function ( Settings $settings, LoginEventTable $login_event_table ): EventRetention {
			return new EventRetention( $settings, $login_event_table, 'openwpsecurity_loginprotection_delete_expired_events' );
		},
		PermanentBanStore::class    => static function ( LoginEventLogger $login_event_logger, IpAddressInspector $ip_address_inspector ): PermanentBanStore {
			return new PermanentBanStore(
				'openwpsecurity_loginprotection_permanent_bans',
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
		EventReportFormatter::class => static function (): EventReportFormatter {
			return new EventReportFormatter(
				array(
					'success_login'         => 'Successful Login',
					'failed_login'          => 'Failed Login',
					'blocked_login'         => 'Blocked Login',
					'login_lockout'         => 'Lockout Created',
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
