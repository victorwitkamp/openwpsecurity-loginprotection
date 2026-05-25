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

use VictorWitkamp\OpenWPSecurity\LoginProtection\Runtime\WordPressIntegration;

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

$wordpress_integration = new WordPressIntegration();

register_activation_hook( OPENWPSECURITY_LOGINPROTECTION_FILE, array( $wordpress_integration, 'activate' ) );
register_deactivation_hook( OPENWPSECURITY_LOGINPROTECTION_FILE, array( $wordpress_integration, 'deactivate' ) );

add_action( 'plugins_loaded', array( $wordpress_integration, 'initialize_runtime' ) );
