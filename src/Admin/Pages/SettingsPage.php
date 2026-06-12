<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\LoginProtection\Admin\Pages;

use VictorWitkamp\OpenWPSecurity\Core\Admin\Pages\AbstractAdminPage;
use VictorWitkamp\OpenWPSecurity\Core\Admin\Reporting\EventReportFormatter;
use VictorWitkamp\OpenWPSecurity\Core\Admin\Reporting\ReportPeriod;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Admin\Navigation\AdminMenu;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Configuration\Settings;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class SettingsPage extends AbstractAdminPage {
	private Settings $settings;

	public function __construct( Settings $settings, ReportPeriod $report_period, EventReportFormatter $event_report_formatter ) {
		parent::__construct( $report_period, $event_report_formatter, AdminMenu::page_tabs() );
		$this->settings = $settings;
	}

	public function render(): void {
		$this->assert_page_access();

		$settings_updated = $this->handle_form_submission();
		$settings         = $this->settings->get();
		?>
		<div class="wrap vwfw-admin">
			<h1><?php esc_html_e( 'OpenWPSecurity - Login Protection Settings', 'openwpsecurity-loginprotection' ); ?></h1>
			<p><?php esc_html_e( 'Configure storage, IP resolution, whitelisting, and GeoIP lookup.', 'openwpsecurity-loginprotection' ); ?></p>
			<?php $this->render_page_tabs( 'openwpsecurity-loginprotection-settings' ); ?>

			<?php if ( $settings_updated ) : ?>
				<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Login Protection settings saved.', 'openwpsecurity-loginprotection' ); ?></p></div>
			<?php endif; ?>

			<form method="post" class="vwfw-panel">
				<?php wp_nonce_field( 'vwfw_save_login_settings' ); ?>
				<div class="vwfw-settings-section">
					<h2><?php esc_html_e( 'Runtime &amp; Data Settings', 'openwpsecurity-loginprotection' ); ?></h2>
					<p class="description"><?php echo wp_kses_post( __( 'Temporary-ban and permanent-ban thresholds are managed on the <strong>Policies</strong> page.', 'openwpsecurity-loginprotection' ) ); ?></p>
					<table class="form-table" role="presentation">
						<tr>
							<th scope="row"><label for="event_retention_days"><?php esc_html_e( 'Event retention', 'openwpsecurity-loginprotection' ); ?></label></th>
							<td>
								<input id="event_retention_days" name="event_retention_days" type="number" min="0" value="<?php echo esc_attr( (string) $settings['event_retention_days'] ); ?>" class="small-text"> <?php esc_html_e( 'days', 'openwpsecurity-loginprotection' ); ?>
								<p class="description"><?php echo wp_kses_post( __( 'How long Login Protection attempt and temporary-ban event records remain in the database. Use <strong>0</strong> to keep them forever.', 'openwpsecurity-loginprotection' ) ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="trusted_ip_headers"><?php esc_html_e( 'Trusted IP headers', 'openwpsecurity-loginprotection' ); ?></label></th>
							<td>
								<input id="trusted_ip_headers" name="trusted_ip_headers" type="text" value="<?php echo esc_attr( implode( ', ', (array) $settings['trusted_ip_headers'] ) ); ?>" class="regular-text">
								<p class="description"><?php echo wp_kses_post( __( 'Comma-separated header names used to resolve the visitor IP address. <code>REMOTE_ADDR</code> is always retained as a fallback.', 'openwpsecurity-loginprotection' ) ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="whitelist_ips"><?php esc_html_e( 'Whitelisted IP addresses', 'openwpsecurity-loginprotection' ); ?></label></th>
							<td>
								<textarea id="whitelist_ips" name="whitelist_ips" rows="6" class="large-text code"><?php echo esc_textarea( implode( "\n", (array) $settings['whitelist_ips'] ) ); ?></textarea>
								<p class="description"><?php esc_html_e( 'One IP address per line. Whitelisted IPs bypass Login Protection temporary and permanent bans.', 'openwpsecurity-loginprotection' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Remote GeoIP lookup', 'openwpsecurity-loginprotection' ); ?></th>
							<td>
								<label for="enable_remote_geoip">
									<input id="enable_remote_geoip" name="enable_remote_geoip" type="checkbox" value="1" <?php checked( ! empty( $settings['enable_remote_geoip'] ) ); ?>>
									<?php esc_html_e( 'Use a remote lookup when local GeoIP resolution does not resolve an IP address.', 'openwpsecurity-loginprotection' ); ?>
								</label>
							</td>
						</tr>
					</table>
				</div>
				<p class="submit">
					<button type="submit" name="vwfw_save_login_settings" class="button button-primary"><?php esc_html_e( 'Save Login Protection Settings', 'openwpsecurity-loginprotection' ); ?></button>
				</p>
			</form>
		</div>
		<?php
	}

	private function handle_form_submission(): bool {
		if ( 'POST' !== $_SERVER['REQUEST_METHOD'] || ! isset( $_POST['vwfw_save_login_settings'] ) ) {
			return false;
		}

		check_admin_referer( 'vwfw_save_login_settings' );
		$this->settings->update( $this->settings->sanitize_infrastructure_submission( wp_unslash( $_POST ) ) );
		return true;
	}
}
