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
			<h1>OpenWPSecurity - Login Protection Settings</h1>
			<p>Configure storage, IP resolution, whitelisting, and GeoIP lookup.</p>
			<?php $this->render_page_tabs( 'openwpsecurity-loginprotection-settings' ); ?>

			<?php if ( $settings_updated ) : ?>
				<div class="notice notice-success is-dismissible"><p>Login Protection settings saved.</p></div>
			<?php endif; ?>

			<form method="post" class="vwfw-panel">
				<?php wp_nonce_field( 'vwfw_save_login_settings' ); ?>
				<div class="vwfw-settings-section">
					<h2>Runtime &amp; Data Settings</h2>
					<p class="description">Temporary-ban and permanent-ban thresholds are managed on the <strong>Policies</strong> page.</p>
					<table class="form-table" role="presentation">
						<tr>
							<th scope="row"><label for="event_retention_days">Event retention</label></th>
							<td>
								<input id="event_retention_days" name="event_retention_days" type="number" min="0" value="<?php echo esc_attr( (string) $settings['event_retention_days'] ); ?>" class="small-text"> days
								<p class="description">How long Login Protection attempt and temporary-ban event records remain in the database. Use <strong>0</strong> to keep them forever.</p>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="trusted_ip_headers">Trusted IP headers</label></th>
							<td>
								<input id="trusted_ip_headers" name="trusted_ip_headers" type="text" value="<?php echo esc_attr( implode( ', ', (array) $settings['trusted_ip_headers'] ) ); ?>" class="regular-text">
								<p class="description">Comma-separated header names used to resolve the visitor IP address. <code>REMOTE_ADDR</code> is always retained as a fallback.</p>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="whitelist_ips">Whitelisted IP addresses</label></th>
							<td>
								<textarea id="whitelist_ips" name="whitelist_ips" rows="6" class="large-text code"><?php echo esc_textarea( implode( "\n", (array) $settings['whitelist_ips'] ) ); ?></textarea>
								<p class="description">One IP address per line. Whitelisted IPs bypass Login Protection temporary and permanent bans.</p>
							</td>
						</tr>
						<tr>
							<th scope="row">Remote GeoIP lookup</th>
							<td>
								<label for="enable_remote_geoip">
									<input id="enable_remote_geoip" name="enable_remote_geoip" type="checkbox" value="1" <?php checked( ! empty( $settings['enable_remote_geoip'] ) ); ?>>
									Use a remote lookup when local GeoIP resolution does not resolve an IP address.
								</label>
							</td>
						</tr>
					</table>
				</div>
				<p class="submit">
					<button type="submit" name="vwfw_save_login_settings" class="button button-primary">Save Login Protection Settings</button>
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
