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

		$this->handle_settings_submission();
		$settings = $this->settings->get();
		?>
		<div class="wrap vwfw-admin">
			<h1>OpenWPSecurity - Login Protection Settings</h1>
			<?php $this->render_page_tabs( 'openwpsecurity-loginprotection-settings' ); ?>

			<?php // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only success flag after redirect. ?>
			<?php if ( isset( $_GET['settings-updated'] ) ) : ?>
				<div class="notice notice-success is-dismissible"><p>Login Protection settings saved.</p></div>
			<?php endif; ?>

			<form method="post" class="vwfw-panel">
				<?php wp_nonce_field( 'vwfw_save_login_settings' ); ?>
				<div class="vwfw-settings-section">
					<h2>Login Protection Settings</h2>
					<p class="description">These settings apply only to failed-password handling, login lockouts, failed-login streaks, and login-triggered permanent bans. They do not change Request Handling or Captcha behavior.</p>
					<table class="form-table" role="presentation">
						<tr>
							<th scope="row"><label for="login_max_attempts">Login attempts before lockout</label></th>
							<td>
								<input id="login_max_attempts" name="login_max_attempts" type="number" min="1" value="<?php echo esc_attr( (string) $settings['login_max_attempts'] ); ?>" class="small-text">
								<p class="description">How many failed password submissions from the same IP address are allowed inside the login window before Login Protection creates a lockout.</p>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="login_window_minutes">Login attempt window</label></th>
							<td>
								<input id="login_window_minutes" name="login_window_minutes" type="number" min="1" value="<?php echo esc_attr( (string) $settings['login_window_minutes'] ); ?>" class="small-text"> minutes
								<p class="description">The rolling window used to count failed password submissions for Login Protection.</p>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="login_lockout_minutes">Lockout duration</label></th>
							<td>
								<input id="login_lockout_minutes" name="login_lockout_minutes" type="number" min="1" value="<?php echo esc_attr( (string) $settings['login_lockout_minutes'] ); ?>" class="small-text"> minutes
								<p class="description">How long the Login Protection lockout remains active after the failed-attempt threshold is exceeded.</p>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="login_lockouts_before_permanent_ban">Permanent ban after lockouts</label></th>
							<td>
								<input id="login_lockouts_before_permanent_ban" name="login_lockouts_before_permanent_ban" type="number" min="0" value="<?php echo esc_attr( (string) $settings['login_lockouts_before_permanent_ban'] ); ?>" class="small-text"> lockouts
								<p class="description">How many completed Login Protection lockouts from the same IP address are allowed before a permanent ban is created. Use <strong>0</strong> to disable login-triggered permanent bans.</p>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="login_failed_attempts_before_permanent_ban">Permanent ban after failed logins in a row</label></th>
							<td>
								<input id="login_failed_attempts_before_permanent_ban" name="login_failed_attempts_before_permanent_ban" type="number" min="0" value="<?php echo esc_attr( (string) $settings['login_failed_attempts_before_permanent_ban'] ); ?>" class="small-text"> failed logins
								<p class="description">How many failed login attempts in a row from the same IP address are allowed before a permanent ban is created, even if those failures are spread out over time. A successful login resets this failed-login streak. Use <strong>0</strong> to disable this permanent-ban path.</p>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="event_retention_days">Event retention</label></th>
							<td>
								<input id="event_retention_days" name="event_retention_days" type="number" min="0" value="<?php echo esc_attr( (string) $settings['event_retention_days'] ); ?>" class="small-text"> days
								<p class="description">How long login-event records should be kept. Use <strong>0</strong> to keep them forever.</p>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="trusted_ip_headers">Trusted IP headers</label></th>
							<td>
								<input id="trusted_ip_headers" name="trusted_ip_headers" type="text" value="<?php echo esc_attr( implode( ',', (array) $settings['trusted_ip_headers'] ) ); ?>" class="regular-text">
								<p class="description">Comma-separated header names used to resolve the visitor IP address. <code>REMOTE_ADDR</code> is always retained as a fallback.</p>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="whitelist_ips">Whitelisted IP addresses</label></th>
							<td>
								<textarea id="whitelist_ips" name="whitelist_ips" rows="6" class="large-text code"><?php echo esc_textarea( implode( "\n", (array) $settings['whitelist_ips'] ) ); ?></textarea>
								<p class="description">One IP address per line. Whitelisted IPs bypass Login Protection lockouts and bans.</p>
							</td>
						</tr>
						<tr>
							<th scope="row">Remote GeoIP lookup</th>
							<td>
								<label for="enable_remote_geoip">
									<input id="enable_remote_geoip" name="enable_remote_geoip" type="checkbox" value="1" <?php checked( ! empty( $settings['enable_remote_geoip'] ) ); ?>>
									Enable remote country lookups when the local GeoIP extension does not resolve an IP address.
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

	private function handle_settings_submission(): void {
		if ( 'POST' !== $_SERVER['REQUEST_METHOD'] || ! isset( $_POST['vwfw_save_login_settings'] ) ) {
			return;
		}

		check_admin_referer( 'vwfw_save_login_settings' );
		$this->settings->update( $this->settings->sanitize_submission( wp_unslash( $_POST ) ) );
		wp_safe_redirect(
			add_query_arg(
				array(
					'page'             => 'openwpsecurity-loginprotection-settings',
					'settings-updated' => '1',
				),
				admin_url( 'admin.php' )
			)
		);
		exit;
	}
}
