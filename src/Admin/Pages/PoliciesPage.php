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

final class PoliciesPage extends AbstractAdminPage {
	private Settings $settings;

	public function __construct( Settings $settings, ReportPeriod $report_period, EventReportFormatter $event_report_formatter ) {
		parent::__construct( $report_period, $event_report_formatter, AdminMenu::page_tabs() );
		$this->settings = $settings;
	}

	public function render(): void {
		$this->assert_page_access();

		$policies_updated = $this->handle_form_submission();
		$settings         = $this->settings->get();
		?>
		<div class="wrap vwfw-admin">
			<h1>OpenWPSecurity - Login Protection Policies</h1>
			<p>Configure failed-login counting, temporary bans, and permanent-ban escalation.</p>
			<?php $this->render_page_tabs( 'openwpsecurity-loginprotection-policies' ); ?>

			<?php if ( $policies_updated ) : ?>
				<div class="notice notice-success is-dismissible"><p>Login Protection policies saved.</p></div>
			<?php endif; ?>

			<form method="post" class="vwfw-panel">
				<?php wp_nonce_field( 'vwfw_save_login_policies' ); ?>
				<h2>Login Enforcement Policy</h2>
				<p class="description">Failed attempts are counted per IP address. Temporary bans and failed-login streaks can independently escalate to a permanent ban.</p>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="login_max_attempts">Attempts before temporary ban</label></th>
						<td>
							<input id="login_max_attempts" name="login_max_attempts" type="number" min="1" value="<?php echo esc_attr( (string) $settings['login_max_attempts'] ); ?>" class="small-text"> failed attempts
							<p class="description">Failures allowed from one IP inside the login attempt window.</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="login_window_minutes">Attempt window</label></th>
						<td><input id="login_window_minutes" name="login_window_minutes" type="number" min="1" value="<?php echo esc_attr( (string) $settings['login_window_minutes'] ); ?>" class="small-text"> minutes</td>
					</tr>
					<tr>
						<th scope="row"><label for="login_lockout_minutes">Temporary ban duration</label></th>
						<td><input id="login_lockout_minutes" name="login_lockout_minutes" type="number" min="1" value="<?php echo esc_attr( (string) $settings['login_lockout_minutes'] ); ?>" class="small-text"> minutes</td>
					</tr>
					<tr>
						<th scope="row"><label for="login_lockouts_before_permanent_ban">Permanent ban after temporary bans</label></th>
						<td>
							<input id="login_lockouts_before_permanent_ban" name="login_lockouts_before_permanent_ban" type="number" min="0" value="<?php echo esc_attr( (string) $settings['login_lockouts_before_permanent_ban'] ); ?>" class="small-text"> temporary bans
							<p class="description">Use 0 to disable escalation from repeated temporary bans.</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="login_failed_attempts_before_permanent_ban">Permanent ban after failure streak</label></th>
						<td>
							<input id="login_failed_attempts_before_permanent_ban" name="login_failed_attempts_before_permanent_ban" type="number" min="0" value="<?php echo esc_attr( (string) $settings['login_failed_attempts_before_permanent_ban'] ); ?>" class="small-text"> failed attempts
							<p class="description">Counts consecutive failures from the same IP across time. A successful login resets the streak. Use 0 to disable.</p>
						</td>
					</tr>
				</table>
				<p class="submit">
					<button type="submit" name="vwfw_save_login_policies" class="button button-primary">Save Login Protection Policies</button>
				</p>
			</form>
		</div>
		<?php
	}

	private function handle_form_submission(): bool {
		if ( 'POST' !== $_SERVER['REQUEST_METHOD'] || ! isset( $_POST['vwfw_save_login_policies'] ) ) {
			return false;
		}

		check_admin_referer( 'vwfw_save_login_policies' );
		$this->settings->update( $this->settings->sanitize_login_submission( wp_unslash( $_POST ) ) );
		return true;
	}
}
