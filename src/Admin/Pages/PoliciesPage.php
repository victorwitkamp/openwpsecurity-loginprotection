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
			<h1><?php esc_html_e( 'OpenWPSecurity - Login Protection Policies', 'openwpsecurity-loginprotection' ); ?></h1>
			<p><?php esc_html_e( 'Configure failed-login counting, temporary bans, and permanent-ban escalation.', 'openwpsecurity-loginprotection' ); ?></p>
			<?php $this->render_page_tabs( 'openwpsecurity-loginprotection-policies' ); ?>

			<?php if ( $policies_updated ) : ?>
				<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Login Protection policies saved.', 'openwpsecurity-loginprotection' ); ?></p></div>
			<?php endif; ?>

			<form method="post" class="vwfw-panel">
				<?php wp_nonce_field( 'vwfw_save_login_policies' ); ?>
				<h2><?php esc_html_e( 'Login Enforcement Policy', 'openwpsecurity-loginprotection' ); ?></h2>
				<p class="description"><?php esc_html_e( 'Failed attempts are counted per IP address. Temporary bans and failed-login streaks can independently escalate to a permanent ban.', 'openwpsecurity-loginprotection' ); ?></p>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="login_max_attempts"><?php esc_html_e( 'Attempts before temporary ban', 'openwpsecurity-loginprotection' ); ?></label></th>
						<td>
							<input id="login_max_attempts" name="login_max_attempts" type="number" min="1" value="<?php echo esc_attr( (string) $settings['login_max_attempts'] ); ?>" class="small-text"> <?php esc_html_e( 'failed attempts', 'openwpsecurity-loginprotection' ); ?>
							<p class="description"><?php esc_html_e( 'Failures allowed from one IP inside the login attempt window.', 'openwpsecurity-loginprotection' ); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="login_window_minutes"><?php esc_html_e( 'Attempt window', 'openwpsecurity-loginprotection' ); ?></label></th>
						<td><input id="login_window_minutes" name="login_window_minutes" type="number" min="1" value="<?php echo esc_attr( (string) $settings['login_window_minutes'] ); ?>" class="small-text"> <?php esc_html_e( 'minutes', 'openwpsecurity-loginprotection' ); ?></td>
					</tr>
					<tr>
						<th scope="row"><label for="login_lockout_minutes"><?php esc_html_e( 'Temporary ban duration', 'openwpsecurity-loginprotection' ); ?></label></th>
						<td><input id="login_lockout_minutes" name="login_lockout_minutes" type="number" min="1" value="<?php echo esc_attr( (string) $settings['login_lockout_minutes'] ); ?>" class="small-text"> <?php esc_html_e( 'minutes', 'openwpsecurity-loginprotection' ); ?></td>
					</tr>
					<tr>
						<th scope="row"><label for="login_lockouts_before_permanent_ban"><?php esc_html_e( 'Permanent ban after temporary bans', 'openwpsecurity-loginprotection' ); ?></label></th>
						<td>
							<input id="login_lockouts_before_permanent_ban" name="login_lockouts_before_permanent_ban" type="number" min="0" value="<?php echo esc_attr( (string) $settings['login_lockouts_before_permanent_ban'] ); ?>" class="small-text"> <?php esc_html_e( 'temporary bans', 'openwpsecurity-loginprotection' ); ?>
							<p class="description"><?php esc_html_e( 'Use 0 to disable escalation from repeated temporary bans.', 'openwpsecurity-loginprotection' ); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="login_failed_attempts_before_permanent_ban"><?php esc_html_e( 'Permanent ban after failure streak', 'openwpsecurity-loginprotection' ); ?></label></th>
						<td>
							<input id="login_failed_attempts_before_permanent_ban" name="login_failed_attempts_before_permanent_ban" type="number" min="0" value="<?php echo esc_attr( (string) $settings['login_failed_attempts_before_permanent_ban'] ); ?>" class="small-text"> <?php esc_html_e( 'failed attempts', 'openwpsecurity-loginprotection' ); ?>
							<p class="description"><?php esc_html_e( 'Counts consecutive failures from the same IP across time. A successful login resets the streak. Use 0 to disable.', 'openwpsecurity-loginprotection' ); ?></p>
						</td>
					</tr>
				</table>
				<p class="submit">
					<button type="submit" name="vwfw_save_login_policies" class="button button-primary"><?php esc_html_e( 'Save Login Protection Policies', 'openwpsecurity-loginprotection' ); ?></button>
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
