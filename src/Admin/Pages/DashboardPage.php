<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\LoginProtection\Admin\Pages;

use VictorWitkamp\OpenWPSecurity\Core\Admin\Pages\AbstractAdminPage;
use VictorWitkamp\OpenWPSecurity\Core\Admin\Presentation\CountryDistributionPanel;
use VictorWitkamp\OpenWPSecurity\Core\Admin\Reporting\EventReportFormatter;
use VictorWitkamp\OpenWPSecurity\Core\Admin\Reporting\ReportPeriod;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Admin\Navigation\AdminMenu;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Configuration\Settings;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\LoginLockoutStore;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\Reports\LoginDashboardReport;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class DashboardPage extends AbstractAdminPage {
	private Settings $settings;
	private LoginDashboardReport $login_dashboard_report;
	private CountryDistributionPanel $country_distribution_panel;
	private LoginLockoutStore $login_lockout_store;

	public function __construct( Settings $settings, LoginDashboardReport $login_dashboard_report, CountryDistributionPanel $country_distribution_panel, LoginLockoutStore $login_lockout_store, ReportPeriod $report_period, EventReportFormatter $event_report_formatter ) {
		parent::__construct( $report_period, $event_report_formatter, AdminMenu::page_tabs() );
		$this->settings                   = $settings;
		$this->login_dashboard_report     = $login_dashboard_report;
		$this->country_distribution_panel = $country_distribution_panel;
		$this->login_lockout_store        = $login_lockout_store;
	}

	public function render(): void {
		$this->assert_page_access();

		$period         = $this->current_period( '24h' );
		$period_seconds = $this->period_seconds_for( $period );
		$country_metric = $this->current_country_metric();
		$data           = array(
			'summary'             => $this->login_dashboard_report->summary( $period_seconds ),
			'countries'           => $this->login_dashboard_report->countries_for_metric( $country_metric, $period_seconds ),
			'recent_successful'   => $this->login_dashboard_report->recent_successful_logins( $period_seconds ),
			'recent_failed'       => $this->login_dashboard_report->recent_failed_logins( $period_seconds ),
			'recent_blocked'      => $this->login_dashboard_report->recent_blocked_logins( $period_seconds ),
			'active_lockouts'     => $this->login_lockout_store->get_active_lockouts(),
			'recent_bans'         => $this->login_dashboard_report->recent_permanent_bans( $period_seconds ),
			'current_settings'    => $this->settings->get(),
			'country_metric_name' => $this->country_metric_label( $country_metric ),
		);
		?>
		<div class="wrap vwfw-admin">
			<h1>OpenWPSecurity - Login Protection</h1>
			<p>Failed-password protection for the WordPress login flow, with lockouts, permanent-ban escalation, and login-event history.</p>

			<?php $this->render_page_tabs( 'openwpsecurity-loginprotection' ); ?>
			<?php
			$this->render_period_form(
				'openwpsecurity-loginprotection',
				$period,
				true,
				array(
					'country_metric' => $country_metric,
				)
			);
			?>
			<?php $this->render_country_metric_form( $period, $country_metric ); ?>

			<div class="vwfw-cards">
				<?php $this->render_summary_card( 'Total Attempts', (int) $data['summary']['total_attempts'] ); ?>
				<?php $this->render_summary_card( 'Successful Logins', (int) $data['summary']['successful_attempts'] ); ?>
				<?php $this->render_summary_card( 'Failed Logins', (int) $data['summary']['failed_attempts'] ); ?>
				<?php $this->render_summary_card( 'Blocked Logins', (int) $data['summary']['blocked_attempts'] ); ?>
				<?php $this->render_summary_card( 'Lockouts', (int) $data['summary']['lockouts'] ); ?>
				<?php $this->render_summary_card( 'Active Lockouts', count( $data['active_lockouts'] ) ); ?>
				<?php $this->render_summary_card( 'Permanent Bans', (int) $data['summary']['permanent_bans'] ); ?>
				<?php $this->render_summary_card( 'Unique Login IPs', (int) $data['summary']['unique_ips'] ); ?>
			</div>

			<?php $this->country_distribution_panel->render( $data['countries'], 'Login Events by Country: ' . $data['country_metric_name'], 'Events' ); ?>

			<div class="vwfw-grid vwfw-grid--three">
				<?php $this->render_recent_successful_logins_panel( $data['recent_successful'] ); ?>
				<?php $this->render_recent_failed_logins_panel( $data['recent_failed'] ); ?>
				<?php $this->render_recent_blocked_logins_panel( $data['recent_blocked'] ); ?>
			</div>

			<div class="vwfw-grid vwfw-grid--two">
				<?php $this->render_active_lockouts_panel( $data['active_lockouts'], $data['current_settings'] ); ?>
				<?php $this->render_recent_bans_panel( $data['recent_bans'], (int) $data['summary']['permanent_bans'] ); ?>
			</div>
		</div>
		<?php
	}

	private function render_country_metric_form( string $period, string $country_metric ): void {
		?>
		<form class="vwfw-period-form" method="get">
			<input type="hidden" name="page" value="openwpsecurity-loginprotection">
			<input type="hidden" name="period" value="<?php echo esc_attr( $period ); ?>">
			<label for="vwfw-login-country-metric"><strong>Country Chart</strong></label>
			<select id="vwfw-login-country-metric" name="country_metric">
				<option value="total_attempts" <?php selected( $country_metric, 'total_attempts' ); ?>>Total Login Attempts</option>
				<option value="failed_attempts" <?php selected( $country_metric, 'failed_attempts' ); ?>>Failed Attempts</option>
				<option value="successful_attempts" <?php selected( $country_metric, 'successful_attempts' ); ?>>Successful Attempts</option>
			</select>
			<button type="submit" class="button">Apply</button>
		</form>
		<?php
	}

	private function render_recent_successful_logins_panel( array $rows ): void {
		$this->render_login_event_panel(
			'Recent Successful Logins',
			'Most recent successful WordPress logins.',
			$rows,
			'No successful logins found for this period.'
		);
	}

	private function render_recent_failed_logins_panel( array $rows ): void {
		$this->render_login_event_panel(
			'Recent Failed Logins',
			'Most recent failed WordPress logins.',
			$rows,
			'No failed logins found for this period.'
		);
	}

	private function render_recent_blocked_logins_panel( array $rows ): void {
		?>
		<div class="vwfw-panel vwfw-record-panel">
			<?php $this->render_record_header( 'Recent Blocked Logins', 'Most recent login submissions rejected because a lockout was already active.', count( $rows ), false ); ?>
			<div class="vwfw-record-table-wrap">
				<table class="widefat striped fixed vwfw-compact-table">
					<thead>
						<tr>
							<th>Time</th>
							<th>IP</th>
							<th>Country</th>
							<th>Username</th>
							<th>Lockout Expires</th>
						</tr>
					</thead>
					<tbody>
						<?php if ( empty( $rows ) ) : ?>
							<tr><td colspan="5">No blocked logins found for this period.</td></tr>
						<?php else : ?>
							<?php foreach ( $rows as $row ) : ?>
								<tr>
									<td><?php echo esc_html( $this->event_report_formatter->admin_datetime( (string) $row['created_at'] ) ); ?></td>
									<td><?php echo esc_html( (string) $row['ip_address'] ); ?></td>
									<td><?php echo esc_html( trim( (string) $row['country_code'] . ' ' . (string) $row['country_name'] ) ); ?></td>
									<td><?php echo esc_html( (string) $row['username'] ); ?></td>
									<td><?php echo esc_html( $row['lockout_expires_at'] ? $this->event_report_formatter->admin_datetime( (string) $row['lockout_expires_at'] ) : '' ); ?></td>
								</tr>
							<?php endforeach; ?>
						<?php endif; ?>
					</tbody>
				</table>
			</div>
		</div>
		<?php
	}

	private function render_login_event_panel( string $title, string $description, array $rows, string $empty_message ): void {
		?>
		<div class="vwfw-panel vwfw-record-panel">
			<?php $this->render_record_header( $title, $description, count( $rows ), false ); ?>
			<div class="vwfw-record-table-wrap">
				<table class="widefat striped fixed vwfw-compact-table">
					<thead>
						<tr>
							<th>Time</th>
							<th>Type</th>
							<th>IP</th>
							<th>Country</th>
							<th>Username</th>
						</tr>
					</thead>
					<tbody>
						<?php if ( empty( $rows ) ) : ?>
							<tr><td colspan="5"><?php echo esc_html( $empty_message ); ?></td></tr>
						<?php else : ?>
							<?php foreach ( $rows as $row ) : ?>
								<tr>
									<td><?php echo esc_html( $this->event_report_formatter->admin_datetime( (string) $row['created_at'] ) ); ?></td>
									<td><?php echo esc_html( $this->event_report_formatter->event_type_label( (string) $row['event_type'] ) ); ?></td>
									<td><?php echo esc_html( (string) $row['ip_address'] ); ?></td>
									<td><?php echo esc_html( trim( (string) $row['country_code'] . ' ' . (string) $row['country_name'] ) ); ?></td>
									<td><?php echo esc_html( (string) $row['username'] ); ?></td>
								</tr>
							<?php endforeach; ?>
						<?php endif; ?>
					</tbody>
				</table>
			</div>
		</div>
		<?php
	}

	private function render_active_lockouts_panel( array $active_lockouts, array $settings ): void {
		?>
		<div class="vwfw-panel vwfw-record-panel">
			<?php $this->render_record_header( 'Active Lockouts', 'Temporary lockouts that are active right now inside Login Protection.', count( $active_lockouts ), false ); ?>
			<div class="vwfw-record-table-wrap">
				<table class="widefat striped fixed vwfw-compact-table">
					<thead>
						<tr>
							<th>IP</th>
							<th>Expires</th>
							<th>Lockouts</th>
							<th>Lockout Ban Threshold</th>
						</tr>
					</thead>
					<tbody>
						<?php if ( empty( $active_lockouts ) ) : ?>
							<tr><td colspan="4">No login lockouts are active right now.</td></tr>
						<?php else : ?>
							<?php foreach ( $active_lockouts as $ip => $expires ) : ?>
								<tr>
									<td><?php echo esc_html( (string) $ip ); ?></td>
									<td><?php echo esc_html( $this->event_report_formatter->admin_datetime( gmdate( 'Y-m-d H:i:s', (int) $expires ) ) ); ?></td>
									<td><?php echo esc_html( (string) $this->login_lockout_store->lockout_count( (string) $ip ) ); ?></td>
									<td><?php echo esc_html( (string) $settings['login_lockouts_before_permanent_ban'] ); ?></td>
								</tr>
							<?php endforeach; ?>
						<?php endif; ?>
					</tbody>
				</table>
			</div>
		</div>
		<?php
	}

	private function render_recent_bans_panel( array $rows, int $total_items ): void {
		?>
		<div class="vwfw-panel vwfw-record-panel">
			<?php $this->render_record_header( 'Recent Permanent Bans', 'Most recently created permanent bans where the source was Login Protection.', $total_items, false ); ?>
			<div class="vwfw-record-table-wrap">
				<table class="widefat striped fixed vwfw-analysis-table">
					<thead>
						<tr>
							<th>Time</th>
							<th>IP</th>
							<th>Country</th>
							<th>Source</th>
							<th>Reason</th>
						</tr>
					</thead>
					<tbody>
						<?php if ( empty( $rows ) ) : ?>
							<tr><td colspan="5">No login-triggered permanent bans found for this period.</td></tr>
						<?php else : ?>
							<?php foreach ( $rows as $row ) : ?>
								<?php $details = $this->event_report_formatter->details_from_json( (string) $row['details'] ); ?>
								<tr>
									<td><?php echo esc_html( $this->event_report_formatter->admin_datetime( (string) $row['created_at'] ) ); ?></td>
									<td><?php echo esc_html( (string) $row['ip_address'] ); ?></td>
									<td><?php echo esc_html( trim( (string) $row['country_code'] . ' ' . (string) $row['country_name'] ) ); ?></td>
									<td><?php echo esc_html( $this->event_report_formatter->ban_source_label( (string) ( $details['source'] ?? '' ) ) ); ?></td>
									<td class="vwfw-break"><?php echo esc_html( (string) ( $details['reason'] ?? '' ) ); ?></td>
								</tr>
							<?php endforeach; ?>
						<?php endif; ?>
					</tbody>
				</table>
			</div>
		</div>
		<?php
	}

	private function current_country_metric(): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only admin filter parameter.
		$metric = isset( $_GET['country_metric'] ) ? sanitize_key( (string) wp_unslash( $_GET['country_metric'] ) ) : 'total_attempts';

		return in_array( $metric, array( 'total_attempts', 'failed_attempts', 'successful_attempts' ), true ) ? $metric : 'total_attempts';
	}

	private function country_metric_label( string $country_metric ): string {
		if ( 'failed_attempts' === $country_metric ) {
			return 'Failed Attempts';
		}

		if ( 'successful_attempts' === $country_metric ) {
			return 'Successful Attempts';
		}

		return 'Total Login Attempts';
	}
}
