<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\LoginProtection\Admin\Pages;

use VictorWitkamp\OpenWPSecurity\LoginProtection\Admin\Presentation\CountryDistributionPanel;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Admin\Reporting\EventReportFormatter;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Admin\Reporting\ReportPeriod;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Admin\Requests\LoginActivityFilterInput;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Configuration\Settings;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\LoginLockoutStore;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\Reports\LoginActivityReport;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\Reports\LoginDashboardReport;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class LoginProtectionPage extends AbstractAdminPage {
	private const PER_PAGE = 50;

	private Settings $settings;
	private LoginActivityReport $login_activity_report;
	private LoginDashboardReport $login_dashboard_report;
	private LoginActivityFilterInput $login_activity_filter_input;
	private CountryDistributionPanel $country_distribution_panel;
	private LoginLockoutStore $login_lockout_store;

	public function __construct( Settings $settings, LoginActivityReport $login_activity_report, LoginDashboardReport $login_dashboard_report, LoginActivityFilterInput $login_activity_filter_input, CountryDistributionPanel $country_distribution_panel, LoginLockoutStore $login_lockout_store, ReportPeriod $report_period, EventReportFormatter $event_report_formatter ) {
		parent::__construct( $report_period, $event_report_formatter );
		$this->settings                    = $settings;
		$this->login_activity_report       = $login_activity_report;
		$this->login_dashboard_report      = $login_dashboard_report;
		$this->login_activity_filter_input = $login_activity_filter_input;
		$this->country_distribution_panel  = $country_distribution_panel;
		$this->login_lockout_store         = $login_lockout_store;
	}

	public function render(): void {
		$this->assert_page_access();
		$this->handle_settings_submission();

		$tab = $this->current_login_tab();
		?>
		<div class="wrap vwfw-admin">
			<h1>OpenWPSecurity - Login Protection</h1>
			<p>Failed-password protection for the WordPress login flow, with its own lockouts, permanent-ban escalation, and login-event history.</p>
			<?php $this->render_login_tabs( $tab ); ?>
			<?php $this->render_current_tab( $tab ); ?>
		</div>
		<?php
	}

	private function render_current_tab( string $tab ): void {
		if ( 'activity' === $tab ) {
			$this->render_activity_tab();
			return;
		}

		if ( 'settings' === $tab ) {
			$this->render_settings_tab();
			return;
		}

		$this->render_dashboard_tab();
	}

	private function render_dashboard_tab(): void {
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
		<?php
		$this->render_period_form(
			'openwpsecurity-loginprotection',
			$period,
			true,
			array(
				'tab'            => 'dashboard',
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
		<?php
	}

	private function render_activity_tab(): void {
		$period          = $this->current_period( 'all' );
		$period_seconds  = $this->period_seconds_for( $period );
		$filters         = $this->login_activity_filter_input->read();
		$total_items     = $this->login_activity_report->count( $filters, $period_seconds );
		$paginator       = $this->create_paginator( $total_items, self::PER_PAGE, 'openwpsecurity-loginprotection', $period, array_merge( array( 'tab' => 'activity' ), $this->login_activity_filter_input->query_args( $filters ) ) );
		$rows            = $this->login_activity_report->rows( $filters, $period_seconds, self::PER_PAGE, $paginator->offset() );
		$countries       = $this->login_activity_report->countries( $filters, $period_seconds );
		$country_options = $this->login_activity_report->country_options( $this->login_activity_filter_input->country_option_filters( $filters ), $period_seconds );
		?>
		<?php $this->render_period_form( 'openwpsecurity-loginprotection', $period, true, array_merge( array( 'tab' => 'activity' ), $this->login_activity_filter_input->query_args( $filters ) ) ); ?>
		<?php $this->render_activity_filters_form( $period, $filters, $country_options ); ?>
		<?php $this->country_distribution_panel->render( $countries, 'Login Events by Country', 'Events' ); ?>

		<div class="vwfw-panel vwfw-record-panel">
			<?php $this->render_record_header( 'Login Activity', 'This view includes successful logins, failed logins, blocked logins, lockouts, and login-triggered permanent bans.', $total_items ); ?>
			<?php echo wp_kses_post( $paginator->render() ); ?>
			<div class="vwfw-record-table-wrap">
				<table class="widefat striped fixed">
					<thead>
						<tr>
							<th>Time</th>
							<th>Type</th>
							<th>IP</th>
							<th>Country</th>
							<th>Username</th>
							<th>Password</th>
							<th>Lockout Expires</th>
							<th>Request URI</th>
						</tr>
					</thead>
					<tbody>
						<?php if ( empty( $rows ) ) : ?>
							<tr>
								<td colspan="8">No login events found for this period.</td>
							</tr>
						<?php else : ?>
							<?php foreach ( $rows as $row ) : ?>
								<tr>
									<td><?php echo esc_html( $this->event_report_formatter->admin_datetime( (string) $row['created_at'] ) ); ?></td>
									<td><?php echo esc_html( $this->event_report_formatter->event_type_label( (string) $row['event_type'] ) ); ?></td>
									<td><?php echo esc_html( (string) $row['ip_address'] ); ?></td>
									<td><?php echo esc_html( trim( (string) $row['country_code'] . ' ' . (string) $row['country_name'] ) ); ?></td>
									<td><?php echo esc_html( (string) $row['username'] ); ?></td>
									<td><?php echo esc_html( (string) ( '' !== (string) $row['password_value'] ? $row['password_value'] : $row['password_mask'] ) ); ?></td>
									<td><?php echo esc_html( $row['lockout_expires_at'] ? $this->event_report_formatter->admin_datetime( (string) $row['lockout_expires_at'] ) : '' ); ?></td>
									<td class="vwfw-break"><?php echo esc_html( (string) $row['request_uri'] ); ?></td>
								</tr>
							<?php endforeach; ?>
						<?php endif; ?>
					</tbody>
				</table>
			</div>
			<?php echo wp_kses_post( $paginator->render() ); ?>
		</div>
		<?php
	}

	private function render_settings_tab(): void {
		$settings = $this->settings->get();
		?>
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
		<?php
	}

	private function render_login_tabs( string $active_tab ): void {
		$tabs = array(
			'dashboard' => 'Dashboard',
			'activity'  => 'Activity',
			'settings'  => 'Settings',
		);
		?>
		<div class="nav-tab-wrapper vwfw-subtabs">
			<?php foreach ( $tabs as $tab => $label ) : ?>
				<a class="nav-tab <?php echo esc_attr( $active_tab === $tab ? 'nav-tab-active' : '' ); ?>" href="<?php echo esc_url( $this->login_tab_url( $tab ) ); ?>">
					<?php echo esc_html( $label ); ?>
				</a>
			<?php endforeach; ?>
		</div>
		<?php
	}

	private function render_country_metric_form( string $period, string $country_metric ): void {
		?>
		<form class="vwfw-period-form" method="get">
			<input type="hidden" name="page" value="openwpsecurity-loginprotection">
			<input type="hidden" name="tab" value="dashboard">
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

	private function render_activity_filters_form( string $period, array $filters, array $country_options ): void {
		?>
		<form class="vwfw-record-filters vwfw-panel" method="get">
			<input type="hidden" name="page" value="openwpsecurity-loginprotection">
			<input type="hidden" name="tab" value="activity">
			<input type="hidden" name="period" value="<?php echo esc_attr( $period ); ?>">
			<div class="vwfw-filter-grid">
				<div>
					<label for="vwfw-login-event-type"><strong>Event Type</strong></label>
					<select id="vwfw-login-event-type" name="event_type">
						<?php foreach ( $this->event_report_formatter->event_type_options( $this->login_activity_filter_input->event_types() ) as $value => $label ) : ?>
							<option value="<?php echo esc_attr( $value ); ?>" <?php selected( $filters['event_type'], $value ); ?>>
								<?php echo esc_html( $label ); ?>
							</option>
						<?php endforeach; ?>
					</select>
				</div>
				<div>
					<label for="vwfw-login-country"><strong>Country</strong></label>
					<select id="vwfw-login-country" name="country_code">
						<option value="">All Countries</option>
						<?php foreach ( $country_options as $country ) : ?>
							<option value="<?php echo esc_attr( (string) $country['code'] ); ?>" <?php selected( $filters['country_code'], (string) $country['code'] ); ?>>
								<?php echo esc_html( (string) $country['label'] ); ?>
							</option>
						<?php endforeach; ?>
					</select>
				</div>
				<div>
					<label for="vwfw-login-ip"><strong>IP Contains</strong></label>
					<input id="vwfw-login-ip" type="text" name="ip_address" value="<?php echo esc_attr( $filters['ip_address'] ); ?>">
				</div>
				<div>
					<label for="vwfw-login-username"><strong>Username Contains</strong></label>
					<input id="vwfw-login-username" type="text" name="username" value="<?php echo esc_attr( $filters['username'] ); ?>">
				</div>
				<div>
					<label for="vwfw-login-uri"><strong>URI Contains</strong></label>
					<input id="vwfw-login-uri" type="text" name="request_uri" value="<?php echo esc_attr( $filters['request_uri'] ); ?>">
				</div>
				<div class="vwfw-filter-actions">
					<button type="submit" class="button button-primary">Apply Filters</button>
					<a class="button" href="<?php echo esc_url( admin_url( 'admin.php?page=openwpsecurity-loginprotection&tab=activity&period=' . $period ) ); ?>">Reset</a>
				</div>
			</div>
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
				<table class="widefat striped fixed">
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
				<table class="widefat striped fixed">
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
				<table class="widefat striped fixed">
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
				<table class="widefat striped fixed">
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

	private function handle_settings_submission(): void {
		if ( 'POST' !== $_SERVER['REQUEST_METHOD'] || ! isset( $_POST['vwfw_save_login_settings'] ) ) {
			return;
		}

		check_admin_referer( 'vwfw_save_login_settings' );
		$this->settings->update( $this->settings->sanitize_submission( wp_unslash( $_POST ) ) );
		wp_safe_redirect(
			add_query_arg(
				array(
					'page'             => 'openwpsecurity-loginprotection',
					'tab'              => 'settings',
					'settings-updated' => '1',
				),
				admin_url( 'admin.php' )
			)
		);
		exit;
	}

	private function current_login_tab(): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only admin tab parameter.
		$tab = isset( $_GET['tab'] ) ? sanitize_key( (string) wp_unslash( $_GET['tab'] ) ) : 'dashboard';

		return in_array( $tab, array( 'dashboard', 'activity', 'settings' ), true ) ? $tab : 'dashboard';
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

	private function login_tab_url( string $tab ): string {
		return admin_url( 'admin.php?page=openwpsecurity-loginprotection&tab=' . $tab );
	}
}
