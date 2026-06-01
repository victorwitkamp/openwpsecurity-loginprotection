<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\LoginProtection\Admin\Pages;

use VictorWitkamp\OpenWPSecurity\Core\Admin\Pages\AbstractAdminPage;
use VictorWitkamp\OpenWPSecurity\Core\Admin\Reporting\EventReportFormatter;
use VictorWitkamp\OpenWPSecurity\Core\Admin\Reporting\ReportPeriod;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Admin\Navigation\AdminMenu;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\Reports\LoginCredentialCorrelationReport;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class AnalysisPage extends AbstractAdminPage {
	private LoginCredentialCorrelationReport $login_credential_correlation_report;

	public function __construct( LoginCredentialCorrelationReport $login_credential_correlation_report, ReportPeriod $report_period, EventReportFormatter $event_report_formatter ) {
		parent::__construct( $report_period, $event_report_formatter, AdminMenu::page_tabs() );
		$this->login_credential_correlation_report = $login_credential_correlation_report;
	}

	public function render(): void {
		$this->assert_page_access();

		$period         = $this->current_period( '30d' );
		$period_seconds = $this->period_seconds_for( $period );
		$summary        = $this->login_credential_correlation_report->summary( $period_seconds );
		?>
		<div class="wrap vwfw-admin">
			<h1>OpenWPSecurity - Login Protection Analysis</h1>
			<?php $this->render_page_tabs( 'openwpsecurity-loginprotection-analysis' ); ?>
			<?php $this->render_period_form( 'openwpsecurity-loginprotection-analysis', $period, true ); ?>

			<div class="vwfw-cards">
				<?php $this->render_summary_card( 'Attack Attempts', (int) $summary['correlated_attempts'] ); ?>
				<?php $this->render_summary_card( 'Attack IPs', (int) $summary['correlated_ips'] ); ?>
				<?php $this->render_summary_card( 'Password Fingerprints', (int) $summary['password_fingerprints'] ); ?>
				<?php $this->render_summary_card( 'Repeated Fingerprints', (int) $summary['repeated_fingerprints'] ); ?>
				<?php $this->render_summary_card( 'Fingerprints on 5+ IPs', (int) $summary['fingerprints_seen_on_5plus_ips'] ); ?>
				<?php $this->render_summary_card( 'High-Variety IPs', (int) $summary['high_variety_ips'] ); ?>
				<?php $this->render_summary_card( '/24 Campaigns', (int) $summary['network_campaigns'] ); ?>
				<?php $this->render_summary_card( 'UA Campaigns', (int) $summary['user_agent_campaigns'] ); ?>
			</div>

			<div class="vwfw-grid vwfw-grid--two">
				<?php $this->render_password_strategy_panel( $this->login_credential_correlation_report->password_strategy_counts( $period_seconds ) ); ?>
				<?php $this->render_password_feature_signature_panel( $this->login_credential_correlation_report->password_feature_signatures( $period_seconds ) ); ?>
			</div>

			<div class="vwfw-grid vwfw-grid--two">
				<?php $this->render_common_passwords_panel( $this->login_credential_correlation_report->common_passwords( $period_seconds ) ); ?>
				<?php $this->render_reused_password_fingerprint_panel( $this->login_credential_correlation_report->reused_password_fingerprints( $period_seconds ) ); ?>
			</div>

			<div class="vwfw-grid vwfw-grid--two">
				<?php $this->render_high_variety_ip_panel( $this->login_credential_correlation_report->high_variety_ips( $period_seconds ) ); ?>
				<?php $this->render_ipv4_network_campaign_panel( $this->login_credential_correlation_report->ipv4_network_campaigns( $period_seconds ) ); ?>
			</div>

			<?php $this->render_user_agent_campaign_panel( $this->login_credential_correlation_report->user_agent_campaigns( $period_seconds ) ); ?>
		</div>
		<?php
	}

	private function render_password_strategy_panel( array $rows ): void {
		?>
		<div class="vwfw-panel vwfw-record-panel">
			<?php $this->render_record_header( 'Password Strategy Signals', 'Derived features from submitted failed-login passwords. The password tables below display the actual stored values.', count( $rows ), false ); ?>
			<div class="vwfw-record-table-wrap">
				<table class="widefat striped fixed vwfw-compact-table">
					<thead>
						<tr>
							<th>Signal</th>
							<th>Attempts</th>
							<th>IPs</th>
							<th>Usernames</th>
						</tr>
					</thead>
					<tbody>
						<?php if ( empty( $rows ) ) : ?>
							<tr><td colspan="4">No password strategy signals found for this period.</td></tr>
						<?php else : ?>
							<?php foreach ( $rows as $row ) : ?>
								<tr>
									<td><?php echo esc_html( (string) $row['label'] ); ?></td>
									<td><?php echo esc_html( number_format_i18n( (int) $row['attempts'] ) ); ?></td>
									<td><?php echo esc_html( number_format_i18n( (int) $row['ips'] ) ); ?></td>
									<td><?php echo esc_html( number_format_i18n( (int) $row['usernames'] ) ); ?></td>
								</tr>
							<?php endforeach; ?>
						<?php endif; ?>
					</tbody>
				</table>
			</div>
		</div>
		<?php
	}

	private function render_password_feature_signature_panel( array $rows ): void {
		?>
		<div class="vwfw-panel vwfw-record-panel">
			<?php $this->render_record_header( 'Password Feature Signatures', 'Password attempts grouped by length, character classes, trailing digits, year use, and username inclusion.', count( $rows ), false ); ?>
			<div class="vwfw-record-table-wrap">
				<table class="widefat striped fixed vwfw-analysis-table">
					<thead>
						<tr>
							<th>Feature Signature</th>
							<th>Attempts</th>
							<th>IPs</th>
							<th>Usernames</th>
							<th>Fingerprints</th>
						</tr>
					</thead>
					<tbody>
						<?php if ( empty( $rows ) ) : ?>
							<tr><td colspan="5">No password feature signatures found for this period.</td></tr>
						<?php else : ?>
							<?php foreach ( $rows as $row ) : ?>
								<tr>
									<td class="vwfw-break"><?php echo esc_html( (string) $row['feature'] ); ?></td>
									<td><?php echo esc_html( number_format_i18n( (int) $row['attempts'] ) ); ?></td>
									<td><?php echo esc_html( number_format_i18n( (int) $row['ips'] ) ); ?></td>
									<td><?php echo esc_html( number_format_i18n( (int) $row['usernames'] ) ); ?></td>
									<td><?php echo esc_html( number_format_i18n( (int) $row['password_fingerprints'] ) ); ?></td>
								</tr>
							<?php endforeach; ?>
						<?php endif; ?>
					</tbody>
				</table>
			</div>
		</div>
		<?php
	}

	private function render_reused_password_fingerprint_panel( array $rows ): void {
		?>
		<div class="vwfw-panel vwfw-record-panel">
			<?php $this->render_record_header( 'Reused Passwords', 'Actual failed-login passwords reused across IP addresses, usernames, or countries.', count( $rows ), false ); ?>
			<div class="vwfw-record-table-wrap">
				<table class="widefat striped fixed vwfw-analysis-table">
					<thead>
						<tr>
							<th>Password</th>
							<th>Attempts</th>
							<th>IPs</th>
							<th>Usernames</th>
							<th>Countries</th>
							<th>First Seen</th>
							<th>Last Seen</th>
						</tr>
					</thead>
					<tbody>
						<?php if ( empty( $rows ) ) : ?>
							<tr><td colspan="7">No reused password fingerprints found for this period.</td></tr>
						<?php else : ?>
							<?php foreach ( $rows as $row ) : ?>
								<tr>
									<td class="vwfw-sensitive"><?php echo esc_html( (string) $row['password_value'] ); ?></td>
									<td><?php echo esc_html( number_format_i18n( (int) $row['attempts'] ) ); ?></td>
									<td><?php echo esc_html( number_format_i18n( (int) $row['ips'] ) ); ?></td>
									<td><?php echo esc_html( number_format_i18n( (int) $row['usernames'] ) ); ?></td>
									<td><?php echo esc_html( number_format_i18n( (int) $row['countries'] ) ); ?></td>
									<td><?php echo esc_html( $this->event_report_formatter->admin_datetime( (string) $row['first_seen'] ) ); ?></td>
									<td><?php echo esc_html( $this->event_report_formatter->admin_datetime( (string) $row['last_seen'] ) ); ?></td>
								</tr>
							<?php endforeach; ?>
						<?php endif; ?>
					</tbody>
				</table>
			</div>
		</div>
		<?php
	}

	private function render_common_passwords_panel( array $rows ): void {
		?>
		<div class="vwfw-panel vwfw-record-panel">
			<?php $this->render_record_header( 'Most Tried Passwords', 'Actual failed-login passwords ranked by total attempts in the selected period.', count( $rows ), false ); ?>
			<div class="vwfw-record-table-wrap">
				<table class="widefat striped fixed vwfw-analysis-table">
					<thead>
						<tr>
							<th>Password</th>
							<th>Attempts</th>
							<th>IPs</th>
							<th>Usernames</th>
							<th>UA Fingerprints</th>
							<th>First Seen</th>
							<th>Last Seen</th>
						</tr>
					</thead>
					<tbody>
						<?php if ( empty( $rows ) ) : ?>
							<tr><td colspan="7">No failed-login passwords found for this period.</td></tr>
						<?php else : ?>
							<?php foreach ( $rows as $row ) : ?>
								<tr>
									<td class="vwfw-sensitive"><?php echo esc_html( (string) $row['password_value'] ); ?></td>
									<td><?php echo esc_html( number_format_i18n( (int) $row['attempts'] ) ); ?></td>
									<td><?php echo esc_html( number_format_i18n( (int) $row['ips'] ) ); ?></td>
									<td><?php echo esc_html( number_format_i18n( (int) $row['usernames'] ) ); ?></td>
									<td><?php echo esc_html( number_format_i18n( (int) $row['user_agent_fingerprints'] ) ); ?></td>
									<td><?php echo esc_html( $this->event_report_formatter->admin_datetime( (string) $row['first_seen'] ) ); ?></td>
									<td><?php echo esc_html( $this->event_report_formatter->admin_datetime( (string) $row['last_seen'] ) ); ?></td>
								</tr>
							<?php endforeach; ?>
						<?php endif; ?>
					</tbody>
				</table>
			</div>
		</div>
		<?php
	}

	private function render_high_variety_ip_panel( array $rows ): void {
		?>
		<div class="vwfw-panel vwfw-record-panel">
			<?php $this->render_record_header( 'IPs Trying Many Passwords', 'Source IPs with many distinct password fingerprints, which is a stronger credential-stuffing signal than exact password reuse alone.', count( $rows ), false ); ?>
			<div class="vwfw-record-table-wrap">
				<table class="widefat striped fixed vwfw-analysis-table">
					<thead>
						<tr>
							<th>IP</th>
							<th>Country</th>
							<th>Attempts</th>
							<th>Fingerprints</th>
							<th>Lengths</th>
							<th>Usernames</th>
							<th>User Agents</th>
							<th>Blocked</th>
							<th>Lockouts</th>
						</tr>
					</thead>
					<tbody>
						<?php if ( empty( $rows ) ) : ?>
							<tr><td colspan="9">No high-variety IPs found for this period.</td></tr>
						<?php else : ?>
							<?php foreach ( $rows as $row ) : ?>
								<tr>
									<td><?php echo esc_html( (string) $row['ip_address'] ); ?></td>
									<td><?php echo esc_html( trim( (string) $row['country_code'] . ' ' . (string) $row['country_name'] ) ); ?></td>
									<td><?php echo esc_html( number_format_i18n( (int) $row['attempts'] ) ); ?></td>
									<td><?php echo esc_html( number_format_i18n( (int) $row['password_fingerprints'] ) ); ?></td>
									<td><?php echo esc_html( number_format_i18n( (int) $row['password_lengths'] ) ); ?></td>
									<td><?php echo esc_html( number_format_i18n( (int) $row['usernames'] ) ); ?></td>
									<td><?php echo esc_html( number_format_i18n( (int) $row['user_agents'] ) ); ?></td>
									<td><?php echo esc_html( number_format_i18n( (int) $row['blocked'] ) ); ?></td>
									<td><?php echo esc_html( number_format_i18n( (int) $row['lockouts'] ) ); ?></td>
								</tr>
							<?php endforeach; ?>
						<?php endif; ?>
					</tbody>
				</table>
			</div>
		</div>
		<?php
	}

	private function render_ipv4_network_campaign_panel( array $rows ): void {
		?>
		<div class="vwfw-panel vwfw-record-panel">
			<?php $this->render_record_header( 'IPv4 /24 Campaigns', 'IPv4 ranges where multiple source IPs attempted login credentials in the selected period.', count( $rows ), false ); ?>
			<div class="vwfw-record-table-wrap">
				<table class="widefat striped fixed vwfw-analysis-table">
					<thead>
						<tr>
							<th>Network</th>
							<th>Attempts</th>
							<th>IPs</th>
							<th>Fingerprints</th>
							<th>Usernames</th>
							<th>Countries</th>
							<th>First Seen</th>
							<th>Last Seen</th>
						</tr>
					</thead>
					<tbody>
						<?php if ( empty( $rows ) ) : ?>
							<tr><td colspan="8">No IPv4 /24 campaigns found for this period.</td></tr>
						<?php else : ?>
							<?php foreach ( $rows as $row ) : ?>
								<tr>
									<td><?php echo esc_html( (string) $row['network'] ); ?></td>
									<td><?php echo esc_html( number_format_i18n( (int) $row['attempts'] ) ); ?></td>
									<td><?php echo esc_html( number_format_i18n( (int) $row['ips'] ) ); ?></td>
									<td><?php echo esc_html( number_format_i18n( (int) $row['password_fingerprints'] ) ); ?></td>
									<td><?php echo esc_html( number_format_i18n( (int) $row['usernames'] ) ); ?></td>
									<td><?php echo esc_html( number_format_i18n( (int) $row['countries'] ) ); ?></td>
									<td><?php echo esc_html( $this->event_report_formatter->admin_datetime( (string) $row['first_seen'] ) ); ?></td>
									<td><?php echo esc_html( $this->event_report_formatter->admin_datetime( (string) $row['last_seen'] ) ); ?></td>
								</tr>
							<?php endforeach; ?>
						<?php endif; ?>
					</tbody>
				</table>
			</div>
		</div>
		<?php
	}

	private function render_user_agent_campaign_panel( array $rows ): void {
		?>
		<div class="vwfw-panel vwfw-record-panel">
			<?php $this->render_record_header( 'User-Agent Campaigns', 'Shared user-agent fingerprints across multiple IP addresses, with browser, platform, device, and raw user-agent details.', count( $rows ), false ); ?>
			<div class="vwfw-record-table-wrap">
				<table class="widefat striped fixed vwfw-user-agent-table">
					<thead>
						<tr>
							<th>User-Agent</th>
							<th>Attempts</th>
							<th>IPs</th>
							<th>Passwords</th>
							<th>Usernames</th>
							<th>First Seen</th>
							<th>Last Seen</th>
						</tr>
					</thead>
					<tbody>
						<?php if ( empty( $rows ) ) : ?>
							<tr><td colspan="7">No user-agent campaigns found for this period.</td></tr>
						<?php else : ?>
							<?php foreach ( $rows as $row ) : ?>
								<tr>
									<td class="vwfw-user-agent-cell">
										<strong><?php echo esc_html( (string) $row['user_agent_fingerprint'] ); ?></strong>
										<span><?php echo esc_html( (string) $row['user_agent_summary'] ); ?></span>
										<code><?php echo esc_html( (string) $row['user_agent'] ); ?></code>
									</td>
									<td><?php echo esc_html( number_format_i18n( (int) $row['attempts'] ) ); ?></td>
									<td><?php echo esc_html( number_format_i18n( (int) $row['ips'] ) ); ?></td>
									<td><?php echo esc_html( number_format_i18n( (int) $row['passwords'] ) ); ?></td>
									<td><?php echo esc_html( number_format_i18n( (int) $row['usernames'] ) ); ?></td>
									<td><?php echo esc_html( $this->event_report_formatter->admin_datetime( (string) $row['first_seen'] ) ); ?></td>
									<td><?php echo esc_html( $this->event_report_formatter->admin_datetime( (string) $row['last_seen'] ) ); ?></td>
								</tr>
							<?php endforeach; ?>
						<?php endif; ?>
					</tbody>
				</table>
			</div>
		</div>
		<?php
	}
}
