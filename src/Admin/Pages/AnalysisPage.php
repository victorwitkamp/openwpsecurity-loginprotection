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
			<p>Identify coordinated credential attacks across source IPs, usernames, passwords, networks, and user agents.</p>
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

			<?php $this->render_key_findings_panel( $this->login_credential_correlation_report->key_findings( $period_seconds ) ); ?>

			<div class="vwfw-grid">
				<?php $this->render_password_characteristics_panel( $this->login_credential_correlation_report->password_characteristics( $period_seconds ) ); ?>
			</div>

			<div class="vwfw-grid vwfw-grid--single">
				<?php $this->render_targeted_usernames_panel( $this->login_credential_correlation_report->targeted_usernames( $period_seconds ) ); ?>
				<?php $this->render_important_passwords_panel( $this->login_credential_correlation_report->important_passwords( $period_seconds, 8 ) ); ?>
			</div>

			<div class="vwfw-grid vwfw-grid--single">
				<?php $this->render_high_variety_ip_panel( $this->login_credential_correlation_report->high_variety_ips( $period_seconds ) ); ?>
				<?php $this->render_ipv4_network_campaign_panel( $this->login_credential_correlation_report->ipv4_network_campaigns( $period_seconds ) ); ?>
			</div>

			<?php $this->render_user_agent_campaign_panel( $this->login_credential_correlation_report->user_agent_campaigns( $period_seconds, 6 ) ); ?>
		</div>
		<?php
	}

	private function render_key_findings_panel( array $rows ): void {
		if ( empty( $rows ) ) {
			return;
		}
		?>
		<div class="vwfw-analysis-findings">
			<?php foreach ( $rows as $row ) : ?>
				<article class="vwfw-finding-card">
					<span class="vwfw-finding-label"><?php echo esc_html( (string) $row['label'] ); ?></span>
					<strong><?php echo esc_html( (string) $row['value'] ); ?></strong>
					<p><?php echo esc_html( (string) $row['detail'] ); ?></p>
				</article>
			<?php endforeach; ?>
		</div>
		<?php
	}

	private function render_password_characteristics_panel( array $rows ): void {
		$groups = $this->group_password_characteristics( $rows );
		?>
		<div class="vwfw-panel vwfw-record-panel">
			<?php $this->render_record_header( 'Password Characteristics', 'How attackers are constructing the actual failed-password values.', count( $rows ), false ); ?>
			<?php if ( empty( $groups ) ) : ?>
				<p class="description">No password characteristics found for this period.</p>
			<?php else : ?>
				<div class="vwfw-distribution-grid">
					<?php foreach ( $groups as $group_label => $group_rows ) : ?>
						<section class="vwfw-distribution-card">
							<h3><?php echo esc_html( (string) $group_label ); ?></h3>
							<?php foreach ( $group_rows as $row ) : ?>
								<?php $bar_width = min( 100, max( 0, (float) $row['attempt_share'] ) ); ?>
								<div class="vwfw-distribution-row">
									<div class="vwfw-distribution-heading">
										<span><?php echo esc_html( (string) $row['label'] ); ?></span>
										<strong><?php echo esc_html( $this->format_percentage( (float) $row['attempt_share'] ) ); ?></strong>
									</div>
									<div class="vwfw-distribution-track" aria-hidden="true">
										<span class="vwfw-distribution-bar" style="width: <?php echo esc_attr( (string) $bar_width ); ?>%"></span>
									</div>
									<div class="vwfw-distribution-meta">
										<span><?php echo esc_html( number_format_i18n( (int) $row['attempts'] ) ); ?> attempts</span>
										<span><?php echo esc_html( number_format_i18n( (int) $row['ips'] ) ); ?> IPs</span>
										<span><?php echo esc_html( number_format_i18n( (int) $row['password_values'] ) ); ?> passwords</span>
									</div>
								</div>
							<?php endforeach; ?>
						</section>
					<?php endforeach; ?>
				</div>
			<?php endif; ?>
		</div>
		<?php
	}

	private function render_targeted_usernames_panel( array $rows ): void {
		?>
		<div class="vwfw-panel vwfw-record-panel">
			<?php $this->render_record_header( 'Targeted Usernames', 'Submitted usernames ranked by attack volume and password variety.', count( $rows ), false ); ?>
			<div class="vwfw-record-table-wrap">
				<table class="widefat striped fixed vwfw-analysis-table vwfw-target-table">
					<thead>
						<tr>
							<th>Username</th>
							<th>Attempts</th>
							<th>Spread</th>
							<th>Username in Password</th>
							<th>Blocked</th>
							<th>Last Seen</th>
						</tr>
					</thead>
					<tbody>
						<?php if ( empty( $rows ) ) : ?>
							<tr><td colspan="6">No targeted usernames found for this period.</td></tr>
						<?php else : ?>
							<?php foreach ( $rows as $row ) : ?>
								<tr>
									<td class="vwfw-table-primary"><?php echo esc_html( (string) $row['username'] ); ?></td>
									<td><?php echo esc_html( number_format_i18n( (int) $row['attempts'] ) ); ?></td>
									<td class="vwfw-break"><?php echo esc_html( (string) $row['target_summary'] ); ?></td>
									<td>
										<?php echo esc_html( $this->format_percentage( (float) $row['username_in_password_share'] ) ); ?>
										<span class="vwfw-muted"><?php echo esc_html( number_format_i18n( (int) $row['username_in_password_attempts'] ) ); ?> attempts</span>
									</td>
									<td><?php echo esc_html( number_format_i18n( (int) $row['blocked'] ) ); ?></td>
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

	private function render_important_passwords_panel( array $rows ): void {
		?>
		<div class="vwfw-panel vwfw-record-panel">
			<?php $this->render_record_header( 'Password Campaigns', 'Actual failed-password values ranked by volume and distribution.', count( $rows ), false ); ?>
			<div class="vwfw-record-table-wrap">
				<table class="widefat striped fixed vwfw-analysis-table vwfw-password-table">
					<thead>
						<tr>
							<th>Password</th>
							<th>Attempts</th>
							<th>Spread</th>
							<th>Distribution</th>
							<th>Seen</th>
						</tr>
					</thead>
					<tbody>
						<?php if ( empty( $rows ) ) : ?>
							<tr><td colspan="5">No failed-login passwords found for this period.</td></tr>
						<?php else : ?>
							<?php foreach ( $rows as $row ) : ?>
								<tr>
									<td class="vwfw-sensitive"><?php echo esc_html( (string) $row['password_value'] ); ?></td>
									<td><?php echo esc_html( number_format_i18n( (int) $row['attempts'] ) ); ?></td>
									<td class="vwfw-break"><?php echo esc_html( (string) $row['spread_summary'] ); ?></td>
									<td>
										<div class="vwfw-mini-metrics">
											<span><strong><?php echo esc_html( number_format_i18n( (int) $row['ips'] ) ); ?></strong> IPs</span>
											<span><strong><?php echo esc_html( number_format_i18n( (int) $row['countries'] ) ); ?></strong> countries</span>
											<span><strong><?php echo esc_html( number_format_i18n( (int) $row['user_agent_fingerprints'] ) ); ?></strong> UAs</span>
										</div>
									</td>
									<td>
										<span><?php echo esc_html( $this->event_report_formatter->admin_datetime( (string) $row['first_seen'] ) ); ?></span>
										<span class="vwfw-muted"><?php echo esc_html( $this->event_report_formatter->admin_datetime( (string) $row['last_seen'] ) ); ?></span>
									</td>
								</tr>
							<?php endforeach; ?>
						<?php endif; ?>
					</tbody>
				</table>
			</div>
		</div>
		<?php
	}

	private function format_percentage( float $percentage ): string {
		return number_format_i18n( $percentage, 1 ) . '%';
	}

	private function group_password_characteristics( array $rows ): array {
		$groups = array();

		foreach ( $rows as $row ) {
			$group_label              = (string) $row['group_label'];
			$groups[ $group_label ][] = $row;
		}

		return $groups;
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
							<th>Last Seen</th>
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
