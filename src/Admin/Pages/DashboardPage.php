<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\LoginProtection\Admin\Pages;

use VictorWitkamp\OpenWPSecurity\Core\Admin\Pages\AbstractAdminPage;
use VictorWitkamp\OpenWPSecurity\Core\Admin\Reporting\EventReportFormatter;
use VictorWitkamp\OpenWPSecurity\Core\Admin\Reporting\ReportPeriod;
use VictorWitkamp\OpenWPSecurity\Core\Security\Ban\PermanentBanStore;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Admin\Navigation\AdminMenu;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Ban\TemporaryBanRepository;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\Reports\LoginDashboardReport;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class DashboardPage extends AbstractAdminPage {
	private LoginDashboardReport $login_dashboard_report;
	private TemporaryBanRepository $temporary_ban_repository;
	private PermanentBanStore $ban_store;

	public function __construct( LoginDashboardReport $login_dashboard_report, TemporaryBanRepository $temporary_ban_repository, PermanentBanStore $ban_store, ReportPeriod $report_period, EventReportFormatter $event_report_formatter ) {
		parent::__construct( $report_period, $event_report_formatter, AdminMenu::page_tabs() );
		$this->login_dashboard_report   = $login_dashboard_report;
		$this->temporary_ban_repository = $temporary_ban_repository;
		$this->ban_store                = $ban_store;
	}

	public function render(): void {
		$this->assert_page_access();

		$period = $this->current_period( '24h' );

		if ( 'all' === $period ) {
			$period = '24h';
		}

		$data = $this->load_dashboard_data( $period );
		?>
		<div class="wrap vwfw-admin vwfw-dashboard">
			<h1><?php esc_html_e( 'OpenWPSecurity - Login Protection', 'openwpsecurity-loginprotection' ); ?></h1>
			<p><?php esc_html_e( 'Selected-range login activity and current enforcement state.', 'openwpsecurity-loginprotection' ); ?></p>

			<?php $this->render_page_tabs( 'openwpsecurity-loginprotection' ); ?>
			<?php $this->render_period_form( 'openwpsecurity-loginprotection', $period, false ); ?>

			<?php $this->render_summary_cards( $data ); ?>
			<?php $this->render_current_state( $data ); ?>
		</div>
		<?php
	}

	private function load_dashboard_data( string $period ): array {
		$period_seconds = $this->report_period->seconds( $period );

		return array(
			'summary'        => $this->login_dashboard_report->summary( $period_seconds ),
			'temporary_bans' => $this->temporary_ban_repository->count_active_temporary_bans(),
			'current_bans'   => $this->ban_store->count_bans(),
		);
	}

	private function render_summary_cards( array $data ): void {
		$summary = $data['summary'];
		?>
		<div class="vwfw-cards">
			<?php $this->render_summary_card( __( 'Total Attempts', 'openwpsecurity-loginprotection' ), (int) $summary['total_attempts'] ); ?>
			<?php $this->render_summary_card( __( 'Successful Logins', 'openwpsecurity-loginprotection' ), (int) $summary['successful_attempts'] ); ?>
			<?php $this->render_summary_card( __( 'Failed Logins', 'openwpsecurity-loginprotection' ), (int) $summary['failed_attempts'] ); ?>
			<?php $this->render_summary_card( __( 'Blocked Logins', 'openwpsecurity-loginprotection' ), (int) $summary['blocked_attempts'] ); ?>
			<?php $this->render_summary_card( __( 'Temporary Bans Created', 'openwpsecurity-loginprotection' ), (int) $summary['lockouts'] ); ?>
			<?php $this->render_summary_card( __( 'Permanent Bans Created', 'openwpsecurity-loginprotection' ), (int) $summary['permanent_bans'] ); ?>
			<?php $this->render_summary_card( __( 'Unique Login IPs', 'openwpsecurity-loginprotection' ), (int) $summary['unique_ips'] ); ?>
		</div>
		<?php
	}

	private function render_current_state( array $data ): void {
		$permanent_bans_url = admin_url( 'admin.php?page=openwpsecurity-loginprotection-bans' );
		$temporary_bans_url = admin_url( 'admin.php?page=openwpsecurity-loginprotection-temporary-bans' );
		?>
		<section class="vwfw-current-state">
			<div class="vwfw-section-heading">
				<div>
					<h2><?php esc_html_e( 'Current Enforcement', 'openwpsecurity-loginprotection' ); ?></h2>
					<p class="description"><?php esc_html_e( 'Live enforcement state. These values are not affected by the selected reporting range.', 'openwpsecurity-loginprotection' ); ?></p>
				</div>
			</div>
			<div class="vwfw-state-grid vwfw-state-grid--compact">
				<a class="vwfw-state-item" href="<?php echo esc_url( $temporary_bans_url ); ?>">
					<span><?php esc_html_e( 'Current Temporary Bans', 'openwpsecurity-loginprotection' ); ?></span>
					<strong><?php echo esc_html( number_format_i18n( (int) $data['temporary_bans'] ) ); ?></strong>
					<small><?php esc_html_e( 'Open management page', 'openwpsecurity-loginprotection' ); ?></small>
				</a>
				<a class="vwfw-state-item" href="<?php echo esc_url( $permanent_bans_url ); ?>">
					<span><?php esc_html_e( 'Current Permanent Bans', 'openwpsecurity-loginprotection' ); ?></span>
					<strong><?php echo esc_html( number_format_i18n( (int) $data['current_bans'] ) ); ?></strong>
					<small><?php esc_html_e( 'Open management page', 'openwpsecurity-loginprotection' ); ?></small>
				</a>
			</div>
		</section>
		<?php
	}
}
