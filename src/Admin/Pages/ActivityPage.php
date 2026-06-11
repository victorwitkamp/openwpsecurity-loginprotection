<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\LoginProtection\Admin\Pages;

use VictorWitkamp\OpenWPSecurity\Core\Admin\Pages\AbstractAdminPage;
use VictorWitkamp\OpenWPSecurity\Core\Admin\Presentation\CountryDistributionPanel;
use VictorWitkamp\OpenWPSecurity\Core\Admin\Presentation\FilterFormRenderer;
use VictorWitkamp\OpenWPSecurity\Core\Admin\Presentation\RecordTablePanel;
use VictorWitkamp\OpenWPSecurity\Core\Admin\Reporting\EventReportFormatter;
use VictorWitkamp\OpenWPSecurity\Core\Admin\Reporting\ReportPeriod;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Admin\Navigation\AdminMenu;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Admin\Requests\LoginActivityFilterInput;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\Reports\LoginActivityReport;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class ActivityPage extends AbstractAdminPage {
	private const PER_PAGE = 25;

	private LoginActivityReport $login_activity_report;
	private LoginActivityFilterInput $login_activity_filter_input;
	private CountryDistributionPanel $country_distribution_panel;
	private FilterFormRenderer $filter_form_renderer;
	private RecordTablePanel $record_table_panel;

	public function __construct( LoginActivityReport $login_activity_report, LoginActivityFilterInput $login_activity_filter_input, CountryDistributionPanel $country_distribution_panel, FilterFormRenderer $filter_form_renderer, RecordTablePanel $record_table_panel, ReportPeriod $report_period, EventReportFormatter $event_report_formatter ) {
		parent::__construct( $report_period, $event_report_formatter, AdminMenu::page_tabs() );
		$this->login_activity_report       = $login_activity_report;
		$this->login_activity_filter_input = $login_activity_filter_input;
		$this->country_distribution_panel  = $country_distribution_panel;
		$this->filter_form_renderer        = $filter_form_renderer;
		$this->record_table_panel          = $record_table_panel;
	}

	public function render(): void {
		$this->assert_page_access();

		$period          = $this->current_period( 'all' );
		$period_seconds  = $this->period_seconds_for( $period );
		$filters         = $this->login_activity_filter_input->read();
		$total_items     = $this->login_activity_report->count( $filters, $period_seconds );
		$paginator       = $this->create_paginator( $total_items, self::PER_PAGE, 'openwpsecurity-loginprotection-activity', $period, $this->login_activity_filter_input->query_args( $filters ) );
		$rows            = $this->login_activity_report->rows( $filters, $period_seconds, self::PER_PAGE, $paginator->offset() );
		$countries       = $this->login_activity_report->countries( $filters, $period_seconds );
		$country_options = $this->login_activity_report->country_options( $this->login_activity_filter_input->country_option_filters( $filters ), $period_seconds );
		?>
		<div class="wrap vwfw-admin">
			<h1>OpenWPSecurity - Login Protection Activity</h1>
			<p>Inspect successful, failed, and blocked login attempts together with temporary-ban and permanent-ban events.</p>
			<?php $this->render_page_tabs( 'openwpsecurity-loginprotection-activity' ); ?>
			<?php $this->render_period_form( 'openwpsecurity-loginprotection-activity', $period, true, $this->login_activity_filter_input->query_args( $filters ) ); ?>
			<?php $this->render_activity_filters_form( $period, $filters, $country_options ); ?>
			<?php $this->country_distribution_panel->render( $countries, 'Login Activity by Country', 'Events' ); ?>

			<?php
			$this->record_table_panel->render(
				'Login Activity',
				'This view includes successful logins, failed logins, blocked logins, temporary bans, and login-triggered permanent bans.',
				$total_items,
				$paginator->render(),
				array( 'Time', 'Type', 'IP', 'Country', 'Username', 'Password', 'Temporary Ban Expires', 'Request URI' ),
				$rows,
				'No login activity found for this period.',
				'widefat striped fixed vwfw-activity-table',
				function ( array $row ): void {
					?>
					<td><?php echo esc_html( $this->event_report_formatter->admin_datetime( (string) $row['created_at'] ) ); ?></td>
					<td><?php echo esc_html( $this->event_report_formatter->event_type_label( (string) $row['event_type'] ) ); ?></td>
					<td><?php echo esc_html( (string) $row['ip_address'] ); ?></td>
					<td><?php echo esc_html( trim( (string) $row['country_code'] . ' ' . (string) $row['country_name'] ) ); ?></td>
					<td><?php echo esc_html( (string) $row['username'] ); ?></td>
					<td><?php echo esc_html( (string) ( '' !== (string) $row['password_value'] ? $row['password_value'] : $row['password_mask'] ) ); ?></td>
					<td><?php echo esc_html( $row['lockout_expires_at'] ? $this->event_report_formatter->admin_datetime( (string) $row['lockout_expires_at'] ) : '' ); ?></td>
					<td class="vwfw-break"><?php echo esc_html( (string) $row['request_uri'] ); ?></td>
					<?php
				}
			);
		?>
		</div>
		<?php
	}

	private function render_activity_filters_form( string $period, array $filters, array $country_options ): void {
		$country_select_options = array( '' => 'All Countries' );

		foreach ( $country_options as $country ) {
			$country_select_options[ (string) $country['code'] ] = (string) $country['label'];
		}

		$this->filter_form_renderer->render(
			'openwpsecurity-loginprotection-activity',
			$period,
			array(
				array(
					'type'    => 'select',
					'id'      => 'vwfw-login-event-type',
					'name'    => 'event_type',
					'label'   => 'Event Type',
					'value'   => $filters['event_type'],
					'options' => $this->event_report_formatter->event_type_options( $this->login_activity_filter_input->event_types() ),
				),
				array(
					'type'    => 'select',
					'id'      => 'vwfw-login-country',
					'name'    => 'country_code',
					'label'   => 'Country',
					'value'   => $filters['country_code'],
					'options' => $country_select_options,
				),
				array(
					'id'    => 'vwfw-login-ip',
					'name'  => 'ip_address',
					'label' => 'IP Contains',
					'value' => $filters['ip_address'],
				),
				array(
					'id'    => 'vwfw-login-username',
					'name'  => 'username',
					'label' => 'Username Contains',
					'value' => $filters['username'],
				),
				array(
					'id'    => 'vwfw-login-uri',
					'name'  => 'request_uri',
					'label' => 'URI Contains',
					'value' => $filters['request_uri'],
				),
			),
			admin_url( 'admin.php?page=openwpsecurity-loginprotection-activity&period=' . $period )
		);
	}
}
