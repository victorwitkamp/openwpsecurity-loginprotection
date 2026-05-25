<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\LoginProtection\Admin\Reporting;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class EventReportFormatter {
	public function details_from_json( string $details_json ): array {
		if ( '' === $details_json ) {
			return array();
		}

		$decoded = json_decode( $details_json, true );

		return is_array( $decoded ) ? $decoded : array();
	}

	public function admin_datetime( string $gmt_datetime ): string {
		return get_date_from_gmt( $gmt_datetime, 'Y-m-d H:i:s' );
	}

	public function event_type_label( string $event_type ): string {
		$labels = $this->event_type_labels();

		return $labels[ $event_type ] ?? $event_type;
	}

	public function event_type_options( array $event_types, string $all_label = 'All Types' ): array {
		$options = array(
			'' => $all_label,
		);
		$labels  = $this->event_type_labels();

		foreach ( $event_types as $event_type ) {
			$options[ $event_type ] = $labels[ $event_type ] ?? $event_type;
		}

		return $options;
	}

	public function ban_source_label( string $source ): string {
		$labels = array(
			'login_protection' => 'Login Protection',
			'login_lockout'    => 'Login Protection',
			'manual'           => 'Manual',
		);

		return $labels[ $source ] ?? $source;
	}

	private function event_type_labels(): array {
		return array(
			'success_login'         => 'Successful Login',
			'failed_login'          => 'Failed Login',
			'blocked_login'         => 'Blocked Login',
			'login_lockout'         => 'Lockout Created',
			'permanent_ban_created' => 'Permanent Ban Created',
		);
	}
}
