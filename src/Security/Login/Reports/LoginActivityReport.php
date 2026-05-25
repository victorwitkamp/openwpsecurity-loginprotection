<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\Reports;

use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\Events\LoginEventLookup;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class LoginActivityReport {
	private LoginEventLookup $login_event_lookup;

	public function __construct( LoginEventLookup $login_event_lookup ) {
		$this->login_event_lookup = $login_event_lookup;
	}

	public function count( array $filters = array(), ?int $period_seconds = null ): int {
		return $this->login_event_lookup->count_events_matching_types( $this->event_types(), $filters, $period_seconds );
	}

	public function rows( array $filters = array(), ?int $period_seconds = null, ?int $limit = null, int $offset = 0 ): array {
		return $this->login_event_lookup->find_rows_matching_types( $this->event_types(), $filters, $period_seconds, $limit, $offset );
	}

	public function countries( array $filters = array(), ?int $period_seconds = null, int $limit = 8 ): array {
		return $this->login_event_lookup->country_totals_matching_types( $this->event_types(), $filters, $period_seconds, $limit );
	}

	public function country_options( array $filters = array(), ?int $period_seconds = null ): array {
		return $this->login_event_lookup->country_options_matching_types( $this->event_types(), $filters, $period_seconds );
	}

	public function event_types(): array {
		return array(
			'success_login',
			'failed_login',
			'blocked_login',
			'login_lockout',
			'permanent_ban_created',
		);
	}
}
