<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\Reports;

use VictorWitkamp\OpenWPSecurity\Core\Admin\Reporting\CountryDistribution;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class LoginActivityReport {
	private LoginActivityLookup $login_activity_lookup;
	private CountryDistribution $country_distribution;

	public function __construct( LoginActivityLookup $login_activity_lookup, CountryDistribution $country_distribution ) {
		$this->login_activity_lookup = $login_activity_lookup;
		$this->country_distribution  = $country_distribution;
	}

	public function count( array $filters = array(), ?int $period_seconds = null ): int {
		return $this->login_activity_lookup->count( $this->event_types(), $filters, $period_seconds );
	}

	public function rows( array $filters = array(), ?int $period_seconds = null, ?int $limit = null, int $offset = 0 ): array {
		return $this->login_activity_lookup->rows( $this->event_types(), $filters, $period_seconds, $limit, $offset );
	}

	public function countries( array $filters = array(), ?int $period_seconds = null, int $limit = 8 ): array {
		return $this->country_distribution->summarize( $this->login_activity_lookup->country_totals( $this->event_types(), $filters, $period_seconds, null ), $limit );
	}

	public function country_options( array $filters = array(), ?int $period_seconds = null ): array {
		return $this->login_activity_lookup->country_options( $this->event_types(), $filters, $period_seconds );
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
