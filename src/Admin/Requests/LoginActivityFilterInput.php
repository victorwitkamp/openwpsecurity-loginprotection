<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\LoginProtection\Admin\Requests;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class LoginActivityFilterInput {
	private const EVENT_TYPES = array(
		'success_login',
		'failed_login',
		'blocked_login',
		'login_lockout',
		'permanent_ban_created',
	);

	public function read(): array {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only admin filter parameter.
		$event_type = isset( $_GET['event_type'] ) ? sanitize_key( (string) wp_unslash( $_GET['event_type'] ) ) : '';

		if ( ! in_array( $event_type, self::EVENT_TYPES, true ) ) {
			$event_type = '';
		}

		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Read-only admin filter parameters.
		return array(
			'event_type'   => $event_type,
			'country_code' => isset( $_GET['country_code'] ) ? strtoupper( sanitize_text_field( (string) wp_unslash( $_GET['country_code'] ) ) ) : '',
			'ip_address'   => isset( $_GET['ip_address'] ) ? sanitize_text_field( (string) wp_unslash( $_GET['ip_address'] ) ) : '',
			'username'     => isset( $_GET['username'] ) ? sanitize_text_field( (string) wp_unslash( $_GET['username'] ) ) : '',
			'request_uri'  => isset( $_GET['request_uri'] ) ? sanitize_text_field( (string) wp_unslash( $_GET['request_uri'] ) ) : '',
		);
		// phpcs:enable WordPress.Security.NonceVerification.Recommended
	}

	public function event_types(): array {
		return self::EVENT_TYPES;
	}

	public function country_option_filters( array $filters ): array {
		unset( $filters['country_code'] );

		return $filters;
	}

	public function query_args( array $filters ): array {
		$query_args = array();

		if ( '' !== $filters['event_type'] ) {
			$query_args['event_type'] = $filters['event_type'];
		}

		if ( '' !== $filters['country_code'] ) {
			$query_args['country_code'] = $filters['country_code'];
		}

		if ( '' !== $filters['ip_address'] ) {
			$query_args['ip_address'] = $filters['ip_address'];
		}

		if ( '' !== $filters['username'] ) {
			$query_args['username'] = $filters['username'];
		}

		if ( '' !== $filters['request_uri'] ) {
			$query_args['request_uri'] = $filters['request_uri'];
		}

		return $query_args;
	}
}
