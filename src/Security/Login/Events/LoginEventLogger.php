<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\Events;

use VictorWitkamp\OpenWPSecurity\Core\Location\GeoIpLookup;
use VictorWitkamp\OpenWPSecurity\Core\Http\RequestContext;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Configuration\Settings;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Logging\CredentialFormatter;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\LoginAttempt;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\LoginAttemptRepository;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\LoginLockout;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\LoginLockoutRepository;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class LoginEventLogger {
	private Settings $settings;
	private GeoIpLookup $geo_ip_lookup;
	private CredentialFormatter $credential_formatter;
	private RequestContext $request_context;
	private LoginAttemptRepository $login_attempts;
	private LoginLockoutRepository $login_lockouts;

	public function __construct( LoginAttemptRepository $login_attempts, LoginLockoutRepository $login_lockouts, Settings $settings, GeoIpLookup $geo_ip_lookup, CredentialFormatter $credential_formatter, RequestContext $request_context ) {
		$this->settings             = $settings;
		$this->geo_ip_lookup        = $geo_ip_lookup;
		$this->credential_formatter = $credential_formatter;
		$this->request_context      = $request_context;
		$this->login_attempts       = $login_attempts;
		$this->login_lockouts       = $login_lockouts;
	}

	public function log( string $event_type, string $ip, string $username = '', string $password = '', array $extra = array() ): void {
		$settings = $this->settings->get();
		$geo      = $this->geo_ip_lookup->lookup( $ip, ! empty( $settings['enable_remote_geoip'] ) );
		$details  = isset( $extra['details'] ) && is_array( $extra['details'] ) ? $extra['details'] : array();

		$event = array(
			'attempt_type'       => $event_type,
			'event_type'         => $event_type,
			'ip_address'         => $ip,
			'country_code'       => (string) ( $geo['country_code'] ?? '' ),
			'country_name'       => (string) ( $geo['country_name'] ?? '' ),
			'username'           => $username,
			'password_value'     => $this->credential_formatter->password_value( $password ),
			'password_mask'      => $this->credential_formatter->mask_password( $password ),
			'password_hash'      => $this->credential_formatter->password_fingerprint( $password ),
			'user_agent'         => $this->request_context->current_user_agent(),
			'request_uri'        => $this->request_context->current_url(),
			'lockout_expires_at' => $extra['lockout_expires_at'] ?? null,
			'evidence_json'      => $details ? wp_json_encode( $details ) : '',
			'details'            => $details ? wp_json_encode( $details ) : '',
		);

		if ( 'login_lockout' === $event_type ) {
			$this->login_lockouts->insert(
				new LoginLockout(
					$ip,
					(string) $event['country_code'],
					(string) $event['country_name'],
					$username,
					(int) ( $details['failed_attempts'] ?? 0 ),
					(int) ( $details['lockout_count'] ?? 0 ),
					(string) ( $event['lockout_expires_at'] ?? '' ),
					(string) $event['request_uri'],
					(string) $event['user_agent'],
					(string) $event['evidence_json']
				)
			);

			return;
		}

		if ( 'permanent_ban_created' === $event_type ) {
			return;
		}

		$this->login_attempts->insert(
			new LoginAttempt(
				$event_type,
				$ip,
				(string) $event['country_code'],
				(string) $event['country_name'],
				$username,
				(string) $event['password_value'],
				(string) $event['password_mask'],
				(string) $event['password_hash'],
				(string) $event['user_agent'],
				(string) $event['request_uri'],
				null === $event['lockout_expires_at'] ? null : (string) $event['lockout_expires_at'],
				(string) $event['evidence_json']
			)
		);
	}
}
