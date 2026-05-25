<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\Events;

use VictorWitkamp\OpenWPSecurity\LoginProtection\Configuration\Settings;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Http\RequestContext;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Location\GeoIpLookup;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Logging\CredentialFormatter;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class LoginEventLogger {
	private LoginEventWriter $login_event_writer;
	private Settings $settings;
	private GeoIpLookup $geo_ip_lookup;
	private CredentialFormatter $credential_formatter;
	private RequestContext $request_context;

	public function __construct( LoginEventWriter $login_event_writer, Settings $settings, GeoIpLookup $geo_ip_lookup, CredentialFormatter $credential_formatter, RequestContext $request_context ) {
		$this->login_event_writer   = $login_event_writer;
		$this->settings             = $settings;
		$this->geo_ip_lookup        = $geo_ip_lookup;
		$this->credential_formatter = $credential_formatter;
		$this->request_context      = $request_context;
	}

	public function log( string $event_type, string $ip, string $username = '', string $password = '', array $extra = array() ): void {
		$settings = $this->settings->get();
		$geo      = $this->geo_ip_lookup->lookup( $ip, ! empty( $settings['enable_remote_geoip'] ) );
		$details  = isset( $extra['details'] ) && is_array( $extra['details'] ) ? $extra['details'] : array();

		$event = array(
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
			'details'            => $details ? wp_json_encode( $details ) : '',
		);

		$this->login_event_writer->insert( $event );
	}
}
