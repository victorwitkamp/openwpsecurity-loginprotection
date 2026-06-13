<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final readonly class LoginAttempt {
	private string $attempt_type;
	private string $ip_address;
	private string $country_code;
	private string $country_name;
	private string $username;
	private string $password_value;
	private string $password_mask;
	private string $password_hash;
	private string $user_agent;
	private string $request_uri;
	private ?string $lockout_expires_at;
	private string $evidence_json;

	public function __construct( string $attempt_type, string $ip_address, string $country_code, string $country_name, string $username, string $password_value, string $password_mask, string $password_hash, string $user_agent, string $request_uri, ?string $lockout_expires_at, string $evidence_json ) {
		$this->attempt_type       = $attempt_type;
		$this->ip_address         = $ip_address;
		$this->country_code       = $country_code;
		$this->country_name       = $country_name;
		$this->username           = $username;
		$this->password_value     = $password_value;
		$this->password_mask      = $password_mask;
		$this->password_hash      = $password_hash;
		$this->user_agent         = $user_agent;
		$this->request_uri        = $request_uri;
		$this->lockout_expires_at = $lockout_expires_at;
		$this->evidence_json      = $evidence_json;
	}

	/**
	 * @return array<string, string|null>
	 */
	public function to_row(): array {
		return array(
			'attempt_type'       => $this->attempt_type,
			'ip_address'         => $this->ip_address,
			'country_code'       => $this->country_code,
			'country_name'       => $this->country_name,
			'username'           => $this->username,
			'password_value'     => $this->password_value,
			'password_mask'      => $this->password_mask,
			'password_hash'      => $this->password_hash,
			'user_agent'         => $this->user_agent,
			'request_uri'        => $this->request_uri,
			'lockout_expires_at' => $this->lockout_expires_at,
			'evidence_json'      => $this->evidence_json,
		);
	}
}
