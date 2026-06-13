<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final readonly class LoginLockout {
	private string $ip_address;
	private string $country_code;
	private string $country_name;
	private string $username;
	private int $failed_attempt_count;
	private int $lockout_count;
	private string $expires_at;
	private string $request_uri;
	private string $user_agent;
	private string $evidence_json;

	public function __construct( string $ip_address, string $country_code, string $country_name, string $username, int $failed_attempt_count, int $lockout_count, string $expires_at, string $request_uri, string $user_agent, string $evidence_json ) {
		$this->ip_address           = $ip_address;
		$this->country_code         = $country_code;
		$this->country_name         = $country_name;
		$this->username             = $username;
		$this->failed_attempt_count = $failed_attempt_count;
		$this->lockout_count        = $lockout_count;
		$this->expires_at           = $expires_at;
		$this->request_uri          = $request_uri;
		$this->user_agent           = $user_agent;
		$this->evidence_json        = $evidence_json;
	}

	/**
	 * @return array<string, int|string>
	 */
	public function to_row(): array {
		return array(
			'ip_address'           => $this->ip_address,
			'country_code'         => $this->country_code,
			'country_name'         => $this->country_name,
			'username'             => $this->username,
			'failed_attempt_count' => $this->failed_attempt_count,
			'lockout_count'        => $this->lockout_count,
			'expires_at'           => $this->expires_at,
			'request_uri'          => $this->request_uri,
			'user_agent'           => $this->user_agent,
			'evidence_json'        => $this->evidence_json,
		);
	}
}
