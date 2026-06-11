<?php

declare(strict_types=1);

namespace VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login;

use WP_Error;
use WP_User;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Configuration\Settings;
use VictorWitkamp\OpenWPSecurity\Core\Http\RequestContext;
use VictorWitkamp\OpenWPSecurity\Core\Http\Response\RequestDenialResponder;
use VictorWitkamp\OpenWPSecurity\Core\Security\Ban\PermanentBanStore;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Ban\TemporaryBanCounterStore;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Ban\TemporaryBanRepository;
use VictorWitkamp\OpenWPSecurity\LoginProtection\Security\Login\Events\LoginEventLogger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class LoginAttemptGuard {
	private Settings $settings;
	private TemporaryBanRepository $temporary_ban_repository;
	private TemporaryBanCounterStore $temporary_ban_counter_store;
	private PermanentBanStore $ban_store;
	private LoginEventLogger $login_event_logger;
	private RequestDenialResponder $denial_responder;
	private RequestContext $request_context;
	private AttemptCounter $attempt_counter;
	private FailedLoginStreakStore $failed_login_streak_store;
	private int $temporary_ban_expires = 0;

	public function __construct( Settings $settings, TemporaryBanRepository $temporary_ban_repository, TemporaryBanCounterStore $temporary_ban_counter_store, PermanentBanStore $ban_store, LoginEventLogger $login_event_logger, RequestDenialResponder $denial_responder, RequestContext $request_context, AttemptCounter $attempt_counter, FailedLoginStreakStore $failed_login_streak_store ) {
		$this->settings                    = $settings;
		$this->temporary_ban_repository    = $temporary_ban_repository;
		$this->temporary_ban_counter_store = $temporary_ban_counter_store;
		$this->ban_store                   = $ban_store;
		$this->login_event_logger          = $login_event_logger;
		$this->denial_responder            = $denial_responder;
		$this->request_context             = $request_context;
		$this->attempt_counter             = $attempt_counter;
		$this->failed_login_streak_store   = $failed_login_streak_store;
	}

	public function register_hooks(): void {
		add_filter( 'authenticate', array( $this, 'reject_banned_login' ), 1, 3 );
		add_filter( 'authenticate', array( $this, 'reject_temporarily_banned_login' ), 5, 3 );
		add_filter( 'authenticate', array( $this, 'record_failed_login' ), 99, 3 );
		add_action( 'wp_login', array( $this, 'record_successful_login' ), 10, 2 );
		add_action( 'login_init', array( $this, 'prepare_login_screen' ), 1 );
	}

	public function prepare_login_screen(): void {
		if ( wp_doing_ajax() ) {
			return;
		}

		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			return;
		}

		$ip = $this->get_ip();
		if ( $this->is_ip_whitelisted( $ip ) ) {
			return;
		}

		$ban = $this->ban_store->get_ban_for_ip( $ip );

		if ( array() !== $ban ) {
			$this->denial_responder->deny_permanently(
				$ip,
				'wp_login',
				'Access permanently blocked',
				'This IP address has been permanently banned by OpenWPSecurity - Login Protection.',
				'OpenWPSecurity - Login Protection will not allow access to the WordPress login flow for this IP address.'
			);
		}

		$expires = $this->temporary_ban_repository->temporary_ban_expires_at( $ip );

		if ( $expires > 0 ) {
			$this->temporary_ban_expires = $expires;
			add_filter( 'login_message', array( $this, 'render_temporary_ban_message' ) );
			return;
		}
	}

	public function reject_banned_login( $user, string $username, string $password ) {
		if ( $username === '' && $password === '' ) {
			return $user;
		}

		$ip = $this->get_ip();

		if ( $this->is_ip_whitelisted( $ip ) ) {
			return $user;
		}

		$ban = $this->ban_store->get_ban_for_ip( $ip );

		if ( array() === $ban ) {
			return $user;
		}

		$this->login_event_logger->log(
			'blocked_login',
			$ip,
			$username,
			$password,
			array(
				'details' => array(
					'reason'     => 'permanent_ban',
					'ban_source' => (string) ( $ban['source'] ?? '' ),
				),
			)
		);

		return new WP_Error(
			'openwpsecurity_loginprotection_permanently_banned',
			'This IP address has been permanently banned by OpenWPSecurity - Login Protection.'
		);
	}

	public function reject_temporarily_banned_login( $user, string $username, string $password ) {
		if ( $username === '' && $password === '' ) {
			return $user;
		}

		$ip = $this->get_ip();

		if ( $this->is_ip_whitelisted( $ip ) ) {
			return $user;
		}

		$expires = $this->temporary_ban_repository->temporary_ban_expires_at( $ip );

		if ( $expires <= 0 ) {
			return $user;
		}

		$minutes = max( 1, (int) ceil( ( $expires - time() ) / MINUTE_IN_SECONDS ) );

		$this->login_event_logger->log(
			'blocked_login',
			$ip,
			$username,
			$password,
			array(
				'details'            => array(
					'reason' => 'ip_locked_out',
				),
				'lockout_expires_at' => gmdate( 'Y-m-d H:i:s', $expires ),
			)
		);

		return new WP_Error(
			'openwpsecurity_loginprotection_locked_out',
			sprintf( 'Too many failed login attempts. Try again in %d minute(s).', $minutes )
		);
	}

	public function record_failed_login( $user, string $username, string $password ) {
		if ( $username === '' && $password === '' ) {
			return $user;
		}

		if ( ! is_wp_error( $user ) ) {
			return $user;
		}

		if ( in_array( $user->get_error_code(), array( 'openwpsecurity_loginprotection_locked_out', 'openwpsecurity_loginprotection_permanently_banned' ), true ) ) {
			return $user;
		}

		$ip = $this->get_ip();

		$this->login_event_logger->log(
			'failed_login',
			$ip,
			$username,
			$password,
			array(
				'details' => array(
					'error_codes' => $user->get_error_codes(),
				),
			)
		);

		if ( $this->is_ip_whitelisted( $ip ) ) {
			return $user;
		}

		$settings            = $this->settings->get();
		$state               = $this->attempt_counter->increment( $ip );
		$failed_login_streak = $this->failed_login_streak_store->record_failed_login( $ip );

		if ( $this->create_permanent_ban_after_failed_login_streak( $ip, $username, $failed_login_streak ) ) {
			$this->attempt_counter->clear( $ip );
			$this->temporary_ban_repository->remove_temporary_ban( $ip );
			$this->failed_login_streak_store->clear_failed_login_streak( $ip );
			$this->denial_responder->deny_permanently(
				$ip,
				'wp_login',
				'Access permanently blocked',
				'This IP address has been permanently banned by OpenWPSecurity - Login Protection after too many failed logins in a row.',
				'Access to the WordPress login flow is now blocked for this IP address.'
			);
		}

		if ( $state['count'] < $settings['login_max_attempts'] ) {
			return $user;
		}

		$lockout_count = $this->temporary_ban_counter_store->increment_for_ip( $ip );
		$expires       = $this->temporary_ban_repository->create_temporary_ban( $ip, $settings['login_lockout_minutes'] * MINUTE_IN_SECONDS, $lockout_count );
		$this->attempt_counter->clear( $ip );

		$this->login_event_logger->log(
			'login_lockout',
			$ip,
			$username,
			$password,
			array(
				'details'            => array(
					'failed_attempts' => $state['count'],
					'lockout_count'   => $lockout_count,
				),
				'lockout_expires_at' => gmdate( 'Y-m-d H:i:s', $expires ),
			)
		);

		$created_ban = $this->create_permanent_ban_after_repeated_temporary_bans(
			$ip,
			$username,
			(int) $state['count'],
			$expires,
			$lockout_count
		);

		if ( $created_ban ) {
			$this->temporary_ban_repository->remove_temporary_ban( $ip );
			$this->failed_login_streak_store->clear_failed_login_streak( $ip );
			$this->denial_responder->deny_permanently(
				$ip,
				'wp_login',
				'Access permanently blocked',
				'This IP address has been permanently banned by OpenWPSecurity - Login Protection after repeated lockouts.',
				'Access to the WordPress login flow is now blocked for this IP address.'
			);
		}

		return $user;
	}

	public function record_successful_login( string $username, WP_User $user ): void {
		$ip = $this->get_ip();

		if ( '' !== $ip ) {
			$this->attempt_counter->clear( $ip );
			$this->temporary_ban_repository->remove_temporary_ban( $ip );
			$this->failed_login_streak_store->clear_failed_login_streak( $ip );
		}

		$this->login_event_logger->log(
			'success_login',
			$ip,
			$username,
			'',
			array(
				'details' => array(
					'user_id' => $user->ID,
				),
			)
		);
	}

	public function render_temporary_ban_message( string $message ): string {
		if ( $this->temporary_ban_expires <= 0 ) {
			return $message;
		}

		$minutes_left = max( 1, (int) ceil( ( $this->temporary_ban_expires - time() ) / MINUTE_IN_SECONDS ) );

		return '<div id="login_error"><strong>OpenWPSecurity - Login Protection:</strong> Too many failed login attempts were detected from this IP address. Try again in ' . esc_html( (string) $minutes_left ) . ' minute(s).</div>' . $message;
	}

	private function get_ip(): string {
		return $this->request_context->current_ip();
	}

	private function is_ip_whitelisted( string $ip ): bool {
		return $this->request_context->is_ip_whitelisted( $ip );
	}

	private function create_permanent_ban_after_repeated_temporary_bans( string $ip, string $username, int $failed_attempt_count, int $lockout_expires, int $lockout_count ): bool {
		$settings = $this->settings->get();

		if ( (int) $settings['login_lockouts_before_permanent_ban'] <= 0 ) {
			return false;
		}

		if ( $lockout_count < (int) $settings['login_lockouts_before_permanent_ban'] ) {
			return false;
		}

		if ( $this->ban_store->is_banned( $ip ) ) {
			return false;
		}

		$this->ban_store->create_ban(
			$ip,
			'IP address reached the permanent-ban threshold after repeated temporary bans.',
			'login_protection',
			array(
				'username'                  => $username,
				'failed_attempts'           => $failed_attempt_count,
				'lockout_expires'           => gmdate( 'Y-m-d H:i:s', $lockout_expires ),
				'lockout_count'             => $lockout_count,
				'login_lockouts_before_ban' => (int) $settings['login_lockouts_before_permanent_ban'],
			)
		);

		return true;
	}

	private function create_permanent_ban_after_failed_login_streak( string $ip, string $username, int $failed_login_streak ): bool {
		$settings = $this->settings->get();

		if ( (int) $settings['login_failed_attempts_before_permanent_ban'] <= 0 ) {
			return false;
		}

		if ( $failed_login_streak < (int) $settings['login_failed_attempts_before_permanent_ban'] ) {
			return false;
		}

		if ( $this->ban_store->is_banned( $ip ) ) {
			return false;
		}

		$this->ban_store->create_ban(
			$ip,
			'IP address reached the permanent-ban threshold after too many failed logins in a row.',
			'login_protection',
			array(
				'username'                         => $username,
				'failed_login_streak'              => $failed_login_streak,
				'login_failed_attempts_before_ban' => (int) $settings['login_failed_attempts_before_permanent_ban'],
				'permanent_ban_trigger'            => 'failed_login_streak',
			)
		);

		return true;
	}
}
