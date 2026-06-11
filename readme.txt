=== OpenWPSecurity - Login Protection ===
Contributors: victorwitkamp
Donate link: https://github.com/sponsors/victorwitkamp
Tags: security, login security, temporary bans, permanent bans, logging
Requires at least: 6.5
Tested up to: 6.9.4
Requires PHP: 8.2
Stable tag: 0.3.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

WordPress login activity tracking, temporary bans, failed-password analysis, permanent bans, and login security reporting.

== Description ==

OpenWPSecurity - Login Protection monitors the WordPress login flow and stores login attempts, active temporary bans, temporary-ban counters, and permanent bans in separate plugin-owned database tables.

Runtime behavior:

* Records successful logins, failed logins, blocked logins, temporary bans, and login-triggered permanent bans.
* Creates temporary IP bans for the WordPress login flow after configured failed-login thresholds.
* Escalates repeated temporary bans or long failed-login streaks into permanent IP bans.
* Keeps login attempts, temporary-ban state, settings, counters, and permanent bans separate from the firewall plugin.
* Stores submitted failed-login passwords as plaintext, masked values, and salted fingerprints for password/IP correlation analysis.
* Correlates failed-login activity by password fingerprints, derived password features, source IPs, IPv4 /24 ranges, and user-agent fingerprints.
* Provides admin reporting for login activity, countries, IP addresses, usernames, user agents, temporary-ban expiry, evidence details, and credential-correlation signals.

Stored login-attempt fields include attempt type, timestamp, IP address, country fields, username, plaintext password value, password mask, password fingerprint, user agent, request URI, temporary-ban expiry, and JSON evidence.

Remote GeoIP lookup is optional and disabled by default. Local, private, and reserved IP addresses are classified without remote lookup.

== Installation ==

1. Upload the packaged plugin folder to `/wp-content/plugins/`.
2. Activate `OpenWPSecurity - Login Protection`.
3. Review Login Protection settings for trusted IP headers, whitelisted IPs, failed-login thresholds, temporary-ban duration, permanent-ban escalation, retention, and GeoIP lookup.

== Frequently Asked Questions ==

= What data does the plugin store for failed login attempts? =

Each failed login attempt record stores: attempt type, timestamp, IP address, country, username, the submitted password in plaintext, a password mask, a salted SHA-256 password fingerprint, user agent, request URI, and JSON evidence. Storing the plaintext password is intentional — it enables the credential-correlation analysis on the Analysis page, which identifies whether the same password is being tried across many IPs or usernames. You can configure how long records are retained (default: 90 days) or disable retention entirely on the Settings page. If you prefer not to store plaintext passwords, use the Firewall plugin instead, which does not record credentials.

= Can I whitelist my own IP address? =

Yes. Add one or more IP addresses (or CIDR ranges) to the whitelist on the Settings page. Whitelisted IPs and logged-in administrators are always bypassed.

= What triggers a permanent ban? =

Two conditions escalate a temporary lockout to a permanent ban: (1) an IP reaches the configured number of consecutive failed login attempts without a success, or (2) the same IP accumulates the configured number of temporary lockouts within the counter window. Both thresholds are configurable on the Settings page.

= Does the plugin work behind a CDN or reverse proxy? =

Yes. Configure the trusted IP header (for example `X-Forwarded-For` or `CF-Connecting-IP`) on the Settings page so the plugin reads the real visitor IP rather than the proxy address.

= What is the difference between Login Protection and the Firewall plugin? =

Login Protection focuses exclusively on `wp-login.php` and stores detailed credential-correlation data for failed logins. The Firewall plugin covers all WordPress request types and applies endpoint-specific rate limits, captcha challenges, and IP banning. The two plugins can be used independently or together; when both are active you can optionally configure the Firewall to also enforce Login Protection permanent bans.

= How do I remove all plugin data? =

Deactivate and then delete the plugin from the Plugins screen. The uninstall routine drops all plugin-owned database tables and removes all plugin options.

== External Services ==

When the **Remote GeoIP lookup** setting is enabled (disabled by default), this plugin sends the visitor's IP address to a third-party service to determine the country of origin:

* Service: [ipwho.is](https://ipwho.is/)
* Data sent: IP address only
* Purpose: Country classification for security logs and reports
* Privacy policy: https://ipwho.is/

Remote GeoIP lookup is never used for private, loopback, or reserved IP addresses, which are classified locally without any external call. You can disable remote lookup at any time on the Settings page.

== Privacy Notice ==

This plugin stores the following personal data about WordPress site visitors:

* IP address (used for ban and rate-limit decisions)
* Country of origin (derived from IP address)
* User agent string
* Request URI
* Submitted login username
* Submitted login password (plaintext, mask, and fingerprint — for credential-correlation analysis)

Data is stored in plugin-owned database tables on your server. No personal data is sent to external services unless the optional Remote GeoIP lookup is enabled. Records are automatically deleted after the configured retention period (default: 90 days).

== Screenshots ==

1. Dashboard showing login attempt counts, lockouts, permanent bans, and recent activity.
2. Activity log with filtering by attempt type, IP address, username, and date range.
3. Analysis page with credential-correlation signals and attack-pattern indicators.
4. Temporary bans view with expiry times and evidence details.
5. Permanent bans management with individual ban removal.
6. Settings page with thresholds, trusted IP headers, whitelisting, and retention options.

== Changelog ==

= 0.3.0 =
* Updated to openwpsecurity/core 0.4.0.
* Added plugin banner, icon, and branding assets.
* Added uninstall routine to remove all plugin-owned tables and options on deletion.
* Added FAQ, External Services, Privacy Notice, Screenshots, and Changelog sections to readme.

= 0.2.0 =
* Initial public release.
* Failed-login tracking with configurable attempt thresholds and lockout windows.
* Temporary IP lockouts with escalation to permanent bans on repeated violations.
* Credential-correlation analysis by password fingerprint, IP range, username, and user agent.
* Separate login-attempts and login-lockouts tables with configurable retention.
* Optional remote GeoIP lookup via ipwho.is (disabled by default).
* Admin interface with dashboard, activity log, analysis, temporary bans, permanent bans, policies, and settings pages.
