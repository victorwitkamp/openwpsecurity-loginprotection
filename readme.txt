=== OpenWPSecurity - Login Protection ===
Contributors: victorwitkamp
Tags: security, login security, lockouts, bans, logging
Requires at least: 6.5
Tested up to: 6.9.4
Requires PHP: 8.2
Stable tag: 0.2.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

WordPress login-event tracking, temporary lockouts, failed-password analysis, permanent bans, and login security reporting.

== Description ==

OpenWPSecurity - Login Protection monitors the WordPress login flow and records successful, failed, blocked, and locked-out login activity in a dedicated login-event table.

Runtime behavior:

* Records successful logins, failed logins, blocked logins, temporary lockouts, and login-triggered permanent bans.
* Creates temporary IP lockouts after configured failed-login thresholds.
* Escalates repeated lockouts or long failed-login streaks into permanent IP bans.
* Keeps login events, settings, lockout counters, and permanent bans separate from the firewall plugin.
* Stores submitted failed-login passwords as plaintext, masked values, and salted fingerprints for password/IP correlation analysis.
* Provides admin reporting for login activity, countries, IP addresses, usernames, user agents, lockout expiry, and event details.

Stored login-event fields include event type, timestamp, IP address, country fields, username, plaintext password value, password mask, password fingerprint, user agent, request URI, lockout expiry, and JSON details.

Remote GeoIP lookup is optional and disabled by default. Local, private, and reserved IP addresses are classified without remote lookup.

== Installation ==

1. Upload the packaged plugin folder to `/wp-content/plugins/`.
2. Activate `OpenWPSecurity - Login Protection`.
3. Review Login Protection settings for trusted IP headers, whitelisted IPs, failed-login thresholds, lockout duration, permanent-ban escalation, retention, and GeoIP lookup.
