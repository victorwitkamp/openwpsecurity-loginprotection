=== OpenWPSecurity - Login Protection ===
Contributors: victorwitkamp
Tags: security, login security, lockouts, bans, logging
Requires at least: 6.5
Tested up to: 6.9.4
Requires PHP: 8.2
Stable tag: 0.2.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

WordPress login protection with failed-login tracking, lockouts, permanent bans, and a dedicated login-event dashboard.

== Description ==

OpenWPSecurity - Login Protection focuses on the WordPress login flow. It tracks successful, failed, and blocked login attempts, creates temporary lockouts, escalates repeated abuse into permanent bans, and keeps login events in a dedicated table with its own admin dashboard.

Current highlights:

* Tracks successful logins, failed logins, blocked logins, lockout creation, and login-triggered permanent bans.
* Stores login events separately from the firewall plugin's general request events.
* Provides a dedicated Login Protection admin page with Dashboard, Activity, and Settings tabs.
* Maintains its own permanent-ban store and login-protection settings independently from the firewall plugin.

Development/build notes:

* PHP tooling is managed with Composer.
* Admin styles are authored in `assets/scss/admin.scss` and compiled to `assets/css/admin.css`.
* Run `npm run build:css` after changing SCSS sources.
* GitHub Actions workflows are included for CI and release packaging.

== Installation ==

1. Upload the plugin folder to `/wp-content/plugins/`.
2. Activate `OpenWPSecurity - Login Protection` in WordPress admin.
3. Open the `OpenWPSecurity - Login Protection` admin page and review the Settings tab.

== Frequently Asked Questions ==

= Does this replace the firewall plugin? =

No. This plugin protects the WordPress login flow. It is designed to complement the firewall plugin, not replace its request-handling features.

= Where do I change the admin CSS? =

Edit `assets/scss/admin.scss` and rebuild `assets/css/admin.css` with `npm run build:css`.
