# OpenWPSecurity — Login Protection

<img src=".wordpress-org/banner-772x250.png" alt="OpenWPSecurity Login Protection" width="772">

WordPress login activity tracking, failed-login thresholds, temporary lockouts, permanent bans, and credential-correlation analysis.

[![WordPress](https://img.shields.io/badge/WordPress-6.5%2B-blue?logo=wordpress)](https://wordpress.org/)
[![PHP](https://img.shields.io/badge/PHP-8.2%2B-777BB4?logo=php)](https://php.net/)
[![License](https://img.shields.io/badge/License-GPL--2.0--or--later-green)](LICENSE)

---

## Features

- Records every login attempt: successful logins, failed logins, and blocked logins
- Temporary IP lockouts after configurable failed-login thresholds
- Escalation to permanent bans on repeated lockouts or consecutive failure streaks
- Stores failed-login passwords as plaintext, mask, and SHA-256 fingerprint for correlation analysis
- Credential-correlation report: identify password reuse, IP ranges, username patterns, and user-agent fingerprints
- Optional remote GeoIP lookup via [ipwho.is](https://ipwho.is/) (disabled by default)
- Admin dashboard with activity log, analysis, temporary bans, permanent bans, policies, and settings

> **Privacy note:** Plaintext failed-login passwords are stored by design to enable credential-correlation analysis. Configure the retention period on the Settings page (default: 90 days). If you do not need credential analysis, consider using the [Firewall](https://github.com/victorwitkamp/openwpsecurity-firewall) plugin instead.

## Requirements

- WordPress 6.5+
- PHP 8.2+

## Installation

1. Download the latest release ZIP from the [Releases](../../releases) page.
2. In WordPress admin go to **Plugins → Add New → Upload Plugin**.
3. Upload the ZIP and activate.
4. Configure under **OpenWPSecurity → Login Protection → Settings**.

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| Trusted IP header | `REMOTE_ADDR` | HTTP header used to resolve the real visitor IP |
| Whitelist IPs | — | IPs exempt from all enforcement |
| Max login attempts | 3 | Failed attempts per IP per window before lockout |
| Attempt window | 15 min | Rolling window for counting attempts |
| Lockout duration | 30 min | Duration of a temporary lockout |
| Lockouts before permanent ban | 2 | Repeated lockouts that trigger a permanent ban |
| Failed streak before permanent ban | 10 | Consecutive failures that trigger a permanent ban |
| Event retention | 90 days | How long login-attempt records are kept |
| Remote GeoIP | Disabled | Send IP to ipwho.is for country lookup |

## Database tables

| Table | Purpose |
|-------|---------|
| `*_openwpsecurity_loginprotection_login_attempts` | All login attempts with credential data |
| `*_openwpsecurity_loginprotection_login_lockouts` | Lockout events |
| `*_openwpsecurity_loginprotection_temporary_bans` | Active temporary bans |
| `*_openwpsecurity_loginprotection_temporary_ban_counts` | Per-IP ban recurrence counters |
| `*_openwpsecurity_loginprotection_permanent_bans` | Permanent IP bans |

All tables are dropped on plugin deletion.

## Requirements & dependency

This plugin requires [`openwpsecurity/core`](https://github.com/victorwitkamp/openwpsecurity-core), which is bundled in the release ZIP via Composer.

## License

GPL-2.0-or-later — see [LICENSE](LICENSE).
