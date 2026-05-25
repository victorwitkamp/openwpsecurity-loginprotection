# OpenWPSecurity Login Protection Memory

## Purpose
`OpenWPSecurity - Login Protection` protects the WordPress login flow:
- successful and failed login logging
- blocked login logging
- login-specific temporary lockouts
- login-specific permanent bans
- failed-login streak bans

## Current Structure
- `src/Runtime/`
  plugin startup, WordPress integration, container definitions
- `src/Configuration/`
  login-protection settings
- `src/Http/`
  request context and permanent-ban response handling for login flow
- `src/Security/Login/`
  login attempt guard, lockout store, failed-login streak store
- `src/Security/Login/Events/`
  login event schema, lookup, migration, writer
- `src/Security/Login/Reports/`
  login dashboard and activity reporting
- `src/Security/Ban/`
  login-protection-only permanent bans
- `src/Admin/`
  single Login Protection page with dashboard, activity, settings tabs
- `templates/`
  `blocked-permanent.php`

## Key Data
- settings option: `openwpsecurity_loginprotection_settings`
- login events table: `{$wpdb->prefix}openwpsecurity_loginprotection_events`
- active lockouts option: `openwpsecurity_loginprotection_active_lockouts`
- lockout counts option: `openwpsecurity_loginprotection_lockout_counts`
- failed-login streak option: `openwpsecurity_loginprotection_failed_login_streaks`
- permanent bans option: `openwpsecurity_loginprotection_permanent_bans`

## Admin UI
- single left-menu item: `Login Protection`
- tabs:
  - `Dashboard`
  - `Activity`
  - `Settings`

## Important Current Behavior
- login lockouts are separate from firewall temporary blocks
- login permanent bans are separate from firewall permanent bans
- this plugin blocks the login flow, not the whole site
- temporary login lockouts show normal login errors on `wp-login.php`
- permanent login bans render `templates/blocked-permanent.php`

## Recent Work
- split login protection out of the firewall plugin into its own plugin
- renamed/moved code into `VictorWitkamp\\OpenWPSecurity\\LoginProtection`
- old `config/container.php` removed; DI definitions are now autoloaded from `src/Runtime/ContainerDefinitions.php`
- dashboard layout changed on March 27, 2026:
  - row 1: recent successful, failed, blocked logins
  - row 2: active lockouts, recent permanent bans
  - redundant per-panel total counters removed
- activity tab pagination was browser-verified on March 27, 2026, including filtered pagination

## Build / Check Commands
- `composer phpcs`
- `npm install`
- `npm run build`

## Browser Verification Artifacts
Temporary local artifacts were written outside the plugin during debugging:
- `c:\\inetpub\\victorwitkamp\\tmp\\codex-browsercheck\\loginprotection-activity.png`
- `c:\\inetpub\\victorwitkamp\\tmp\\codex-browsercheck\\pagination-click-report.json`
- `c:\\inetpub\\victorwitkamp\\tmp\\codex-browsercheck\\pagination-filtered-report.json`

## Open Follow-Ups
- do a manual in-browser admin polish pass on column widths after moving back toward native WordPress tables
- decide whether plaintext failed-password storage remains acceptable before open-sourcing
- keep reviewing legacy migration constants after more time on the renamed plugin
