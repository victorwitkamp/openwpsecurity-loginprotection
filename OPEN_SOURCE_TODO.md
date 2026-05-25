# Open-Source Preparation TODO

Status on March 22, 2026:

- The plugin is already renamed to `OpenWPSecurity - Login Protection`.
- Composer, npm, PHPCS, CI workflows, and release packaging are present.
- The GitHub/source repo is currently source-first, not install-from-GitHub ready.

## High Priority Before Publishing To GitHub

- Add a real `README.md` for GitHub.
  It should explain what the plugin does, what data it stores, and how to build it from source.
- Add a top-level `LICENSE` file.
- Add `SECURITY.md`.
- Add `CONTRIBUTING.md`.
- Add `CODE_OF_CONDUCT.md`.
- Add GitHub issue templates and a PR template.
- Replace the current `Plugin URI` and `Author URI`.
  They still point to the production site. Use canonical project URLs or repository URLs instead.

## Repo Hygiene

- Decide whether the repository is source-only or installable as-is.
  Right now `.gitignore` excludes `vendor/`, `node_modules/`, and generated `assets/css/`, so a GitHub clone needs build steps before it is usable.
- If the repo stays source-only, document the exact commands:
  `composer install`
  `npm install`
  `npm run build`
- Keep the legacy migration constants, but document that they exist only for upgrade import from the old private/internal plugin names.

## Security And Privacy Review

- Keep plaintext failed-password storage as an intentional analysis feature.
  The `password_value`, `password_mask`, and `password_hash` fields should support reports that correlate repeated password attempts with IPs, countries, usernames, and time windows. Because these are sensitive login-event records, document the behavior clearly, keep retention configurable, and make any admin UI exposure explicit.
- Document exactly which login events are stored:
  successful logins
  failed logins
  blocked logins
  lockout creation
  permanent ban creation
- Add or finish internationalization for user-facing strings.
- Decide uninstall behavior and add `uninstall.php` if data cleanup on uninstall is desired.
- Add a short privacy note that explains retention, login-event storage, and permanent-ban storage.

## WordPress.org Readiness Later

- Review `readme.txt` against the WordPress.org parser and submission expectations.
- Prepare plugin assets: icon, banner, screenshots.
- Re-check all headers, tested-up-to values, and support links.

## Login Protection-Specific Follow-Up

- Keep shared infrastructure aligned with `openwpsecurity-firewall`.
  The first shared extraction is `VictorWitkamp\OpenWPSecurity\Core\Http\IpAddressInspector` in `../openwpsecurity-core`, consumed through a Composer path repository that junctions `vendor/openwpsecurity/core` to the shared package.
- Review whether login lockouts, failed-login streak bans, and permanent bans are explained clearly enough in the admin UI and docs.
- Add password-attempt analysis reports:
  reused attempted passwords across many IPs
  many passwords attempted by one IP
  same password attempted against many usernames
  country and user-agent distribution per attempted password
  time-window trends for repeated password attempts
- Decide how attempted passwords should be displayed in the admin UI.
  Prefer masked values by default, with an explicit reveal action/capability for plaintext values.
- Add explicit documentation for retention and cleanup of login-event data.

## Sources

- WordPress header requirements: https://developer.wordpress.org/plugins/plugin-basics/header-requirements/
- WordPress readme rules: https://developer.wordpress.org/plugins/wordpress-org/how-your-readme-txt-works/
- WordPress detailed plugin guidelines: https://developer.wordpress.org/plugins/wordpress-org/detailed-plugin-guidelines/
- WordPress software license guidance: https://developer.wordpress.org/plugins/plugin-basics/including-a-software-license/
- WordPress uninstall methods: https://developer.wordpress.org/plugins/plugin-basics/uninstall-methods/
- WordPress plugin assets: https://developer.wordpress.org/plugins/wordpress-org/plugin-assets/
- GitHub READMEs: https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-readmes
- GitHub licenses: https://docs.github.com/en/communities/setting-up-your-project-for-healthy-contributions/adding-a-license-to-a-repository
- GitHub contributor guidelines: https://docs.github.com/en/communities/setting-up-your-project-for-healthy-contributions/setting-guidelines-for-repository-contributors
- GitHub code of conduct: https://docs.github.com/en/communities/setting-up-your-project-for-healthy-contributions/adding-a-code-of-conduct-to-your-project
- GitHub security policy: https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/configure-vulnerability-reporting/adding-a-security-policy-to-your-repository
- GitHub issue and PR templates: https://docs.github.com/en/communities/using-templates-to-encourage-useful-issues-and-pull-requests/about-issue-and-pull-request-templates
