# Foundation Inkfire Login

Enterprise-grade WordPress login customiser for Inkfire websites. Replaces the default
WordPress login screen with the Inkfire two-column layout (contact panel + login card)
across Login, Register, Lost Password, and related authentication flows.

Part of the Foundation plugin series by Inkfire Limited.

## Status

| | |
|---|---|
| Current version | 2.2.2 |
| Requires WordPress | 6.0+ |
| Tested up to | 6.9 |
| Requires PHP | 7.4+ |
| Licence | GPLv2 or later |
| Main file | `inkfire-login-styler.php` |
| Installed folder | `foundation-inkfire-login-styler` |

The installed plugin folder (`foundation-inkfire-login-styler`) differs from this
repository name (`foundation-login-plugin`). The release ZIP must contain a top-level
`foundation-inkfire-login-styler/` directory, or WordPress will install a second copy
alongside the existing one instead of updating it in place.

## What it does

- **Brand enforcement** — hardcoded Inkfire teal/pink palette and assets, immune to theme
  style bleeds. This is a "Gold Master" plugin: branding is deliberately not configurable
  so every client site stays consistent.
- **Brute force protection** — login attempts throttled by resolved remote address, with
  lockout expiry persisted in plugin-managed transients so countdowns behave correctly on
  sites using persistent object caches.
- **CSRF protection** — nonce verification on all authentication forms, with documented
  pass-throughs for WooCommerce lost-password, WP-CLI, and admin-triggered reset flows.
- **Accessibility** — WCAG 2.1 AA contrast, visible focus states, ARIA labelling, and
  reduced-motion support.
- **Operations dashboard** — Foundation → Inkfire Login provides audit activity, lockout insight, diagnostics and privacy-safe support reporting. The public login remains zero-configuration.

## Installation

1. Install the release ZIP via **Plugins → Add New → Upload Plugin**, or upload the
   `foundation-inkfire-login-styler` folder to `/wp-content/plugins/`.
2. Activate through the **Plugins** menu.
3. Done. The login page is styled automatically.

## Updates

The plugin bundles [Plugin Update Checker](https://github.com/YahnisElsts/plugin-update-checker)
and tracks GitHub releases on this repository. Update notices appear in the WordPress
dashboard exactly like a wordpress.org plugin.

Updates are **tag-based, not branch-based** — only published releases with an attached ZIP
asset are offered to sites. Draft releases are ignored.

### Release process

1. Bump the version header in `inkfire-login-styler.php` **and** the `Stable tag` in
   `README.txt`. These must match the release tag, or sites will never see the update.
2. Commit and push.
3. Create and push a tag (for example `v2.0.27`).
4. Publish a GitHub release against that tag with the plugin ZIP attached as an asset.

## Repository layout

```
assets/                   Front-end CSS, JS, and brand imagery
inc/                      Login rendering, security, and accessibility modules
plugin-update-checker/    Bundled updater library
README.txt                WordPress-format readme consumed by the updater
inkfire-login-styler.php  Plugin bootstrap
uninstall.php             Cleanup on uninstall
```

`README.txt` is the machine-readable readme the updater parses for version and changelog
data. This file is the human-readable one. Keep the changelog in `README.txt`.

## Why this repository is public

The updater resolves release assets without authentication when the repository is public,
avoiding the need to distribute a read-scoped GitHub token to every site running the
plugin. The code contains no credentials or client data.

## Source of truth

v2.2.1 is the published baseline. This v2.2.2 branch refines the login palette and must
pass its release gate before it is offered to client sites.

## Licence

GPLv2 or later. See [LICENSE](LICENSE).
