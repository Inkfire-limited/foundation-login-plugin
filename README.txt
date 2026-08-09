=== Foundation Inkfire Login - Enterprise Gold ===
Contributors: Inkfire
Tags: login, branding, security, custom login
Requires at least: 6.0
Tested up to: 6.9
Stable tag: 2.2.3
Requires PHP: 7.4
License: GPLv2 or later

Enterprise-grade login customizer with automatic security, accessibility safeguards, authentication audit logging and operational diagnostics.

== Description ==

Replaces the default WordPress login screen with the Inkfire two‑column layout (contact panel + login card). This plugin is designed for enterprise environments where security, accessibility, and strict branding are paramount. It completely hides the core WordPress login styling to ensure a consistent experience across Login, Register, Lost Password, and other authentication flows.

Key Features:

Enterprise Security: Built-in brute force protection (limiting attempts by IP) and CSRF checks on all forms.

Strict Branding: Enforces Inkfire brand colors (Teal/Pink) and assets, preventing theme bleeds.

Accessibility First: engineered toward WCAG 2.2 AA with robust contrast, visible focus, live-region feedback, touch-sized controls, reduced-motion support, and forced-colour fallbacks.

Operational Dashboard: Foundation > Inkfire Login shows recent logins/logouts, failed-login counters, lockouts, incidents and diagnostic health. Foundation > Login Diagnostics provides the full searchable log and settings. The branded login itself remains zero-configuration.

Auto-Updates: Integrated GitHub update checker for seamless delivery from your private or public repository.

== Installation ==

Upload the foundation-inkfire-login-styler folder to the /wp-content/plugins/ directory.

Activate the plugin through the 'Plugins' menu in WordPress.

The login page is automatically styled. No configuration needed.

== Frequently Asked Questions ==

= How do I update the plugin? =
The plugin includes a self-hosted updater. When a new release is available on GitHub, you will see an update notification in your WordPress Dashboard just like a standard plugin.

= How do I change the logo or colors? =
This is a "Gold Master" plugin with hardcoded branding to ensure consistency across all client sites. To change branding, you must modify the assets/ folder and inkfire-login-styler.php in the source code.

== Changelog ==

= 2.2.3 =

Design: Straightened the desktop left edge of the dark account panel where it meets the contact panel, while retaining the rounded standalone panel at tablet and phone widths.

= 2.2.2 =

Design: Removed the oversized background mark, matched the outer login canvas to Inkfire's animated hero gradient, and replaced the muddy account-side wash with a controlled dark-glass surface. The solid authentication card remains unchanged.

= 2.2.1 =

Fix: Constrained the Foundation dashboard grid so wide operational tables scroll inside their own regions instead of forcing the wp-admin document horizontally at narrower viewport widths.

Fix: Added a complete server-rendered dashboard fallback for JavaScript-disabled sessions, keyboard focus hand-off for section navigation, a stateful theme toggle, and reduced-motion safeguards.

Fix: Made Login Diagnostics responsive and labelled, added 50-row filtered event-log pagination, and require an explicit server-verified acknowledgement before an administrator can erase the full event log.

Fix: Retained the successful WordPress password-reset confirmation in the custom login shell instead of presenting a second, now-invalid reset form.

Design: Kept the contact panel and solid authentication card intact while making the surrounding account area translucent, strengthening the Inkfire watermark and adding a layered brand-tinted glass edge to the shell.

Security: Connected reset-form CSRF enforcement to WordPress core's `validate_password_reset` action; a missing or invalid form nonce is now rejected before the password is changed.

Security: Debug reports now expose only mail and DNS configuration status, not recipient addresses, raw DNS records or local mail-path details.

= 2.2.0 =

New: Replaced the former read-only Foundation admin shell with a working login operations dashboard. It now shows successful logins, failures, lockouts, incidents, recent authentication activity and diagnostic health.

New: Failed-login management groups recent username/IP pairs, shows the current brute-force counter and allows an administrator to reset only that temporary counter without altering the WordPress account or deleting audit history.

New: Added a privacy-safe downloadable debug report containing WordPress/PHP/plugin versions, active plugins, diagnostic state, cron state, authentication counts, incident metadata and mail/DNS configuration. It excludes event-row usernames, IPs, user agents, passwords, reset keys, cookies and nonces.

New: Added a working dashboard mail-test action and direct links to the complete searchable event log and diagnostics settings. Dashboard CTAs now use explicit destinations; the login preview uses WordPress reauthentication mode so it can be viewed while already signed in.

Design: Updated the public login screen with a 150px maximum Inkfire lockup, a light contact panel with dark brand text, a navy dark-glass authentication card, and the supplied Inkfire mark as a filtered low-contrast background watermark on the right. Contact details, social destinations, company details and authentication wording remain unchanged.

= 2.1.4 =

Design: Moved the existing WordPress language selector from the account side to the bottom of the left contact panel, without changing the selector, contact details, social links or authentication content.

= 2.1.3 =

Design: Centred each authentication title beneath the Inkfire lockup and outside the Pine Teal form surface.

Design: Removed the visual divider lines from the contact panel while preserving its wording, contact details, opening times, social destinations and company information.

Design: Moved the existing WordPress language selector to the bottom-right of the account side and increased breathing room above the logo and below the account controls.

Design: Replaced the previous notification colours with an orange-and-coral glass treatment using white text. A restrained dark overlay keeps normal-size notification text at WCAG AA contrast while retaining the supplied palette.

= 2.1.2 =

Design: Rebuilt the account area as a single Pine Teal glass login card, removing the previous green outer wrapper and dark nested card. Account links remain outside the form surface.

Design: Reduced the new Inkfire lockup and added 35-48px vertical breathing room around it across desktop and mobile layouts.

Accessibility: Added server-rendered and JavaScript-enhanced live-region semantics for authentication notices, reliable error focus, non-destructive duplicate-submit protection, invalid-field state handling, and an accessible password-strength meter.

Branding: Added the supplied transparent Inkfire WebP lockup and retained the existing side-panel content, contact details, social links, company details and language selector unchanged.

= 2.1.0 =

New: Authentication event log. Logins, failed logins, logouts, lockouts, registrations, password reset requests, completions and failures are recorded on this site, with a filterable viewer under Foundation > Login Diagnostics and an on-demand IP location lookup. Automatically pruned after 90 days. This data never leaves the site it was recorded on.

New: Automatic incident reporting. When the plugin itself malfunctions - mail failures, a burst of blocked security checks, password resets failing with no successes, or a fatal error inside the plugin - an alert is emailed with the site domain and full technical context, and a copy is kept on the site even if that email could not be delivered. Alerts are deduplicated, so a broken site reports once rather than continuously.

New: Mail diagnostics. A test-send button reporting exactly what the transport did, plus MX, SPF and DMARC inspection that flags the common failure where a domain's email is hosted externally but WordPress is sending through the local PHP mail() transport.

New: Diagnostics settings screen for recipient, alert thresholds and retention. Constants in wp-config.php override and lock any field, and IFLS_DISABLE_DIAGNOSTICS switches the whole feature off.

Fix: The login stylesheet is no longer loaded on every wp-admin page; it now loads only on this plugin's own screens.

Fix: Replaced the Font Awesome CDN with inline SVG icons. The login page no longer makes any third-party request, and the social links gained the accessible names the icon font never had.

Fix: Uninstall cleanup now works on sites using a persistent object cache, where transients never touch the options table and the previous direct SQL delete was a silent no-op.

Fix: Removed a no-op login_footer hook that removed nothing.

= 2.0.28 =

Fix: The branded "New password" form could never actually reset a password. It read the reset key from the URL, but WordPress moves that key into the `wp-resetpass-` cookie and strips it from the URL before the form is shown, so the hidden `rp_key` field submitted empty. Core's `hash_equals()` check then failed and users were bounced to "Lost password" with an `invalidkey` error, password unchanged. The key and login are now read from the cookie exactly as wp-login.php does, with the request used only as a fallback on the initial `action=rp` render. Present since 2.0.11. Forged and tampered reset keys are still rejected.

= 2.0.27 =

Fix: Stop the front-end CSRF check from rejecting WordPress core's own admin password-reset tools. The "Send Reset Link" button on user-edit.php and the "Send password reset" bulk action on users.php call retrieve_password() directly and never carry the plugin's login-form nonce, so both failed with "Security check failed." Core already protects each with its own nonce and an edit_user capability check; the plugin now defers to those and no longer double-checks. Front-end lost-password, register, and reset-password forms are unchanged and still require the plugin nonce.

= 2.0.26 =

Fix: Lock login throttling to the resolved remote address by default instead of trusting spoofable forwarded headers first.

Fix: Persist the lockout expiry in plugin-managed transients so countdown messages stay sane on sites using persistent object caches.

Fix: Add `rel="noopener noreferrer"` to public login-screen outbound links opened in a new tab.
= 2.0.25 =

New: Added a read-only shared Foundation shell dashboard while preserving the login styling and security runtime.

= 2.0.24 =

Fix: Replace removed `login_messages()` and `login_errors()` calls with a WordPress 6.9-compatible notice renderer so the branded login page no longer fatals.

Fix: Keep native login info and error notices visible inside the custom login card on current WordPress releases.

= 2.0.22 =

Fix: Restore the hidden WordPress `testcookie` field on the custom login form so successful logins complete reliably.

Fix: Surface core WordPress login messages and errors inside the branded login card instead of silently falling back to the hidden default form.

= 2.0.21 =

Fix: Allow WooCommerce lost-password requests to pass through without the custom IFLS nonce so customer password reset emails are not blocked.

Fix: Allow WP-CLI and admin-triggered password reset flows to run without tripping the front-end CSRF gate.

= 2.0.18 =

Fix: Critical fix for the "Confirm Admin Email" screen loop where the form would not submit or redirect correctly.

Fix: Resolved a Fatal Error conflict with Elementor Cloud Library (Status 403) during the admin email verification flow.

Fix: Implemented robust safe-redirect logic to ensure users are sent immediately to the dashboard after verifying their email.

Update: Disabled custom JavaScript execution specifically on the 'confirm_admin_email' action to ensure native form stability.

= 2.0.9 =

New: Added custom icon to the WordPress Plugins list for better recognition.

Fix: Resolved asset loading issues by strictly enforcing local paths for images and CSS.

Fix: Hardcoded brand colors to ensure immunity to theme style overrides.

= 2.0.8 =

Fix: Updated auto-updater logic to support Release Assets (ZIPs), fixing installation issues on nested repository structures.

Update: Removed branch tracking to strictly enforce stable Tag-based updates.

= 2.0.7 =

Update: Bumped version for updater testing.

= 2.0.6 =

Security: Added IP sanitization helper and improved nonce verification on all forms.

UX: Added real-time password strength meter and "Please wait..." loading states on buttons.

Accessibility: Added missing ARIA labels, improved focus indicators for social icons, and ensured WCAG 2.1 AA contrast compliance.

Dev: Added self-healing asset logic to fallback gracefully if files are missing.
