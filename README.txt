=== Foundation Inkfire Login - Enterprise Gold ===
Contributors: Inkfire
Tags: login, branding, security, custom login
Requires at least: 6.0
Tested up to: 6.9
Stable tag: 2.0.28
Requires PHP: 7.4
License: GPLv2 or later

Enterprise-grade login customizer with automatic security, accessibility compliance, and zero maintenance.

== Description ==

Replaces the default WordPress login screen with the Inkfire two‑column layout (contact panel + login card). This plugin is designed for enterprise environments where security, accessibility, and strict branding are paramount. It completely hides the core WordPress login styling to ensure a consistent experience across Login, Register, Lost Password, and other authentication flows.

Key Features:

Enterprise Security: Built-in brute force protection (limiting attempts by IP) and CSRF checks on all forms.

Strict Branding: Enforces Inkfire brand colors (Teal/Pink) and assets, preventing theme bleeds.

Accessibility First: WCAG 2.1 AA compliant color contrast, focus states, and reduced motion support.

Zero Configuration: Works out of the box. No settings page to clutter the admin.

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
