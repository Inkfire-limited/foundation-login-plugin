# Login defense rollout

Foundation's origin throttle is a containment layer. It cannot protect shared
hosting resources from a request that has already started PHP and WordPress.
Every production rollout therefore needs an application gate and, wherever
the host permits it, a pre-WordPress traffic gate.

The **Foundation → Inkfire Login → Security** section reports these layers as
red, amber or green. Foundation-owned controls are detected automatically.
Edge and server controls must be verified by an administrator after testing;
the stored greenlight is tied to the current hostname and expires after 90
days. A greenlight records evidence only—it does not configure Cloudflare,
NGINX, LiteSpeed or Fail2ban.

## Gate 1: reject abusive traffic before WordPress

Cloudflare is the preferred shared-hosting route, but it is not a plugin
dependency. A site without Cloudflare can satisfy this gate with a tested
reverse-proxy WAF, NGINX `limit_req`, LiteSpeed per-client throttling, or a
Fail2ban jail on a server the operator controls. Foundation cannot prove those
external rules from PHP; test them against access logs, then record the result
in the Security dashboard.

### Cloudflare route

Start with a Managed Challenge custom WAF rule for login submissions:

```text
(http.request.uri.path eq "/wp-login.php" and http.request.method eq "POST" and not cf.client.bot)
```

On a Free zone, add the single available rate-limiting rule for the same path
and method. The available Free-plan window and mitigation duration are short;
use the dashboard's permitted values rather than assuming paid-plan controls.

Deploy rules in challenge/block mode only after confirming legitimate admin,
WooCommerce My Account, password-reset, WP-CLI, uptime-monitoring, and any SSO
journeys. Review Cloudflare Security Events after deployment. Never bulk-block
an address range merely because one address generated a Foundation 429.

## Gate 2: select one failed-login telemetry owner

Foundation and AIOS both observe `wp_login_failed`. AIOS 5.4.9 also captures a
PHP stack trace for each audit row, so duplicate logging becomes expensive
during credential-stuffing waves.

The release default is deliberately non-disruptive:

```php
define('IFLS_AUTH_TELEMETRY_OWNER', 'coexist');
```

After proving Foundation diagnostics, retention cron, reporting, and incident
handling on the target site, opt in through `wp-config.php`:

```php
define('IFLS_AUTH_TELEMETRY_OWNER', 'foundation');
```

This suppresses only AIOS `failed_login` audit rows. It does not disable AIOS,
its firewall, honeypot, two-factor authentication, file protections, or other
audit events. Do not enable AIOS Login Lockdown at the same time as Foundation's
throttle unless the combined user-lockout behaviour has been deliberately
tested.

## Verification

1. Snapshot the database and current Cloudflare/AIOS configuration.
2. Test on a representative staging clone; do not use an unrelated archive.
3. Confirm a valid login, invalid login, logout, lost-password request, reset,
   WooCommerce account login, and administrator-triggered reset.
4. Send five invalid attempts for one identity/address; the next request must
   return 429 with `Retry-After`, and Foundation must store one lockout event.
5. Rotate usernames from one address; the address-wide threshold must block.
6. Confirm forwarded headers cannot change the observed address at origin.
7. Run a bounded burst through Cloudflare and prove most rejected requests do
   not reach origin access logs, PHP, AIOS, or Foundation.
8. Confirm cron pruning, table growth, database query time, PHP errors, and
   Cloudflare Security Events after 24 and 72 hours.

## Rollback

Disable or remove the new Cloudflare rules first if legitimate users are being
challenged. Restore `IFLS_AUTH_TELEMETRY_OWNER` to `coexist` to re-enable AIOS
failed-login rows. Roll back the plugin through the previous signed release
asset after verifying its checksum; do not delete authentication evidence as
part of application rollback.
