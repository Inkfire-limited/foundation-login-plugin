# Foundation Inkfire Login — Diagnostics, Audit Log & Incident Reporting

**Date:** 2026-08-06
**Status:** Approved design, pending implementation plan
**Target version:** 2.1.0 (minor bump — new feature, new DB table)

## Purpose

Two bugs shipped in this plugin went undetected for months because nothing reported them:

- **2.0.27** — the admin "Send Reset Link" button had been returning `Security check failed.` (HTTP 403). Discovered only when a client raised a support ticket.
- **2.0.28** — the branded reset form silently never changed anyone's password, bouncing users to `lostpassword&error=invalidkey`. **Present since 2.0.11, ~7 months.** Found only during a manual audit.

Both produced a loud, machine-detectable signal on the server. Nobody was listening. This feature listens.

It has two distinct jobs, deliberately kept apart:

1. **Give the client an audit trail** of authentication activity on their own site.
2. **Tell Inkfire when the plugin itself is malfunctioning**, on any of the 100+ sites it runs on.

## Non-goals

- Not a general security/firewall plugin. No blocking, no IP banning beyond the existing lockout.
- Not a WordPress-wide activity log. Authentication events only.
- Not a reporting channel for routine user error. A user typing the wrong email is the client's business.
- No charts, dashboards-with-graphs, or log export in v1.

## Architecture

Four units, each independently testable:

| Unit | Responsibility | Talks to |
|---|---|---|
| `IFLS_Event_Log` | Record and query auth events; prune | DB table |
| `IFLS_Incident_Reporter` | Detect malfunction, dedupe, store, email | Event log, mail |
| `IFLS_Mail_Diagnostics` | Test sends, inspect transport and DNS | PHPMailer, DNS |
| `IFLS_Diagnostics_Admin` | Settings screen, log viewer, incident list | The other three |

Each lives in its own file under `inc/`. The main plugin file only wires them up.

---

## 1. Event log (client-side, never transmitted)

### Table: `{prefix}ifls_events`

Created with `dbDelta()` on activation and on version upgrade.

| Column | Type | Notes |
|---|---|---|
| `id` | `BIGINT UNSIGNED AUTO_INCREMENT` | PK |
| `created_at` | `DATETIME` | **UTC**, indexed |
| `event` | `VARCHAR(32)` | indexed |
| `user_id` | `BIGINT UNSIGNED` | 0 when unknown |
| `username` | `VARCHAR(180)` | as submitted, sanitised |
| `ip` | `VARCHAR(45)` | IPv6-safe |
| `user_agent` | `VARCHAR(255)` | truncated |
| `outcome` | `VARCHAR(20)` | `success` / `failure` / `blocked` |
| `detail` | `TEXT` | JSON, no secrets |

Composite index on `(event, created_at)` — every query filters on both.

### Event taxonomy

`login_success`, `login_failed`, `logout`, `lockout`, `reset_requested`, `reset_completed`, `reset_failed`, `csrf_blocked`, `registration`

`detail` never stores passwords, nonces, reset keys, cookies, or auth tokens. Reset keys in particular must never be logged — a log leak would become an account-takeover vector.

### Retention

Daily cron `ifls_prune_events` deletes rows older than the configured retention (default **90 days**). Deletion is batched (`LIMIT 1000` per pass) so a site with a large backlog cannot exhaust `max_execution_time`.

### IP source

Reuses the existing hardened `get_client_ip()`, which prefers `REMOTE_ADDR` and only falls back to forwarded headers. Do not reimplement.

### Geolocation

**On demand only.** No third-party call ever happens during authentication. The log viewer renders a **Locate** control per row; clicking it performs a single server-side lookup for that one IP and caches the result in a transient keyed by IP.

Rationale: resolving on every event would place a third-party network call in the login path (a new way for logins to hang) and would systematically disclose the clients' end-user IPs to another company. Several clients are charities or public-sector-adjacent; that is a GDPR processor question, not merely a technical one.

---

## 2. Incident reporter (→ Inkfire)

### Triggers

| Trigger | Condition | Bug it would have caught |
|---|---|---|
| Mail failure | `wp_mail()` returns false, or `wp_mail_failed` fires | The base-uk.org delivery issue |
| CSRF storm | ≥5 `csrf_blocked` in 60 min | **2.0.27** |
| Reset failure storm | ≥5 `reset_failed` in 60 min **and** 0 `reset_completed` in the same window | **2.0.28** |
| Plugin fatal | Shutdown handler sees a fatal whose file is inside the plugin directory | Login-page white screens |
| Update failure | PUC's `puc_request_info_result-*` filter yields no usable result, or two consecutive scheduled checks return nothing | Sites stranded on old versions |

The "and 0 completions" clause on reset failures is what separates *users clicking stale links* from *resets are broken*. Without it this alert would be noise.

### Deduplication

Each incident gets a fingerprint: `sha1( type + normalised_reason )`. An incident whose fingerprint alerted within the **cooldown** (default 6 h) is counted against the existing incident rather than sent again. One broken site produces one email, not ten thousand.

### Ordering — important

**Store locally first, then queue the send. Never send inline.**

If the incident *is* mail failure, sending will fail; the local copy is the only record. Send status (`pending` / `sent` / `failed`) is recorded per incident, `failed` ones retry on cron, and any undelivered incident is surfaced at the top of the admin screen. The local store is both the requested "copy under the dash" and the fallback channel when email is the thing that's broken.

**Mail is never sent during an authentication request.** Incidents are written with status `pending` and dispatched by cron (or on `shutdown` after the response has been flushed). Sending inline would mean that on a site with slow or failing SMTP, every failed login blocks for the SMTP timeout — turning a reporting feature into an outage on precisely the sites whose mail is already broken. This constraint is not negotiable during implementation.

### Storage

Option `ifls_incidents` — a capped list (most recent **50**), not autoloaded. Volume is low by design; a table would be overkill.

### Email payload

Subject: `[Foundation] {domain} — {incident type}`

Body includes: site domain and URL, incident type, plain-English reason, first seen, last seen, occurrence count, plugin/WP/PHP versions, active theme, mail transport summary (mailer, From, Sender, SMTP auth), and **aggregate counts** of surrounding events.

**Design rule:** the email carries technical context and counts — **not** end-user IP addresses, usernames, or email addresses. Those remain in the client's own dashboard. This keeps client personal data on client infrastructure and keeps the cross-site channel free of PII. *(Explicitly considered and chosen over inlining IPs.)*

### Recipient

Default `webmaster@inkfire.co.uk`. Overridable — see precedence below.

---

## 3. Mail diagnostics

### Test send

A **Send test email** button (capability-checked, nonce-protected) that sends one message and reports:

- `wp_mail()` return value
- Any `wp_mail_failed` error
- PHPMailer `Mailer`, `Host`, `From`, `FromName`, `Sender` (envelope Return-Path), `SMTPAuth`

An empty `Sender` is worth flagging in the UI — it means WordPress set no envelope Return-Path, so SPF gets evaluated against whatever the host substitutes, which breaks DMARC alignment.

### Transport panel

`dns_get_record()` on the site domain showing **MX**, **SPF** and **DMARC**, with an explicit warning when the pattern that caused the base-uk investigation is present:

> MX points to an external provider (e.g. Microsoft 365) but mail is being sent locally via PHP `mail()`. Messages may be quarantined or rejected by the recipient.

DNS lookups are cached in a transient (1 h) and wrapped so a slow or failing resolver degrades to "unavailable" rather than hanging the admin page.

---

## 4. Settings page

A real settings screen (approved as an explicit departure from the plugin's zero-config principle), added as a **Diagnostics** subpage under the existing `foundation-by-inkfire` menu.

| Setting | Default |
|---|---|
| Enable event logging | on |
| Retention (days) | 90 |
| Enable incident reporting | on |
| Report recipient | `webmaster@inkfire.co.uk` |
| Failure threshold (count) | 5 |
| Threshold window (minutes) | 60 |
| Alert cooldown (hours) | 6 |

Stored as one non-autoloaded option `ifls_diagnostics_settings` (array), registered through the Settings API with an explicit `sanitize_callback`: recipient via `sanitize_email()` plus `is_email()` validation, numerics via `absint()` clamped to sane ranges, booleans cast.

### Precedence

`defaults` → `option` → `constant`

A defined constant (`IFLS_REPORT_EMAIL`, `IFLS_DISABLE_REPORTING`) always wins and renders the corresponding field read-only with an explanatory note, so a locked-down site can pin behaviour in `wp-config.php` and the UI tells the truth about it.

---

## Fail-safety — the primary safety control

This code executes on every authentication on every site the plugin runs on. It must be **architecturally incapable of breaking login**, even when it is itself broken. This matters more than any rollout strategy, because it is the control that holds when everything else has been got wrong.

1. **Every entry point is wrapped.** Each public logging/reporting call sits inside `try { … } catch ( \Throwable $e ) { }` which swallows and no-ops. A failure in this feature must never propagate into the authentication path.
2. **Always after, never before.** Logging hooks run after the auth action has completed. Nothing in this feature sits between a user and their login.
3. **Degrade to silence.** Missing table, failed query, unwritable option, absent cron — each results in "no logging", not an error. Absence of logs is an acceptable failure mode; a broken login screen is not.
4. **Kill switch.** `define( 'IFLS_DISABLE_DIAGNOSTICS', true )` in `wp-config.php` disables all logging, detection and reporting, checked before any other work. Recovery on a live site is one line and no database access.
5. **The fatal handler must not fatal.** The shutdown handler that detects plugin fatals is itself the riskiest component; it does the minimum possible work, guards every call, and never allocates significantly.
6. **No inline mail.** See the incident reporter section above.

## Security requirements

- Every admin screen: `current_user_can('manage_options')` **and** nonce verification on any state change.
- Settings saved through the Settings API with a sanitize callback — never raw `$_POST` into `update_option()`.
- All output escaped at the point of render (`esc_html`, `esc_attr`, `esc_url`). Log rows contain attacker-controlled data (username, user agent) and are the single most likely XSS vector in this feature.
- Log queries use `$wpdb->prepare()` throughout; `LIKE` filters pass through `$wpdb->esc_like()`.
- The log is never web-accessible: it lives in the database, not in a file under `wp-content`.
- Test-email recipient is not free-text from the request — it sends to the configured recipient or the current user, never to an address supplied in the POST body (otherwise the button becomes an open relay).

## Privacy

- Auth logging on the client's own site for security purposes is ordinary legitimate-interest processing; the data stays with the controller.
- The cross-site channel to Inkfire carries no end-user personal data by design (see design rule above).
- Retention is bounded and configurable.
- Because the log holds personal data, the viewer includes a **Clear log** control so a client can satisfy an erasure request.

## Testing

There is no multi-day canary, so the pre-release bar is correspondingly higher and the tests below are a **gate**, not a checklist to work through afterwards. They are automated where possible, so they can be re-run on demand rather than depending on someone remembering to click through a flow.

Before tagging:

0. **Fail-safety is proven, not assumed.** With the events table deliberately dropped, and again with it renamed to something unwritable, login/logout/reset must all still work normally. This is the single most important test in the list: it is what makes the no-canary rollout defensible.

1. Table creation and upgrade path — activate, deactivate, reactivate, upgrade from 2.0.28; confirm no duplicate-table or column errors.
2. Every event type fires exactly once per real action (verified against live HTTP flows, not just unit-level calls).
3. Threshold logic: 4 failures must **not** alert; 5 must. Reset-failure alert must stay silent when a completion occurred in the window.
4. Dedup and cooldown: 100 identical failures produce exactly one email.
5. Mail-failure path: with mail forced to fail, the incident must still be stored locally and marked undelivered.
6. Pruning removes only rows past retention, and survives a large backlog without timing out.
7. Settings sanitisation rejects a malformed email, negative numbers, and absurd retention values.
8. XSS: a username and user agent containing `<script>` must render escaped in the viewer.
9. The existing 12-scenario CSRF matrix and the password-reset flow both still pass.
10. Login page renders unchanged, and login latency is not measurably affected.

## Rollout

The decision is to reach every site, not to run a multi-day canary. The safety a canary would have bought is bought instead by **load** and **ordering**, both of which can be had in about an hour.

### Baseline first

Bring the five stragglers (`catlawless.com` 2.0.11, `gsoasatellite.com` / `sakaradee.co.uk` / `sandhurstfire.co.uk` 1.8.1, `wendycarltonart.co.uk` 2.0.20) up to 2.0.28 **before** this feature ships, so every site upgrades from one known baseline. `catlawless.com` matters most — it still carries the broken reset form and will not self-heal.

### Load-based canary, not time-based

Deploy to `thatdeveloper.co.uk` and `inkfire.co.uk`, then *drive* traffic rather than waiting for it: a few hundred synthetic logins, failed logins, lockouts, reset requests and reset failures pushed through in minutes. This exercises thresholds, dedup, cooldown and pruning far harder than a week of organic traffic on a quiet site, and produces the evidence immediately.

Assert afterwards: correct row counts, exactly one alert email per fingerprint, no duplicate tables, no PHP notices, and login latency unchanged.

### Tested rollback, before shipping

Prove the rollback works *before* it is needed — reinstall 2.0.28 over 2.1.0 on a dev site and confirm the site is healthy. The rollback command is a single `wp plugin install <2.0.28-release-url> --force`. The events table is intentionally left in place on rollback: dropping user data during an emergency is the wrong default, and an orphaned table is harmless.

### Waves, not one push

Same session, ~20 minutes, health sweep between each:

1. Dev sites — `thatdeveloper.co.uk`, `inkfire.co.uk`
2. Low-traffic clients
3. Remaining clients, `base-uk.org` last

A mistake that escapes the canary then reaches two sites, not twenty-three.

### Automated post-deploy sweep

Across every site: plugin version, table exists, `wp-login.php` returns 200 with the nonce present, reset flow completes, no new PHP fatals, and event row count is non-zero but not runaway. Any failure halts the remaining waves.
