# Known issues

Findings from a code audit plus an end-to-end run of a real `warden serve`
instance driven through Chromium with a real WebAuthn authenticator (setup,
user creation, invite capture, invite registration, admin login, dashboard).

Status legend: **Fixed** = changed in this pass, **Open** = documented but not
changed yet, **By design** = confirmed intended behaviour.

## Bugs

### 1. Invite registration always fails in the browser — Fixed

`warden/templates/static/invite.js` passed the raw JSON ceremony options
straight to `navigator.credentials.create({ publicKey: data.publicKey })` and
then serialised the resulting `ArrayBuffer`s by putting them into a JSON object.

* `challenge`, `user.id` and `excludeCredentials[].id` arrive base64url-encoded,
  so the browser throws `Failed to read the 'challenge' property ... not of type
  '(ArrayBuffer or ArrayBufferView)'` before any authenticator is touched.
* Even with the options converted, `JSON.stringify` turns the response buffers
  into `{}`, so the server can never verify the attestation.

The page loaded only `invite.js`, while the working helpers live in `warden.js`.
`invite.js` now uses `Warden.prepareCreationOptions()` and
`Warden.serializeRegistration()` (already loaded by `auth_base.html`) and reports
unsupported/blocked passkeys through `Warden.friendlyPasskeyError()`.

### 2. Server-rendered form POSTs rejected with 403 — Fixed

Chromium sends `Origin: null` on same-origin form submissions when the page is
served with `Referrer-Policy: no-referrer` (which Warden sets on every
response). `check_origin()` treated every `null` origin as cross-site, so
`POST /backup_codes/generate` (and any other plain `<form method="post">`)
returned `403 {"detail":"Cross-origin request blocked."}`.

`check_origin()` now accepts `Origin: null` only when `Sec-Fetch-Site` is
`same-origin` or `none`. That header is set by the browser and cannot be forged
by a cross-site page, and browsers that do not send it still get the old
rejection.

### 3. Non-admin invitees land on a JSON 401 — Fixed

`invite_complete()` always redirected to `admin_url()`, but the admin host is
admin-only, so a freshly registered non-admin saw
`{"detail":"Admin access required."}`. The redirect now sends non-admins to the
admin host root, and the middleware renders an HTML explanation page there
instead of JSON for navigation requests, with a working sign-out button.

### 4. `reset-clients` reported success while doing nothing — Fixed

`warden/admin/routes.py` called `_app.state.proxy.reset_clients()` without
`await`, emitting `RuntimeWarning: coroutine ... was never awaited` and returning
`200` before any client was closed. Now awaited.

### 5. The last admin can be demoted — Fixed

`PATCH /_warden/api/users/{id}` with `{"is_admin": false}` had no guard, so the
only admin account could lose dashboard access, locking everyone out.
`update_user()` now returns `400` when the change would leave zero admins.

### 6. `?since=` on the activity page is parsed but ignored — Fixed

`activity_page()` read the `since` query parameter, handed it to the template,
and then queried audit rows without it. `list_audit()` now accepts `since` on
both the SQLite and PostgreSQL backends, and the page passes it through.

### 7. PostgreSQL `list_audit()` ignores `offset` — Fixed

`GET /_warden/api/audit/export?offset=...` passes `offset` to `list_audit()`,
but the PostgreSQL implementation only accepted `limit` and `event`, so
pagination raised `TypeError` on a Postgres deployment. The signature now
matches the SQLite backend.

### 8. Per-route rate limits are global, not per client — Fixed

`ProxyEngine._per_route_rate_limit()` keyed its window on
`host:upstream` only, so one busy client exhausted a route's `rate_limit` for
everyone. The key now includes the client IP, which is already available in the
scope at the call site.

### 9. Saved configuration does not take effect at runtime — Fixed

`app.state.config` and `database.config` were captured once at startup.
`POST /_warden/api/config` and `/config/import` replaced `manager.config` but
left both stale copies in place, so anything reading them (mail settings, the
database vacuum threshold) kept using the old values until a restart. Both save
paths now refresh `app.state.config` and `app.state.db.config`.

### 10. Invite email test failure — Fixed

`tests/test_admin_security.py::test_create_invite_sends_email` asserted
`send_email` was called with keyword arguments, while the route passed them
positionally, producing `KeyError: 'to'`. The route now calls `send_email` with
`to=`, `subject=` and `body=`, matching the documented contract.

### 11. Test suite hangs at exit — Fixed

`tests/test_admin_security.py::test_non_admin_denied_on_admin_host` opened a
second `Database` and called `db.close()` without `await`, leaving an aiosqlite
worker thread alive so `pytest` never exited (the tests themselves reported
`passed`). Now awaited; the suite exits normally.

### 12. CSP blocks the webfont the templates load — Fixed

Every page links `fonts.googleapis.com`/`fonts.gstatic.com`, but the CSP
shipped `style-src 'self' 'unsafe-inline'` and `font-src 'self'`, so the
stylesheet was blocked and the UI silently fell back to a system font. Both CSP
copies (`utils.apply_security_headers` and the middleware header injection) now
allow only 'self'. JetBrains Mono is now self-hosted from
`/_warden/static/fonts/` (6 variable woff2 subsets), so no third-party
requests remain.

## Unfinished functionality

### 13. ACME issuance is unreachable — Fixed

Fixed: the manager stored the bare challenge token and served that instead of
the key authorization the CA requires; it now computes
`HTTP01.key_authorization()` during the order and serves that. The in-memory
responses are now reachable: `main.py` serves them from the challenge route when
`acme_webroot` has no file, the HTTP→HTTPS listener does the same, and the ACME
manager is attached to the proxy (the intended bridge line was missing).
Issuance is wired to the renewal loop through the new opt-in
`tls.acme_directory` / `tls.acme_domain` settings, so an expiring certificate
can be replaced in-process and the dashboard reports `restart_required`.

Still needs attention: the first certificate cannot be obtained this way,
because startup requires a readable certificate before the TLS listener starts
(`validate_runtime_files`). `warden certs bootstrap` now writes a self-signed
placeholder at the configured `certfile`/`keyfile` paths for exactly that gap
(`--force` to replace an existing pair), so the flow is: bootstrap → start → the
renewal loop completes HTTP-01 over the plain HTTP companion → restart to serve
the real certificate.

A self-signed certificate does **not** help the ACME exchange itself: HTTP-01 is
validated over plain HTTP on port 80, and the CA never inspects the presented
certificate. It only answers "the process cannot boot without one". The
remaining hard requirement is therefore unchanged: the CA must be able to fetch
`http://<domain>/.well-known/acme-challenge/<token>` on port 80 (forwarded from
the internet, and not blocked by the ISP). Without that, the fix is DNS-01
issuance, which is not implemented.

The flow is covered by unit tests with a mocked ACME client and by CLI tests for
the bootstrap path, and has since been exercised end to end against a local
Pebble directory (see `ROADMAP.md` §2; rerun with
`python scripts/pebble_issuance.py`). That run found three defects the mocks
had hidden — an `acme` 5.x client argument, the challenge published under the
raw token instead of its base64url encoding, and a `Status` enum compared to a
string — all fixed; the CA then validated the challenge and the renewal loop
wrote a chain issued by `CN=Pebble Intermediate CA …` with `restart_required`
set.

### 14. WebAuthn RP ID does not cover service subdomains — Fixed via warning

An invitee signing in at `app.localhost` with `rp_id: localhost` gets
`SecurityError` (shown as "This domain isn't allowed to use passkeys"). Chrome
only accepts an RP ID that is the origin's host or a registrable domain suffix,
and `localhost` is special-cased to the bare host, so this cannot be fixed in
Warden — it is a configuration rule.

`main.host_coverage_warnings()` now runs at startup and logs two warnings:
when a single-label RP ID cannot cover a route host, and when a route host
differs from the admin host while `server.cookie_domain` is unset (the session
cookie is host-only, so users must sign in again on each host).

### 15. Mesh configuration must exist before first start — Fixed

`ConfigManager.validate_startup()` used to raise `ConfigError: Mesh config not
found` when `mesh.enabled` was true and `mesh.config_path` did not exist yet,
even though the mesh page writes that file on the first `apply()`. Startup now
only requires the parent directory to exist (it is created when possible) and to
be writable; the missing file is logged as an informational message and is
written by the first apply.

### 16. No landing page for signed-in non-admins — Fixed

Non-admins now get `GET /portal` on the admin host: a grid of every enabled
route with its hostname, a public/passkey badge, and an absolute link (scheme
and port included), plus links to their own passkeys, sessions, and backup
codes. Visiting `/` redirects there, and the 403 page for other admin paths
points at it.

Only three admin-host pages and two user-scoped API groups are opened up to
non-admins (`/portal`, `/passkeys`, `/backup_codes`, `/_warden/api/passkeys*`,
`/_warden/api/sessions*`); each already resolves the target user from the
session. State-changing requests on those paths keep the same
`X-Warden-Request` header and origin checks as the admin UI. The portal now
lists only the routes whose group ACL admits the signed-in user; routes without
an ACL keep admitting everyone, so nothing changes for instances that never
configure a group. Per-route ACLs are implemented in item 35.

### 17. "Add service" opened nothing — Fixed

`base.html` rendered `{% block content %}`, `{% block scripts %}`, and
`{% block head_extra %}`, but never `{% block modals %}`. Templates that put
their dialogs in that block (`dashboard.html`, `passkeys.html`, `mesh.html`)
were silently discarded, so `#service-modal-overlay` was not in the DOM. The
click handler then read `title.textContent` on a null node and threw before
opening anything — from the user's side the button simply did nothing. The
passkey and mesh dialogs were missing the same way.

`base.html` now renders the block before the shared confirm dialog. A template
regression test asserts the dashboard/passkey dialogs ship in the HTML, and the
browser E2E clicks **Add service** and waits for the form to become visible.

## Second audit pass

A read-through of the commits above looking for defects the suite does not
cover. Every item below is fixed and tested.

### 18. Per-route rate-limit windows leaked one entry per client IP — Fixed

`_per_route_rate_limit()` gained the client IP in its key (#8), but the cleanup
at the end of the method only removed windows that were *empty* — which never
happens, because a window always holds at least the sample just appended. Every
distinct source address therefore stayed in `_rate_windows` for the life of the
process, and the sweep walked the whole dict on every allowed request.

A new `_prune_rate_windows(cutoff)` drops windows whose newest sample is older
than the 60-second cutoff. It runs only when the table exceeds
`_RATE_WINDOW_MAX_KEYS` (4096), so the common path stays O(1). Covered by
`test_per_route_rate_limit_is_per_client` and
`test_per_route_rate_limit_prunes_stale_windows`.

### 19. ACME authorization polling had no deadline — Fixed

`_run_acme_flow()` polled the CA in `while True: net.poll(authz); time.sleep(2)`.
A challenge that stayed `pending` — a stuck CA, a firewall eating the validator's
request, an order the CA abandoned — pinned the worker thread
(`asyncio.to_thread`) forever and stalled every later renewal with no error.

Extracted `_wait_for_authorization()` with `ACME_AUTHZ_TIMEOUT = 300s`; it raises
`TLSError` on rejection or timeout. Covered by `TestWaitForAuthorization`
(valid, invalid, timeout) in `tests/test_tls_comprehensive.py`.

### 20. Expired ACME challenge tokens were never evicted — Fixed

`get_challenge_response()` returned `None` for an expired token but left the
entry in `_tokens`, so the store grew by one entry per renewal indefinitely. It
now pops expired entries on read; `test_challenge_token_expired` asserts the
token is gone.

### 21. `Origin: null` accepted for `Sec-Fetch-Site: none` — Fixed (narrowed)

The referrer-policy quirk in #2 makes Chromium send `Origin: null` on a
**same-origin** form post, which is what the exception is for. `none` (a
user-initiated navigation) was also accepted without need, widening the CSRF
exception. `check_origin()` now accepts `Origin: null` only with
`Sec-Fetch-Site: same-origin`; `tests/test_utils.py` asserts `none` is rejected.

### 22. `?since=` was unusable — Fixed

`activity_page()` parsed `since` and passed it to the query (#6), but nothing in
the UI ever set it, and the hidden field rendered the literal string
`value="None"` when unset. `/activity` now renders 24h / 7d / 30d / all range
links (server-rendered anchors, since the CSP blocks inline handlers) that
preserve the event filter, and the hidden field is emitted only when `since` is
set.

### 23. Last-admin demotion guard was check-then-act — Fixed

`update_user()` counted admins with `list_users()` and then demoted in a second
statement, so two concurrent requests could both see two admins and leave zero.
Both backends gained `demote_admin()`, which puts the guard inside the UPDATE
(`... WHERE id = ? AND (SELECT COUNT(*) FROM users WHERE is_admin = 1) > 1` for
SQLite, a counted scalar subquery for PostgreSQL).

### 24. Audit ordering differed by backend — Fixed

SQLite ordered by `created_at DESC`; PostgreSQL ordered by `id DESC`. With
`offset` pagination the two disagreed. SQLite now uses
`ORDER BY created_at DESC, id DESC` and PostgreSQL orders by
`created_at.desc(), id.desc()`.

### 25. Mesh directory writability check was a no-op as root — Fixed

`os.access(parent, os.W_OK)` reports writable for root regardless of mode, so
the check in `validate_startup()` could not fail on a root-run container. It is
replaced with a temporary-file probe in the directory. The `mkdir` that precedes
it remains intentional startup behaviour (see #15).

### 26. Health-monitor test left an un-awaited coroutine — Fixed

`tests/test_health_adapter_comprehensive.py` set
`mock_client.aclose.return_value` to a coroutine object, producing
`RuntimeWarning: coroutine ... was never awaited` in every run. The mock now uses
AsyncMock's default awaitable; the suite runs clean under
`-W error::RuntimeWarning`.

### Correction: cookie_domain coverage warning was not missing

An earlier draft of this pass claimed `host_coverage_warnings()` needed a third
case for a `server.cookie_domain` that is not a parent of a route host. It does
not: `parse_config_text()` already rejects that configuration with
`routes[i].host (...) is outside server.cookie_domain (...)` (#config validation,
`warden/config.py`). The startup warning covers only the unset case, which is
reachable.

## Third audit pass

Another read-through of the request path, aimed at what the suite mocks away:
the deployed cookie name, the non-default rate-limiter backend, the WebSocket
edge, and the metrics text an operator actually scrapes.

### 27. Warden forwarded its own session cookie to every upstream over HTTPS — Fixed

`strip_reserved_cookies()` matched only `warden_session` and
`warden_challenge`, but `session_cookie_name()` renames the session cookie to
`__Host-warden_session` whenever `Secure` is in play (every HTTPS deployment).
The real name therefore survived the filter and the proxy sent the admin's
session token to every upstream service in its `Cookie` header, where the app,
its access log, or a bug in it could expose it. `_rewrite_set_cookie()` had the
mirror bug: an upstream `Set-Cookie: __Host-warden_session=…` was passed to the
browser instead of dropped.

Both sides now use `utils.is_reserved_cookie()`, which removes the
`__Host-`/`__Secure-` prefix before comparing. Covered by
`test_strip_reserved_cookies_handles_browser_prefixes` and
`test_proxy_rewrite_set_cookie_drops_prefixed_session_cookie`.

### 28. `rate_limiter.backend: redis` broke every auth endpoint — Fixed

`auth/routes._limited()` unpacked `limiter.allow(...)` synchronously, but
`RedisRateLimiter.allow` is a coroutine. With the Redis backend configured,
every sign-in, setup, invite, passkey and OTP POST raised
`TypeError: cannot unpack non-iterable coroutine object` (a 500), and no attempt
was ever counted — the configured limit silently did not exist. `_limited()` is
now async and awaits the result only when it is awaitable, and its ten call
sites await it. `test_auth_routes_await_async_rate_limiter` installs an async
limiter and expects a 429 with rate-limit headers rather than a 500.

The limiter itself is now covered too: `test_redis_rate_limiter_enforces_window`
checks per-key windows and the pruning of expired entries, and
`test_redis_backed_limiter_blocks_login_after_limit` drives the real
`RedisRateLimiter` through `/_warden/auth/login/begin` until it refuses
the request; both use the in-memory fallback, so no server is needed.

`tests/test_rate_limiter_redis.py` additionally runs against a real server when
`WARDEN_TEST_REDIS_URL` (default `redis://localhost:6379/0`) answers — limit,
TTL, server-side pruning and the endpoint block are all asserted on the keys
Warden wrote — and the CI workflow starts a `redis:7` service. Without a server
those three tests skip, so a plain `pytest` still passes.

### 29. WebSocket upgrades bypassed IP allow/deny lists — Fixed

`RouteConfig.allowed_ips`, `denied_ips`, `blocked_user_agents` and
`blocked_paths` were enforced only in `handle_http()`, so a route restricted to
an office network could be reached from anywhere by opening a WebSocket to the
same host — and `blocked_paths` did not stop an upgrade to a blocked path.

Those rules are now three shared helpers (`_ip_denial`, `_user_agent_denial`,
`_path_denial`) called by both the HTTP and WebSocket paths; a denied upgrade is
accepted and closed with `4403 Access denied`. Covered by
`test_proxy_access_denials_cover_ws_rules` and
`test_websocket_respects_ip_allow_list`.

### 30. Mesh handshake metric made the whole scrape invalid — Fixed

`GET /_warden/metrics` appended
`warden_mesh_last_handshake_seconds{peer=\"<key>\"} <ts>` — literal backslashes
before the quotes, because an f-string was written with escaped quotes inside a
non-raw string. Prometheus rejects a scrape containing that line, so any
instance with mesh peers lost all metrics, not just this one. The label is now
built with `stats.escape_label()`, which is also used for the per-host labels.

### 31. Backup-code sign-in dropped the `next` target — Fixed

`/_warden/auth/login/backup` always redirected to `/`, so a user who opened a
protected service, followed the sign-in redirect, and then chose a recovery
code lost the page they asked for. `BackupCodeBody` gained an optional `next`,
sanitised through `safe_next()` like the passkey flow.

### 32. TOTP is implemented everywhere except enforcement — Fixed

`otp_secrets`, `set_otp_secret()`/`verify_otp()`, `/otp/setup`, `/otp/verify`
and the `warden_otp_*` metrics all exist and work, but `login_complete()` never
asks for a code and no page offers enrolment, so the only way to reach the
endpoints is by hand. `otp_setup()` also stores the new secret before it is
verified. Fixed: enrolment now stores the new secret as *pending* and only
promotes it to the active secret after a successful verification, so an
abandoned flow leaves the previous (working) secret untouched. Login
enforcement is now implemented: `login_complete` issues a short-lived
`login_otp` challenge when the user has TOTP enrolled, and
`/_warden/auth/login/otp` verifies the code before issuing a session.

### 33. IPv4-mapped IPv6 clients escaped (or failed) per-route IP ACLs — Fixed

A dual-stack listener reports an IPv4 client as `::ffff:192.168.1.5`, and
`ipaddress` will not match that address against `192.168.1.0/24`. An
`allowed_ips` route therefore refused the very clients it was meant to admit,
and a `denied_ips` route let a blocked host in whenever it arrived over IPv6.
`_ip_denial()` now unwraps `ipv4_mapped` before matching, so both lists compare
as IPv4. Covered by `test_proxy_ip_denial_unwraps_ipv4_mapped_addresses`.

### 34. `blocked_paths` could be dodged with dot segments — Fixed

The check compared the raw request path, but the proxy forwards that path
untouched and upstream servers normalise it: `/public/../secret`, `/./secret`,
`//secret` and `/secret/` all reached a blocked `/secret`, and
`/admin/./users` reached `/admin/users`. `_path_denial()` now normalises both
the request path and each configured pattern — collapsing `.`/`..`, duplicate
and trailing slashes — before comparing; `/*` still blocks everything. Covered
by `test_proxy_path_denial_normalizes_dot_segments`,
`test_handle_http_blocked_path_cannot_be_dodged` and
`test_websocket_respects_blocked_paths`.

Two remaining ACL caveats, left as documented behaviour: path matching is
case-sensitive (a case-insensitive upstream can still differ), and the client
address is the socket peer, so deploying Warden behind another proxy makes
every request appear to come from that proxy (allow-lists then fail closed).

### 35. Per-route ACLs did not exist — Implemented

`RouteConfig` only had IP/user-agent/path rules; there was no way to say "this
account may open this host". The portal therefore advertised every route to
every signed-in user. There are now named ACL groups in the database
(`acl_groups`, `acl_members`, schema version 6), and every account joins the
built-in `Users` group when it is created — whichever path creates it
(`create_user`, first-run setup, or invite completion).

A route opts in with `allowed_groups: [Family]`. An empty list is the default
and keeps the route open to every signed-in user, so ACLs are never required.
Admins bypass group ACLs. The check is shared by `handle_http` and
`handle_websocket` (``ProxyEngine._group_denial``) so a WebSocket cannot be used
to skip a route ACL, and `/portal` filters on the same `RouteConfig.allows_user`
rule. Group names are case-insensitive and whitespace-normalised. Covered by
`tests/test_acl_groups.py`.

### Minor cleanups in this pass

Dead `finally: pass` in the proxy's HTTP path, a duplicated `logger` line and a
mid-file import in `health_adapter.py`, an audit query whose result was thrown
away on the dashboard, three routes calling `_guard_host()` twice, and the
invite email building its link from `request.url.scheme`/`netloc` instead of
`admin_url()` (wrong behind a TLS-terminating proxy).

## Fourth audit pass

A read of the deployed request path again, this time aimed at the two pieces of
work that were mid-flight (TOTP enforcement and the metrics scrape token) and at
the rules that decide whether a request is authenticated at all.

### 36. `public_paths` could be escaped with dot segments — Fixed

`RouteConfig.is_public_path()` matched `fnmatch` against the raw request path.
Warden forwards that path untouched and the upstream collapses `.`/`..`, so on a
route with `public_paths: [/public/*]` a request for `/public/../admin` reached
`/admin` without a session — an authentication bypass, not just the blocked-path
dodge fixed in #34.

Both sides are now normalised through a shared `config.normalize_path()`, which
the proxy's path-denial helper uses too, so the allow and deny rules cannot
disagree. Covered by `tests/test_path_rules.py` and
`test_public_path_cannot_be_escaped_with_dot_segments`, which checks
`/public/../secret`, `/public/%2e%2e/secret` and `/public/./../secret` against a
live application.

### 37. A pending TOTP secret locked out the active authenticator — Fixed

`verify_otp()` preferred the pending secret and only fell back to the active one
when none was pending. That made enrolment a trap: generating a secret and
abandoning it meant the authenticator the user already had stopped verifying,
and they could not reach the passkeys page to finish the new one because they
could no longer sign in. The docstring promised the fallback the code did not
have.

Both adapters now try the pending secret and then the active one, promoting only
on a pending match. Covered by
`test_pending_otp_secret_never_blocks_the_active_one`.

### 38. One wrong TOTP code discarded the sign-in challenge — Fixed

`/_warden/auth/login/otp` consumed the `login_otp` challenge before checking the
code, so a single typo ended the whole sign-in: the retry answered "Your sign-in
attempt expired" and the user had to redo the passkey ceremony.

Challenges gained a non-destructive `get_challenge()` on both backends; the route
peeks, verifies, and consumes only on success. The per-IP window for this step is
tighter (10/min rather than 30) because a challenge can now be retried.
`test_login_otp_challenge_survives_a_wrong_code` asserts the retry succeeds.

### 39. The last-passkey guard was check-then-act — Fixed

`delete_passkey()` counted credentials and then deleted in a second statement, so
two concurrent removals could each see two keys and leave the account with none —
a lockout with no in-app recovery. The rule now runs inside the `DELETE`
(`... AND (SELECT COUNT(*) ...) > 1`), mirroring the last-admin guard in #23.
Covered by `test_delete_credential_can_keep_the_last_key`.

### 40. TOTP had no enrolment or disable surface — Implemented

#32 added server-side enforcement but left it unreachable: nothing in
`passkeys.html` called `/_warden/auth/otp/setup`, there was no way to see or undo
an enrolment, and the second factor was requested through `window.prompt`, which
cannot be retried in place and is blocked in some embedded browsers.

* `/passkeys` now has a **Two-factor** panel (`static/otp.js`) that enrols from
  the returned secret and turns the factor off with a current code.
* `GET /_warden/auth/otp/status` reports `{enabled, pending}`, and
  `POST /_warden/auth/otp/disable` requires a valid code before deleting the row,
  so a stolen session cannot drop the second factor. `clear_otp_secret()` was
  added to both backends.
* `/login` renders a code field (`#otp-step`) once `login_complete` reports
  `otp_required`; `window.prompt` is gone and `Warden.completeLoginOtp()` posts
  the code.

Covered by `test_otp_status_and_disable`.

### 41. Every metrics scrape ran `wg show` and rewrote handshake rows — Fixed

`GET /_warden/metrics` called `refresh_handshakes()` on every request, which
shells out to `wg show` (10-second timeout) and updates
`mesh_peers.last_handshake` for every peer. A 15-second Prometheus scrape ran
four subprocesses and four database writes a minute, and a slow `wg` stalled the
scrape. The rendered block is now cached for 15 seconds on
`app.state.mesh_metrics_cache`.

### Left open after this pass

* **The TOTP items are done.** Replay protection, per-user reset, and the
  require-for-admins policy were implemented afterwards as #47–#49 below.
* **Request bodies now stream.** The bounded `receive` is handed to `httpx`
  through `_BoundedStream`, so a large upload no longer sits in Warden's memory
  in full while the limit is still enforced as bytes flow (#61 below).
* **Path rules are case-insensitive.** `public_paths` and `blocked_paths` are
  compared after `casefold()` on both sides, so a rule written `/Public/*`
  still matches a request to `/public/admin` on a case-insensitive upstream.

## Fifth audit pass

This pass covered the modules the earlier ones skipped: `cli.py`, `tls.py`,
`mesh_peer.py`, `mesh_apply.py` and the mesh/admin surfaces they feed.

### 42. Startup accepted a TLS key it could not use — Fixed

`validate_runtime_files()` checked that the certificate parsed and the key was
*readable*, then stopped. A key file containing garbage, a passphrase-protected
key, or the key belonging to a different certificate all passed, and the
mismatch only surfaced during the TLS handshake — on a reverse proxy, that is
every site behind it down, with a handshake error instead of a startup message.
The validator now loads the private key, names the passphrase case explicitly,
and compares the public halves of key and certificate, so `warden serve` and
`warden check` fail with the actual cause.

### 43. Writing the mesh config chmod-ed an existing directory to 0700 — Fixed

`MeshPeerIntake.write_config()` ran `os.chmod(path.parent, 0o700)`
unconditionally. With the documented `mesh.config_path: /etc/wireguard/wg0.conf`
that is defensible, but the same code runs for any path: pointing it at
`/tmp/wg0.conf` would have made `/tmp` root-only for every user on the host, and
any other shared directory loses group/other access to unrelated files. The
directory is now tightened only when Warden created it.

### 44. Visiting `/mesh` replaced the last-apply banner on the next visit — Fixed

`MeshManager.refresh_handshakes()` assigned the live status dict to
`last_apply`, and `mesh_page()` calls it on every render. The template reads
`last_apply.ok`, `.timestamp` and `.output`, none of which exist on a status
payload, so after one visit the page rendered a red "Last apply never" banner
that looked like a failed apply. The apply result is no longer touched by
status polling.

### 45. The ACME challenge store never dropped expired tokens — Fixed

`get_challenge_response()` prunes a token only when someone asks for it, and the
CA fetches each token exactly once. Every renewal therefore left its key
authorizations in `ACMEManager._tokens` for the life of the process (two per
issuance, holding account-thumbprint material). Inserting a token now evicts
the expired ones first.

### 46. `python -m warden.cli` raised NameError, and dev TLS wrote to another tool's directory — Fixed

`cmd_config_show()` sat below the `if __name__ == "__main__"` guard, so the
module entry point built its parser before the function existed and died with
`NameError` (the console script was unaffected because it imports the whole
module first). The function now precedes `main()`. While there, the `--dev-tls`
default moved from `/tmp/opencode/warden-dev-tls` — another vendor's directory
name, baked into `--help` and the README — to `.warden/dev-tls` beside the ACME
account key, and that directory is created `0700` because it holds a private
key.

Covered by `test_validate_runtime_files_rejects_unusable_keys`,
`test_expired_acme_tokens_are_pruned_on_insert`,
`test_mesh_write_config_only_tightens_directories_it_creates`,
`test_refresh_handshakes_keeps_the_last_apply_result`,
`test_config_command_prints_the_effective_file` and
`test_module_entry_point_can_build_the_parser`.

Still open from this pass: the mesh `apply` path needs `wg`/`wg-quick` plus
root, which no test exercises end to end. The `Host`-header redirect and the
`(none)` endpoint noted here were fixed later — see #59 below.

## TOTP completion

The three two-factor gaps left open after the fourth pass are now closed.

### 47. A TOTP code could be replayed inside its drift window — Fixed

`verify_otp()` answered "valid" without remembering which time-step it had
accepted, and the ±1-step drift tolerance therefore kept three codes alive for
up to 90 seconds. Anyone who saw a code — a shoulder-surfer, a proxy log, a
phished prompt — could reuse it until its window closed, including on the
sign-in step that had just accepted it.

Schema v8 adds `otp_secrets.last_used_counter`. Verification returns the matched
step and spends it with a single conditional `UPDATE`
(`last_used_counter IS NULL OR last_used_counter < :counter`), so:

* a replayed code is refused;
* an older code still inside the drift window is refused;
* two concurrent requests cannot both spend one code, because the guard lives in
  the statement rather than in a read-then-write pair;
* a code for the *next* step still works, so a user who waits is never locked
  out.

Promoting a pending secret records the step it was proved with, so the code that
completed an enrolment cannot then be reused to sign in. `set_otp_secret()`
clears the counter, which makes re-enrolment start clean. Both backends
implement it, and the migration is idempotent for development databases that
already have the column.

### 48. An admin could not recover another user's lost authenticator — Implemented

The only recovery was the account owner's own `/passkeys` page or
`warden auth reset`, which deletes the entire instance. The Users page now marks
enrolled accounts with a **2FA** badge and a **Reset 2FA** action, backed by
`POST /_warden/api/users/{id}/otp/reset`. It is admin-only, audited as
`otp_reset`, and idempotent (reports `reset: false` when there was nothing to
clear).

Resetting *your own* factor through this endpoint is refused: that path takes a
current code on the passkeys page, so a stolen admin session cannot silently
drop the second factor. The page loads OTP state with a single query
(`otp_user_ids()`), so it does not issue a lookup per row.

### 49. No way to require TOTP for admins — Implemented

`server.require_otp_for_admins` (default `false`) turns enrolment from a personal
choice into a deployment rule. When it is on and a signed-in admin has no
verified secret:

* navigations are redirected to `/passkeys?otp_required=1` with an explanatory
  banner;
* API clients get `403` with `{"otp_setup_required": true, "setup_url": …}`;
* the passkeys page, its APIs, and every auth endpoint stay reachable, so the
  admin enrols with the existing panel and is unlocked on the next request — no
  re-login and no second account.

Enforcing this in the middleware (rather than only at sign-in) also covers
sessions that predate the policy and an admin who flips the flag in YAML, which
a login-time-only check would miss.

## Sixth audit pass

A pass over the proxy edges the suite mocks away — the WebSocket path, the
Prometheus text, and everything that leaves the process — plus a re-read of the
ACME and absolute-URL helpers.

### 50. WebSocket upgrades skipped the route rate limit — Fixed

`handle_http()` called `_per_route_rate_limit()` before anything else, but
`handle_websocket()` never did. A route with `rate_limit: 20` could therefore be
opened an unlimited number of times through the WebSocket path, each connection
holding a long-lived upstream socket — the limit only ever applied to plain
HTTP. The upgrade now checks the same per-client window first and closes with
`4429 Rate limit exceeded` (recorded as a 429 in the metrics).

### 51. An upstream could select a subprotocol the route did not allow — Fixed

The pre-flight check only proved that *some* offered protocol appeared in
`routes[].websocket_subprotocols`, then forwarded every offered protocol and
accepted whichever one the upstream chose. Offering `["allowed", "other"]` to an
upstream that selects `other` produced a connection on the protocol the operator
excluded. The selected protocol is now checked after the upstream handshake;
a mismatch closes `1008 Subprotocol not allowed` instead of being accepted.

### 52. The ACME challenge could be rate-limited into a failed renewal — Fixed

`handle_http()` enforced the per-route limit before serving
`/.well-known/acme-challenge/<token>`. A route under a scan, or simply at its
window, answered the CA with `429`, so a certificate renewal failed for a reason
that had nothing to do with the service behind it. Challenges are now served
first; the limit still applies to every other path on that route.

### 53. Prometheus HELP/TYPE were repeated per route and named one host — Fixed

`prometheus_metrics()` emitted `# HELP`/`# TYPE` inside the per-host loop, so an
instance with four routes declared `warden_route_requests_total` four times and
changed that family's help text to "Total requests for <host>" — whichever host
was iterated first. The text format describes a metric family, not a sample, so
the declarations now appear once with host-independent help text and the samples
follow underneath. `warden_route_latency_ms` also declares its family even when
no request has been timed yet.

### 54. Behind a TLS terminator, Warden advertised its internal port — Fixed

`get_port()` falls back to the local listening port, and both `X-Forwarded-Port`
and `external_url()` used that fallback. With `external_scheme: https` on an
internal `http://:8080` listener, upstreams received a contradictory pair —
`X-Forwarded-Proto: https` with `X-Forwarded-Port: 8080` — and the portal's
absolute links (and the `url` field in the routes API) became
`https://app.home.lan:8080`, an address no client can reach.

The new `utils.host_port()` returns only the port the client actually used (from
the `Host` header) or `None`; forwarded headers and absolute URLs use it, while
`get_port()` keeps its listener fallback for local decisions.

## Closing the ticket list

The audit tickets in `docs/tickets.md` are closed except for the items that need
design work (streamed request bodies, case-insensitive path rules, DNS-01).

### 55. Denials and rate limits were invisible in the metrics — Fixed

`handle_http()` recorded a traffic event only for requests it forwarded, so a
route under a brute-force or scan attempt showed `requests == 0` while it was
answering 403/429. Every edge response Warden generates itself — per-route 429,
ACL/IP/UA/path 403, health-check 503 and both 413 branches — now goes through
`ProxyEngine._record_edge()`, so the dashboard and
`warden_route_requests_total` agree with what clients saw.

### 56. Machine clients got HTML for unknown paths — Fixed

`_not_found()` chose JSON only when the client advertised `application/json`.
Prometheus scraping the wrong host, or `curl`, therefore received the error
page. The decision now follows `is_navigation()`: GET/HEAD with a `text/html`
preference gets the page, everything else gets `{"detail": ...}` with a 404.

### 57. `warden check` reported a corrupt database as valid — Fixed

The command validated YAML, TLS files and paths but never opened the database.
It now runs a read-only `PRAGMA quick_check` on an existing SQLite file and
adds "not a usable SQLite file" / "failed SQLite's integrity check" to
`problems` (JSON and text output), while a missing file stays valid because
startup creates it.

### 58. Email could not use implicit TLS — Fixed

`EmailConfig` only had `starttls`, so an SMTP server that expects TLS from the
first byte (typically port 465) could not be configured: `smtplib.SMTP` fails
on the plaintext greeting. `email.ssl` now selects `SMTP_SSL`, and setting both
modes is rejected at validation time instead of silently picking one.

### 59. The plain-HTTP listener redirected any `Host` header — Fixed

`HttpsRedirectApp._location()` built `Location` from the request's `Host`
verbatim, so exposing the HTTP port turned it into an open redirect to an
attacker-chosen hostname. Only the admin host and hosts with a configured route
are redirected now; anything else answers `404 Unknown host`.

### 61. Streamed request bodies lost the declared length — Fixed

Forwarding an async body makes httpx switch to chunked encoding, and the
`Content-Length` the client sent went with it. Upstreams that read exactly that
many bytes (most WSGI servers and hand-written handlers) saw an empty body —
the regression `test_proxy_post_body` caught once bodies streamed. The
forwarded request now keeps the declared length when the client sent one and
falls back to chunked only for genuinely chunked uploads, with the size limit
still enforced by `_BoundedReceive` during the transfer.

### 60. A losing invite ceremony still stored a passkey — Fixed

`complete_invite_registration()` writes the credential and then claims the
invite with the atomic `mark_invite_used()` (`UPDATE ... WHERE used = 0`). With
two ceremonies started from one token, the loser was told "already been used"
while the passkey it had just created stayed in the database — the token was
single-use, but one token had produced two registrations. The loser now deletes
the row it wrote before raising. The claim still happens after WebAuthn
verification, so a cancelled or failed ceremony does not burn the invite.

### Closed without a code change

* **T-04** — the unused i18n scaffolding (module, catalog placeholder, `_`
  global) was removed rather than shipped half-wired.
* **T-07** — `_load_document()` documents why round-trip loading is required
  for comment-preserving edits; validation keeps the safe loader.
* **T-05** — `ROADMAP.md` §1 records ACL groups as shipped and keeps per-user
  grants as an explicit design alternative.
* **T-06** — `session_cookie_name()` derives the `__Host-` prefix from
  `external_scheme`, matching the `Secure` attribute behind a terminator.
* **T-09** — `upstream_url()` no longer prefixes a path that already starts
  with the configured base.
* **T-12** — the Mesh page has a **Rotate** action for the hub key.
* **Mesh `(none)` endpoint** — `wg show dump` peers without an endpoint store
  `None`, not the literal string.

## Verification

* `ruff check warden tests scripts` (the CI lint step): clean. The `S110`/`B023` findings from
  the first pass were fixed in `a2f6311`.
* Full suite: **467 passed**, **79.47%** coverage (gate 75%), run with
  `-W error::RuntimeWarning` to catch un-awaited coroutines.
* Third pass: `test_strip_reserved_cookies_handles_browser_prefixes`,
  `test_proxy_rewrite_set_cookie_drops_prefixed_session_cookie`,
  `test_proxy_access_denials_cover_ws_rules`,
  `test_websocket_respects_ip_allow_list`, `test_auth_routes_await_async_rate_limiter`,
  `test_redis_rate_limiter_enforces_window`,
  `test_redis_backed_limiter_blocks_login_after_limit`, the live
  `tests/test_rate_limiter_redis.py`, and the ACL checks
  `test_proxy_ip_denial_unwraps_ipv4_mapped_addresses`,
  `test_proxy_path_denial_normalizes_dot_segments`,
  `test_handle_http_blocked_path_cannot_be_dodged` and
  `test_websocket_respects_blocked_paths` pin the fixes above (the async limiter
  test would fail with a 500 before #28).
* `tests/test_acl_groups.py` pins the ACL work: the seeded `Users` group, both
  account-creation paths joining it, the default group being undeletable, the
  unknown-group rejection, open (ACL-free) routes, admin bypass, HTTP/WebSocket
  enforcement, and the portal hiding routes the user cannot open.
* New coverage for this pass: per-client rate limiting and stale-window pruning,
  ACME authorization timeout, expired-token eviction, an order failing
  finalization after its challenge validated, and the narrowed
  `Origin: null` rule; plus `warden certs bootstrap` (write, `--force`, and both
  guard paths) in `tests/test_cli.py`.
* Historical: the real-browser E2E run (Chromium + WebAuthn virtual
  authenticator against a live `warden serve`) covered setup, user creation,
  invite registration, the non-admin portal, every dashboard page, the **Add
  service** dialog, and backup-code generation. That script lived in `e2e/`,
  which was deleted in `300537b`, so it is no longer runnable from this repo;
  the portal and backup-code paths are now covered by
  `tests/test_admin_security.py` instead.
* Pebble: `python scripts/pebble_issuance.py` passes end to end in ~20s —
  issuer `CN=Pebble Intermediate CA …`, a two-certificate chain, three 200
  challenge fetches, and the restart notice.
* Lint: `ruff check tests warden` is clean. The test suite's eight findings
  (`B017`, `SIM117`, `UP031`, `C408`) were fixed rather than ignored, and the
  blind `pytest.raises(Exception)` assertions in `tests/test_invite_flow.py`
  now name `AuthError` and match  the message the flow raises — which is how the narrowing caught that a wrong
  invite token is rejected as "invalid or has already been used" before the
  challenge-binding check runs. CI now lints `warden tests scripts`, so this
  stays enforced.
* CI (`python-app.yml`) now lints `warden tests scripts`, runs
  `--strict-markers -W error::RuntimeWarning`, caches pip, cancels superseded
  runs on the same ref, and has a 20-minute timeout. `release.yml` grants write
  scopes per job (build: `contents: read`, PyPI: `id-token: write`, GitHub
  release: `contents: write`) instead of to the whole workflow, and
  `.github/dependabot.yml` opens weekly grouped PRs for pip and actions.
* Fourth pass: `tests/test_path_rules.py`,
  `test_public_path_cannot_be_escaped_with_dot_segments`,
  `test_pending_otp_secret_never_blocks_the_active_one`,
  `test_get_challenge_peeks_without_consuming`,
  `test_login_otp_challenge_survives_a_wrong_code`,
  `test_delete_credential_can_keep_the_last_key` and
  `test_otp_status_and_disable` pin the items above.
* Fifth pass: `test_validate_runtime_files_rejects_unusable_keys` (parse,
  passphrase and mismatch cases), `test_expired_acme_tokens_are_pruned_on_insert`,
  `test_mesh_write_config_only_tightens_directories_it_creates` (asserts a
  0755 directory stays 0755 and a new one becomes 0700),
  `test_refresh_handshakes_keeps_the_last_apply_result`,
  `test_config_command_prints_the_effective_file`, and
  `test_module_entry_point_can_build_the_parser`, which runs
  `python -m warden.cli --help` in a subprocess and fails with `NameError`
  before #46.
* TOTP completion: `test_totp_codes_cannot_be_replayed` (same code, older step,
  next step, and pending promotion), `test_require_otp_confines_an_unenrolled_admin`
  (redirect, JSON `403`, and unlocking by enrolling through the page's own
  endpoints), and `test_admin_can_reset_another_users_totp` (badge and action
  rendered, reset, second reset reports nothing to do, self-reset and unknown
  user refused).
* Sixth pass: `test_websocket_is_rate_limited` (the second upgrade is closed
  with 4429), `test_websocket_rejects_an_unlisted_upstream_subprotocol`
  (upstream picks `chat` while the route allows only `other`),
  `test_acme_challenge_is_not_rate_limited` (a full window still serves the
  token), `test_prometheus_declares_each_metric_family_once` (two routes, one
  HELP/TYPE pair), `test_host_port_ignores_the_listener_fallback` and
  `test_external_url_behind_a_tls_terminator_omits_the_listener_port`.
* Closing pass: `test_handle_http_ip_denied` (denial now counted),
  `test_machine_404_is_json_without_an_accept_header`,
  `test_email_tls_modes_cannot_be_combined`,
  `test_send_email_uses_implicit_tls_when_configured`,
  `test_check_reports_a_corrupt_database`, `test_check_accepts_a_real_database`,
  `test_https_redirect_rejects_an_unconfigured_host`,
  `test_https_redirect_keeps_the_configured_admin_host` and
  `test_invite_losing_a_race_rolls_back_the_passkey`. The proxy control-flow
  tests now drive a real ASGI `receive` instead of patching `Request`;
  `test_handle_http_chunked_body_over_limit_is_rejected` pins the streamed-size
  limit and `test_proxy_post_body` covers the preserved `Content-Length`.
