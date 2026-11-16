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
allow those two hosts. If third-party requests should be avoided entirely,
self-hosting JetBrains Mono and removing the hosts from the CSP is the follow-up.

## Unfinished functionality

### 13. ACME issuance is unreachable — Partially fixed

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
Pebble directory (see `ROADMAP.md` §2). That run found three defects the mocks
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
`X-Warden-Request` header and origin checks as the admin UI. Service visibility
is intentionally binary for now — every signed-in user sees every enabled route.
Per-route ACLs (a grant table plus admin UI for "this user may open this host")
are a **future feature**, not a defect in the portal; the portal is the natural
place to render them once they exist.

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

## Verification

* `ruff check warden` (the CI lint step): clean. The `S110`/`B023` findings from
  the first pass were fixed in `a2f6311`.
* Full suite: **404 passed**, **77.90%** coverage (gate 75%), run with
  `-W error::RuntimeWarning` to catch un-awaited coroutines.
* New coverage for this pass: per-client rate limiting and stale-window pruning,
  ACME authorization timeout, expired-token eviction, and the narrowed
  `Origin: null` rule; plus `warden certs bootstrap` (write, `--force`, and both
  guard paths) in `tests/test_cli.py`.
* Historical: the real-browser E2E run (Chromium + WebAuthn virtual
  authenticator against a live `warden serve`) covered setup, user creation,
  invite registration, the non-admin portal, every dashboard page, the **Add
  service** dialog, and backup-code generation. That script lived in `e2e/`,
  which was deleted in `300537b`, so it is no longer runnable from this repo;
  the portal and backup-code paths are now covered by
  `tests/test_admin_security.py` instead.
* Known lint debt outside the CI target: `ruff check tests` reports 8
  pre-existing issues (`B017`, `SIM117`, `UP031`, `C408`) in
  `tests/test_invite_flow.py`, `tests/test_invite_routes.py` and
  `tests/test_mail.py`. The workflow lints only `warden`, so these do not fail
  the build; narrowing the blind `pytest.raises(Exception)` assertions is a
  deliberate follow-up rather than a mechanical fix.
