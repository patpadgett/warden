# Roadmap

Known gaps in Warden, ordered by value rather than by effort. Defects live in
[KNOWN_ISSUES.md](KNOWN_ISSUES.md); this file is for work that is missing rather
than broken.

## 1. Per-user route grants (design alternative to ACL groups)

Per-route access control itself is **done**: `routes[].allowed_groups` plus
`acl_groups`/`acl_members` (schema v6) enforce group membership in
`ProxyEngine` on both HTTP and WebSocket paths, the portal hides routes the
user cannot open, and the users page edits membership (KNOWN_ISSUES #35).

This item is now a *different* model, not a missing feature: per-user grants
with optional expiry, for deployments that want one-off access without
creating a group. It has not been built and there is no confirmed demand for
it. Revisit only when a deployment needs time-boxed, individual grants.

Roughly, in dependency order:

* a `grants` table (`user_id`, `host`, optional expiry) plus the matching read
  and write methods on both database backends;
* enforcement in `ProxyEngine`, on the same host match that picks the route, so
  a denied request never reaches the upstream;
* portal and dashboard rendering of the grant set, and an admin UI to change it;
* an audit event for grant and revoke, alongside the existing user events.

Design question worth settling first: whether a route with no grants is open to
all signed-in users (current behaviour, no migration) or closed (safest, but
every existing deployment must grant after upgrading).

## 2. Verify ACME against a real CA

Issuance is covered only by a mocked ACME client, so the shape of the `acme`
library's responses is asserted against our own assumptions. A local
[Pebble](https://github.com/letsencrypt/pebble) directory exercises the parts a
mock cannot: the key authorization the CA actually fetches, `poll` statuses
arriving in a real order, `finalize_order` returning a chain, and the
`restart_required` flag reaching the dashboard.

**Done.** A first run against Pebble (v2.10.3, directory at
`https://localhost:14000/dir`) found three defects the mocks had hidden, all
fixed: the client was built with a `key` argument `acme` 5.x does not accept;
the challenge was published under the raw token rather than its base64url
encoding, so every fetch the CA made returned 404; and the authorization waiter
compared a `Status` enum member to the string `"valid"`, polling until its
deadline. With those fixed the CA validated the challenge, the order finalized,
and the renewal loop wrote a two-certificate chain issued by
`CN=Pebble Intermediate CA …` and set `restart_required`.

**Repeatable.** `python scripts/pebble_issuance.py` reruns the same check from
a clean checkout. It caches the pinned Pebble v2.10.3 binary under
`tmp/pebble-cache/`, generates a throwaway CA for Pebble's own HTTPS directory,
starts both processes on free ports, and asserts the Pebble issuer, a
certificate chain carrying the intermediate, three challenge fetches answered
200, and the restart notice in the log. It stays out of `pytest` because it
downloads a binary and binds loopback ports; run it after changing
`warden/tls.py`, the challenge route, or the renewal loop. The `Pebble ACME`
workflow runs it weekly (and on demand) and puts the result in the job summary.

Not yet exercised against a real CA: production rate limits, and an order that
fails issuance *after* validation (that error path is unit-tested only).

## 3. DNS-01 issuance

HTTP-01 requires the CA to fetch `http://<domain>/.well-known/acme-challenge/<token>`
on port 80. Where that port is unreachable — CGNAT, a locked-down ISP, a host
behind another proxy — the only fix is a DNS-01 challenge, which means a provider
API (Cloudflare, Route 53, deSEC…), a TXT-record writer, and propagation polling.
Not worth building without a specific deployment that needs it.

## 4. Smaller items

* **Lint the tests in CI.** The suite is clean now: the eight `B017`, `SIM117`,
  `UP031` and `C408` findings are fixed, and the blind `pytest.raises(Exception)`
  assertions in `tests/test_invite_flow.py` name `AuthError` and match the
  message the flow raises. The workflow still lints only `warden`, so widening
  that step is what stops the debt coming back.
* **Self-hosted webfont.** Done: JetBrains Mono is now served from
  `/_warden/static/fonts/` (variable woff2, 6 subset files) and the CSP no
  longer allows `fonts.googleapis.com` / `fonts.gstatic.com`.
