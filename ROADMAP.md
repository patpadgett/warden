# Roadmap

Known gaps in Warden, ordered by value rather than by effort. Defects live in
[KNOWN_ISSUES.md](KNOWN_ISSUES.md); this file is for work that is missing rather
than broken.

## 1. Per-route access control

`GET /portal` lists every enabled route to every signed-in user, and the proxy
authorises on "has a session", not "may open this host" (KNOWN_ISSUES #16).
For a proxy whose purpose is gating services, that is the largest functional
gap: a guest account works as a key to every route the admin adds.

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

Not yet exercised against a real CA: production rate limits, and an order that
fails issuance *after* validation (that error path is unit-tested only).

## 3. DNS-01 issuance

HTTP-01 requires the CA to fetch `http://<domain>/.well-known/acme-challenge/<token>`
on port 80. Where that port is unreachable — CGNAT, a locked-down ISP, a host
behind another proxy — the only fix is a DNS-01 challenge, which means a provider
API (Cloudflare, Route 53, deSEC…), a TXT-record writer, and propagation polling.
Not worth building without a specific deployment that needs it.

## 4. Smaller items

* **Blind `pytest.raises(Exception)`** in `tests/test_invite_flow.py` is lint
  debt in the CI-ignored target and can mask real failures (`B017`). Worth
  narrowing to the expected exception before trusting those tests as
  regression cover.
* **Self-hosted webfont.** Every page loads JetBrains Mono from
  `fonts.googleapis.com`, which KNOWN_ISSUES #12 added to the CSP. Serving it
  from `static/` would remove the third-party request and let the CSP drop two
  hosts.
