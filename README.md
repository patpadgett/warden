# Warden

[![auto-tag](https://github.com/patpadgett/warden/actions/workflows/auto-tag.yml/badge.svg)](https://github.com/patpadgett/warden/actions/workflows/auto-tag.yml)
[![CI](https://github.com/patpadgett/warden/actions/workflows/ci.yml/badge.svg)](https://github.com/patpadgett/warden/actions/workflows/ci.yml)

**One door to your homelab.**

Warden is a self-hosted reverse proxy and dashboard built around passkeys. Point
hostnames at Warden, describe your services in YAML, and reach everything through
a single passkey-protected front door — with native WebAuthn, HTTP/WebSocket
proxying, TLS and certificate renewal, and optional WireGuard mesh management.

There is no account database to populate and no password to invent. On first run
Warden prints a one-time setup code, you create the admin account with a passkey,
and every service behind `auth: true` shares that sign-in.

## Why

- **Passkey-native.** WebAuthn registration and login are implemented directly,
  not bolted onto a password login. One admin, many passkeys.
- **Host-based routing.** Each service gets its own hostname. Warden matches the
  `Host` header and streams the request upstream, including WebSockets.
- **Quiet by default.** Protected routes redirect browsers to a polished sign-in
  page. Warden cookies and spoofed identity headers never reach upstreams.
- **Everything editable.** Routes, access, activity, YAML config, and mesh peers
  are managed from the dashboard. YAML remains the source of truth.
- **No build step.** The dashboard is server-rendered HTML with a little vanilla
  JavaScript and one CSS file.

## Quick start (local trial)

Passkeys require a secure context. Browsers treat `localhost` as secure, so use
it for a first look without TLS.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .

warden init --admin-host localhost
warden serve
```

Open <http://localhost:8080/>. The startup banner prints a setup code such as
`Setup code · 7K4M-9Q2X-...`. Open `/_warden/setup`, enter the code, choose a
username, and register a passkey.

To pick the setup code yourself, set `WARDEN_SETUP_TOKEN` before starting:

```bash
WARDEN_SETUP_TOKEN='my-long-one-time-code' warden serve
```

The code must be at least 12 characters after removing punctuation. If no code
is active (for example after it expires), restart Warden to generate a fresh one.

## Observability

- **OpenAPI documentation**: The admin API OpenAPI schema is available at `/_warden/openapi.json` and an interactive Swagger UI is served at `/_warden/docs`. Both endpoints are protected by admin‑host authentication.
- **Prometheus metrics**: Request metrics, authentication counters, OTP counters, role changes, backup code usage, and service latency are exposed at `/_warden/metrics` and also at `/metrics`. These endpoints require an authenticated admin session and the correct host.

1. **Give Warden a name.** `warden.home.lan` is the dashboard; `home.lan` is the
   WebAuthn RP ID. Create DNS records (or `/etc/hosts` entries) for the admin host
   and every route, all pointing at the Warden machine.

2. **Create a config.**

   ```bash
   warden init -o /etc/warden/warden.yaml \
     --admin-host warden.home.lan \
     --rp-id home.lan
   ```

   Then edit it. See [`configs/warden.yaml.example`](configs/warden.yaml.example)
   for every option.

3. **Enable TLS.** Passkeys only work over HTTPS on a real hostname. Point
   `server.tls.certfile` and `server.tls.keyfile` at a PEM certificate and key.
   The certificate should cover the admin host and any protected route hosts, for
   example with a wildcard or SAN certificate for `*.home.lan`.

   ```yaml
   server:
     admin_host: warden.home.lan
     tls:
       enabled: true
       certfile: /etc/letsencrypt/live/warden.home.lan/fullchain.pem
       keyfile: /etc/letsencrypt/live/warden.home.lan/privkey.pem
       acme_webroot: /var/www/warden-acme
       renew_command: certbot renew --quiet
   ```

4. **Validate and run.**

   ```bash
   warden check
   warden serve
   ```

   The banner shows the HTTPS URL and a setup code. Open it, claim the instance,
   and register your first passkey.

5. **Add services** in the dashboard, or edit `routes` in the YAML file and
   restart. Protected routes (`auth: true`) must be under the WebAuthn RP ID.

> **Important:** `server.admin_host` must equal the RP ID or be a subdomain of it.
> Each protected route host must also be under the RP ID. Routes outside it must
> use `auth: false`.

## How requests flow

1. Warden reads the normalized `Host` header.
2. If it is the admin host, the request goes to the dashboard. The dashboard
   requires a passkey session; internal routes live under `/_warden/`.
3. Otherwise Warden finds an exact route, then the longest matching wildcard.
   Unknown or disabled hosts get a friendly 404 page.
4. If the route is protected and the path is not in `public_paths`, Warden checks
   the session cookie. Browsers are redirected to `/_warden/login?next=...`;
   API-style requests get `401` JSON.
5. Warden strips hop-by-hop headers, its own cookies, client-supplied
   `X-Forwarded-*`/identity headers, and proxies the request. Authenticated
   requests can carry the username in `X-Warden-User` (configurable) and always
   carry `X-Warden-User-Id`.
6. Responses stream back. Upstream redirects can be rewritten to the public host,
   and cookies with unreachable `Domain` attributes can be cleaned up.

`PATH` and query strings are preserved. The upstream path in the route (for
example `http://10.0.0.5:3000/api`) is used as a prefix. WebSocket upgrades are
relayed in both directions when `websocket: true`.

### Public paths

`public_paths` skips the passkey gate for matching request paths and WebSocket
paths. It uses Python `fnmatch` patterns:

```yaml
routes:
  - host: app.home.lan
    upstream: http://192.168.1.20:3000
    public_paths:
      - /health
      - /webhooks/*
```

Only expose what needs to be public. A route with `auth: false` is fully public.

## Configuration reference

Warden validates the whole file on load. Unknown keys are rejected, so typos fail
fast. All relative paths are resolved from the directory containing
`warden.yaml`.

### `server`

| Key | Default | Purpose |
| --- | --- | --- |
| `admin_host` | `localhost` | Dashboard hostname. Must be the RP ID or a subdomain of it. |
| `bind` | `0.0.0.0` | Listen address. |
| `http_port` | `8080` | HTTP port. With TLS enabled this is the ACME/redirect companion. |
| `https_port` | `8443` | HTTPS port when TLS is enabled. |
| `session_ttl_hours` | `168` | Lifetime of a passkey session. |
| `cookie_domain` | unset | Parent domain for the session cookie (SSO across subdomains). |
| `secure_cookies` | auto | Force `Secure` on the session cookie; auto means "when HTTPS". |
| `trust_proxy_headers` | `false` | Trust inbound `X-Forwarded-*`. Only behind a proxy you control. |
| `forward_user_header` | `X-Warden-User` | Header carrying the username to authenticated upstreams (`null` disables). |
| `external_scheme` | unset | Force `http`/`https` in generated URLs. |
| `public_url` | unset | Canonical admin origin, e.g. `https://warden.home.lan`. |
| `request_timeout_seconds` | `60` | Default upstream timeout. |
| `health_interval_seconds` | `30` | Dashboard health-check interval. |
| `log_level` | `info` | `debug`, `info`, `warning`, `error`, or `critical`. |
| `rate_limiter` | unset | Configuration for request rate limiting. Optional; if omitted, a memory limiter is used. |

### `server.tls`

| Key | Default | Purpose |
| --- | --- | --- |
| `enabled` | `false` | Serve HTTPS and the HTTP redirect/ACME companion. |
| `certfile` / `keyfile` | required | PEM certificate chain and private key. |
| `acme_webroot` | unset | Directory served at `/.well-known/acme-challenge/`. |
| `renew_command` | unset | Shell command run when renewal is due. |
| `renew_days_before` | `30` | Run the hook when the certificate has this many days left. |
| `check_interval_hours` | `12` | How often the renewal loop checks. |

Warden never reloads a certificate in place: after renewal, restart the process
(or use a certbot deploy hook that restarts it). The HTTP companion stays up
during renewal so webroot challenges keep working.

### `webauthn`

| Key | Default | Purpose |
| --- | --- | --- |
| `rp_id` | `localhost` | WebAuthn relying-party domain. Changing it invalidates passkeys. |
| `rp_name` | `Warden` | Name shown by the authenticator. |
| `require_user_verification` | `false` | Require PIN/biometric verification when authenticating. |
| `challenge_ttl_seconds` | `300` | Lifetime of a ceremony challenge. |
| `allowed_origins` | `[]` | Extra origins allowed to run passkey ceremonies. |

### `database`

| Key | Default | Purpose |
| --- | --- | --- |
| `path` | `warden.db` | SQLite database file. |

The database stores the admin account, passkey public keys, hashed sessions,
mesh private keys, challenges, settings, and the audit log. Back it up and keep
it private.

### `mesh` and `routes`

See the fully commented example in
[`configs/warden.yaml.example`](configs/warden.yaml.example). Route fields:

| Key | Default | Purpose |
| --- | --- | --- |
| `host` | required | Exact hostname or `*.suffix` wildcard. |
| `upstream` | required | `http://` or `https://` base URL, optional path prefix. |
| `name` | host label | Display name. |
| `auth` | `true` | Require a passkey session (outside `public_paths`). |
| `enabled` | `true` | Pause the route without deleting it. |
| `websocket` | `true` | Allow WebSocket upgrades. |
| `preserve_host` | `false` | Send the public `Host` upstream. |
| `verify_tls` | `true` | Verify upstream TLS certificates. |
| `rewrite_redirects` | `true` | Rewrite upstream redirects that point at the upstream itself. |
| `rewrite_cookies` | `true` | Drop unreachable upstream cookie domains and downgrade `Secure` on HTTP. |
| `timeout_seconds` | server default | Per-route upstream timeout. |
| `public_paths` | `[]` | Auth bypass patterns using `fnmatch`. |
| `headers` | `{}` | Extra upstream request headers. |
| `health_path` | `/` | Path used by the health monitor. |
| `icon` | unset | Emoji or short label for the dashboard. |

## Role‑Based Access Control (RBAC)

Warden now supports fine‑grained role‑based access control.

* **Roles** – defined via the admin API (`/_warden/api/roles`). Each role has a name and optional description.
* **User‑role assignments** – assign roles to users with `POST /_warden/api/users/{user_id}/roles/{role_id}` and remove them with the corresponding `DELETE` endpoint.
* **Permission checks** – the admin UI and API enforce that only users with the `admin` role can manage roles, users, and other privileged actions. Use the helper `_require_role(request, "admin")` in custom endpoints if needed.
* **Built‑in role** – the `admin` role is created automatically on first use and should be granted to the initial administrator account.

The UI now includes a **Users** page where you can view users and manage their role assignments.

The **Roles** page (`/roles`) lets administrators view, create, and delete roles directly from the dashboard.

---

## Monitoring & Metrics

Warden exposes a rich set of Prometheus metrics at `GET /_warden/metrics`:

* `warden_uptime_seconds` – process uptime.
* Per‑host request, error, latency, and authenticated request counters (`warden_route_*`).
* Authentication counters: `warden_auth_success_total` and `warden_auth_failure_total`.
* OTP counters: `warden_otp_success_total` and `warden_otp_failure_total`.
* RBAC counters: `warden_role_created_total`, `warden_role_deleted_total`, `warden_role_assigned_total`, `warden_role_removed_total`.
* Backup‑code counters: `warden_backup_code_used_total` – total times a backup code was used for login.

A starter Grafana dashboard is provided in `grafana/warden-dashboard.json`. Import it into Grafana to visualize uptime, request volume, auth success/failure, and role activity.

---

- **Services** — add, edit, pause, and remove routes; open services; see latency,
  status, and traffic.
- **Access** — register additional passkeys, name or remove them, review and
  revoke sign-in sessions. Removing a passkey does not revoke existing sessions;
  revoke sessions separately if a device is lost.
- **Activity** — audit trail for setup, sign-ins, passkey changes, config edits,
  and mesh actions.
- **Config** — edit the YAML file with validation. Route and access changes apply
  immediately. Listener, TLS, database, RP ID, and mesh-interface changes are
  saved but held at their old runtime values until restart, and the page tells
  you a restart is required.
- **Mesh** — create peers, download client configs, apply the hub config, and see
  handshakes when WireGuard is available.

Mutations require the `X-Warden-Request: 1` header and a same-origin request.
The dashboard JavaScript handles both automatically.

## TLS and certificate renewal

Warden can terminate TLS itself or sit behind a TLS terminator.

**Direct TLS.** Enable `server.tls`. Warden serves HTTPS on `https_port`; a small
companion on `http_port` serves ACME challenges and redirects everything else to
HTTPS. Set `acme_webroot` to the same directory certbot writes to, then point the
renewal hook at certbot:

```bash
warden certs status
warden certs renew --dry-run   # print the configured command
warden certs renew             # run it now
```

The built-in renewal loop checks every `check_interval_hours` and runs
`renew_command` when fewer than `renew_days_before` days remain. It does not
restart Warden automatically. A deploy hook is a good place to do that:

```yaml
renew_command: certbot renew --quiet --deploy-hook "systemctl restart warden"
```

The hook runs as the Warden service user. If certbot needs root to write
`/etc/letsencrypt`, either grant that user the necessary access or leave
`renew_command` unset and renew from a root-owned timer. In the timer case Warden
still serves the ACME challenges from `acme_webroot`, and you restart it after the
certificate is replaced.

The Warden service user must be able to read `certfile` and `keyfile`. Let's
Encrypt keeps private keys root-only by default, so deploy a readable copy or
grant access with a group/ACL.

**Behind a TLS terminator.** Leave `server.tls` disabled, set
`external_scheme: https`, `secure_cookies: true`, and optionally `public_url`.
Only enable `trust_proxy_headers` when the terminator is the sole way to reach
Warden and it overwrites `X-Forwarded-*`.

## WireGuard mesh

The mesh is a hub-and-spoke WireGuard network managed alongside the proxy.

```yaml
mesh:
  enabled: true
  interface: wg0
  address: 10.44.0.1/24
  listen_port: 51820
  endpoint: vpn.home.lan:51820
  dns: 10.44.0.1
  client_allowed_ips: 10.44.0.0/24, 192.168.1.0/24
  config_path: /etc/wireguard/wg0.conf
```

Create a peer and apply the hub config:

```bash
warden mesh peer add laptop -o warden-laptop.conf
warden mesh config > /etc/wireguard/wg0.conf   # or inspect it first
warden mesh apply
warden mesh status
```

`warden mesh apply` writes the config, then uses `wg syncconf` if the interface is
up or `wg-quick up` if it is down. Peers can also be created and downloaded from
the Mesh page. Warden stores the hub private key and peer private keys in SQLite
so it can regenerate configs; protect the database accordingly.

Requirements:

- `wireguard-tools` (`wg` and `wg-quick`) on the host.
- Permission to create/configure the interface. This normally means root or
  carefully scoped capabilities; `wg-quick` also invokes `ip`, `iptables`, and
  `sysctl`.
- A UDP port reachable from clients (`listen_port`) and `mesh.endpoint` set to
  the public `host:port` clients should dial.
- `mesh.config_path` writable by the Warden process.

`mesh apply` is manual by design. Peer changes are saved immediately, but the
interface is only updated when you apply from the dashboard or CLI.

## CLI

```text
warden [--config PATH] COMMAND

serve                 run the proxy and dashboard
  --host ADDR         bind override
  --port PORT         HTTP port override
  --https-port PORT   HTTPS port override
  --no-access-log     hide per-request logs

init                  write a starter warden.yaml
  -o/--output PATH
  --admin-host HOST
  --rp-id DOMAIN
  --bind ADDR
  --port PORT
  --https-port PORT
  --database PATH
  --force

check [--json]        validate config, TLS files, and runtime paths

certs status [--json]
certs renew [--dry-run]

auth reset [--yes]    delete the account, passkeys, and sessions
                      (restart to generate a new setup code)

mesh status
mesh config
mesh apply
mesh peers
mesh peer add NAME [--address IP] [--endpoint HOST:PORT]
                    [--keepalive SECONDS] [-o FILE]
mesh peer config NAME
mesh peer remove NAME [--yes]
```

`WARDEN_CONFIG` sets the config path when `--config` is not given. `warden
--version` prints the version. `serve` validates TLS files before binding.

## Docker

The image runs Warden as an unprivileged user and installs it from the local
source tree.

```bash
mkdir -p config
cp configs/warden.yaml.example config/warden.yaml
# edit config/warden.yaml: admin_host, rp_id, routes, TLS paths
docker compose up -d --build
docker compose logs -f warden
```

The compose file maps host `8080`/`8443` to the container's default ports and
keeps the database in a named volume. Edit the mappings and `public_url` if you
want standard ports. Mount certificates read-only and point `certfile`/`keyfile`
at the mounted paths.

WireGuard is not container-friendly by default. The example keeps it disabled. If
you enable it in Docker, the container needs host networking, `/dev/net/tun`,
`NET_ADMIN`, the WireGuard tools, and a writable config path. Running the mesh on
the host (or in a privileged sidecar) is usually simpler.

## systemd

[`deploy/warden.service`](deploy/warden.service) is a starting point for a
non-mesh deployment. A typical install:

```bash
sudo useradd --system --home /var/lib/warden --shell /usr/sbin/nologin warden
sudo install -d -o warden -g warden -m 750 /var/lib/warden /etc/warden
sudo install -d -o warden -g warden -m 755 /var/www/warden-acme

sudo python3 -m venv /opt/warden
sudo /opt/warden/bin/pip install /path/to/warden
sudo install -m 644 deploy/warden.service /etc/systemd/system/warden.service

sudo systemctl daemon-reload
sudo systemctl enable --now warden
sudo journalctl -u warden -f
```

The unit grants `CAP_NET_BIND_SERVICE` for ports below 1024 and uses systemd
sandboxing. Adjust `ExecStart`, the config path, and `ReadWritePaths` to match
your install. The unit deliberately targets proxy mode; a process that manages a
WireGuard interface needs broader privileges than the sandbox allows.

## Security notes

- Warden is **single-admin**. Additional passkeys attach to the same account.
  There is no password fallback and no user self-registration.
- Sessions are opaque 256-bit tokens stored as SHA-256 hashes in SQLite. Cookies
  are `HttpOnly`, `SameSite=Lax`, and `Secure` when the request is HTTPS. The
  session cookie never reaches upstream services.
- Passkey registration and login challenges are stored server-side and consumed
  once. Origin, content type, rate limits, and user verification are checked
  during ceremonies.
- CSRF protection combines same-origin/`Sec-Fetch-Site` checks with a required
  `X-Warden-Request: 1` header on admin mutations.
- Upstreams see sanitized `X-Forwarded-For`, `X-Forwarded-Host`,
  `X-Forwarded-Proto`, `X-Real-IP`, and (for authenticated routes) identity
  headers. Client-supplied identity and forwarding headers are stripped.
- `public_paths` and `auth: false` are deliberate holes. Review them.
- The SQLite database contains sensitive material (passkey metadata, session
  hashes, WireGuard private keys). Use file permissions and encrypted backups.
- Keep Warden to a single process. Sessions and rate limits are process-local;
  multiple workers would also fight over the same SQLite file and renewal loop.
- Run behind a network you trust. Warden's own threat model assumes the admin
  hostname is not exposed on the public internet without TLS.

## OTP (One‑Time Password)

Warden supports optional TOTP‑based two‑factor authentication.

* **Enable OTP** – An authenticated user can POST to `/_warden/auth/otp/setup`. The endpoint is CSRF‑protected (requires `X-Warden-Request: 1` and same‑origin). It returns a Base32 secret and an `otpauth://` URL that can be scanned by Google Authenticator, Authy, or any TOTP app.

* **Verify OTP** – After provisioning, the user POSTs to `/_warden/auth/otp/verify` with the current 6‑digit code. Successful verification increments the `warden_otp_success_total` metric; failures increment `warden_otp_failure_total`.

* **Rate limiting** – OTP verification is limited to 30 attempts per minute per IP.

* **Metrics** – Both success and failure counters are exposed at `/_warden/metrics` and visualised in the Grafana dashboard.

* **No persistent storage** – The secret is stored in the database; OTP codes are time‑based and can be regenerated by the client at any time.

## Backup codes UI

The admin dashboard now includes a **Backup Codes** page at ``/backup_codes``. It lists all backup codes belonging to the current admin user, showing when each code was created and whether it has been used. A **Generate New Backup Code** button creates a fresh code via the ``POST /backup_codes/generate`` endpoint and redirects back to the list.

Warden supports one‑time backup codes for account recovery. An admin can generate a code via the API and a user can log in with it.

- `POST /_warden/api/backup_codes` – creates a new backup code (requires an authenticated admin session).
- `POST /_warden/auth/login/backup` – logs in using a backup code.

The metric `warden_backup_code_used_total` records each successful backup‑code login.

## Backup and recovery

Back up your configuration, database, and TLS certificates.

- the YAML config (contains secrets such as mesh settings and renewal hooks),
- the SQLite database (use `sqlite3 warden.db ".backup backup.db"` or stop Warden
  first),
- TLS certificates and keys if not managed by certbot.

To recover access when every passkey is lost:

```bash
warden auth reset --yes
# restart Warden and use the newly printed setup code
```

This deletes the admin account, all passkeys, sessions, and first-run settings,
but leaves the audit log and mesh peers. To start the whole instance over, remove
the database as well.

## Development

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
pytest
```

The test suite covers config validation, YAML round-tripping, SQLite persistence,
TLS inspection, mesh configs, authentication ceremonies (with mocked WebAuthn
verification), HTTP proxy behavior, admin APIs, WebSockets, and the CLI. It does
not replace a real browser passkey ceremony.

To run against a development config:

```bash
WARDEN_CONFIG=./warden.dev.yaml warden serve --host 127.0.0.1
```

## License

MIT. See [LICENSE](LICENSE).

# bump for auto-tag test
