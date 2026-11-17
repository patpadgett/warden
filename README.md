# Warden

[![tests](https://github.com/patpadgett/warden/actions/workflows/python-app.yml/badge.svg)](https://github.com/patpadgett/warden/actions/workflows/python-app.yml)

**One door to your homelab.**

Warden is a self-hosted reverse proxy and dashboard built around passkeys. Point
hostnames at Warden, describe your services in YAML, and reach everything through
a single passkey-protected front door — with native WebAuthn, HTTP/WebSocket
proxying, TLS and certificate renewal, and optional WireGuard mesh management.

There is no account database to populate and no password to invent. On first run
Warden prints a one-time setup code, you create the admin account with a passkey,
and every service behind `auth: true` shares that sign-in.

## Contents

- [Why](#why)
- [Screenshots](#screenshots)
- [Quick start (local trial)](#quick-start-local-trial)
- [Security notes](#security-notes)
- [Deployment](#deployment)
- [How requests flow](#how-requests-flow)
- [Configuration reference](#configuration-reference)
- [User Access Control](#user-access-control)
- [API reference](#api-reference)
- [Monitoring & Metrics](#monitoring--metrics)
- [Dashboard](#dashboard)
- [TLS and certificate renewal](#tls-and-certificate-renewal)
- [WireGuard mesh](#wireguard-mesh)
- [CLI](#cli)
- [OTP (One-Time Password)](#otp-one-time-password)
- [Backup codes UI](#backup-codes-ui)
- [Backup and recovery](#backup-and-recovery)
- [Contributing and docs](#contributing-and-docs)
- [License](#license)

## Why

- **Passkey-native.** WebAuthn registration and login are implemented directly,
  not bolted onto a password login. One admin, many passkeys.
- **Host-based routing.** Each service gets its own hostname. Warden matches the
  `Host` header and streams the request upstream, including WebSockets.
- **Quiet by default.** Protected routes redirect browsers to a polished sign-in
  page. Warden cookies and spoofed identity headers never reach upstreams.
- **Everything editable.** Routes, access, activity, YAML config, and mesh peers
  are managed from the dashboard. YAML remains the source of truth.
- **No build step.** The dashboard is server-rendered HTML with vanilla
  JavaScript and a single CSS file.

## Screenshots

The admin interface runs on the reserved `admin_host` and is reachable only
after a passkey sign-in.

![Warden services dashboard](assets/screenshots/dashboard.png)

*Services dashboard — routes, live health, proxied request counts, and recent traffic.*

<details>
<summary>More of the admin interface</summary>

![Warden audit log](assets/screenshots/activity.png)

*Audit log — sign-ins, config changes, and mesh actions, newest first.*

![Warden WireGuard mesh](assets/screenshots/mesh.png)

*WireGuard mesh — peers, handshakes, and hub key management.*

![Warden passkeys and sessions](assets/screenshots/passkeys.png)

*Access — registered passkeys and active sessions.*

</details>

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

For a non-`localhost` hostname during development, run `warden serve --dev-tls`
to generate a self-signed certificate under `.warden/dev-tls` (override with
`--tls-dir`). Browsers still need to trust that certificate.

## Security notes

- Warden is **single-admin by default** (one admin account, multiple passkeys
  allowed). The admin account can manage additional users and toggle their
  `is_admin` flag through the dashboard. There is no password fallback and no
  open user self-registration.
- Multi-user access is through the `is_admin` flag: additional users are created
  by the admin (`Users` page), must register at least one passkey, and are
  granted or denied privileged actions by the `is_admin` flag. The built-in admin
  account created during first-run setup is automatically admin.
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
- `public_paths` and `auth: false` are deliberate holes. Review them. Path
  rules are matched after collapsing `.`/`..` segments and duplicate slashes, so
  `/public/../admin` cannot slip through a `/public/*` bypass.
- The SQLite database contains sensitive material (passkey metadata, session
  hashes, WireGuard private keys). Use file permissions and encrypted backups.
- Keep Warden to a single process. Sessions and rate limits are process-local;
  multiple workers would also fight over the same SQLite file and renewal loop.
- Run behind a network you trust. Warden's own threat model assumes the admin
  hostname is not exposed on the public internet without TLS.

## Deployment

Three methods: **host** (systemd / bare metal), **docker**, **helm** (Kubernetes). Pick one.

### Host (systemd / bare metal)

Best for a single server or VM. Uses `deploy/host/warden.service`.

```bash
# 1. Create user and directories
sudo useradd --system --home /var/lib/warden --shell /usr/sbin/nologin warden
sudo install -d -o warden -g warden -m 750 /var/lib/warden /etc/warden
sudo install -d -o warden -g warden -m 755 /var/www/warden-acme

# 2. Install Warden
python3 -m venv /opt/warden
sudo /opt/warden/bin/pip install .

# 3. Create config from example
cp warden.yaml.example /etc/warden/warden.yaml
# edit /etc/warden/warden.yaml: admin_host, rp_id, routes, TLS

# 4. Install service and start
sudo install -m 644 deploy/host/warden.service /etc/systemd/system/warden.service
sudo systemctl daemon-reload
sudo systemctl enable --now warden
sudo journalctl -u warden -f
```

If you want WireGuard mesh, install `wireguard-tools`, set `mesh.enabled: true`, and make `mesh.config_path` writable.

### Docker

Best for quick trials or container hosts. Uses `deploy/docker/docker-compose.yml`.

```bash
mkdir -p config certs
cp warden.yaml.example config/warden.yaml
# edit config/warden.yaml: admin_host, rp_id, routes, TLS paths
chown -R 10001:10001 config   # the image runs as the unprivileged "warden" user

docker compose -f deploy/docker/docker-compose.yml up -d --build
docker compose -f deploy/docker/docker-compose.yml logs -f warden
```

The compose file builds from the repository root (`context: ../..`) and bind-mounts
`config/` and `certs/` from the repository root. The image runs Warden as an
unprivileged user, keeps the database in a named volume, and expects
`WARDEN_CONFIG=/config/warden.yaml`. Edit the port mappings and `public_url` if
you want standard ports. Mount certificates read-only and point
`certfile`/`keyfile` at the mounted paths.

WireGuard is not container-friendly by default. The example keeps it disabled. If
you enable it in Docker, the container needs host networking, `/dev/net/tun`,
`NET_ADMIN`, the WireGuard tools, and a writable config path. Running the mesh on
the host (or in a privileged sidecar) is usually simpler. See
[WireGuard mesh](#wireguard-mesh).

### Helm (Kubernetes)

Best for clusters. Uses `deploy/helm/` chart.

```bash
# From repo root
helm install warden deploy/helm/ \
  --set image.tag=latest \
  --set config.adminHost=warden.home.lan \
  --set webauthn.rpId=home.lan \
  --set database.type=sqlite
```

The chart seeds `/config/warden.yaml` from the chart's ConfigMap on first start.
Set `persistence.enabled=true` to keep the config, database, and mesh keys on a
PVC across restarts; otherwise they live in an `emptyDir`. After first start,
prefer editing the ConfigMap through `helm upgrade` (or delete the persisted
`warden.yaml` to re-seed it) so Helm remains the source of truth. `webauthn.rpId`
must be the parent domain of `config.adminHost` and every protected route.

For mesh in Kubernetes, apply the DaemonSet (privileged, `hostNetwork`, `/etc/wireguard` hostPath):

```bash
# Edit the ConfigMap in the manifest first (interface, address, endpoint).
kubectl apply -f deploy/helm/warden-mesh-daemonset.yaml
```

The DaemonSet runs a standalone Warden instance to manage the host's WireGuard
interface; do not run it alongside the chart's Deployment on the same node, since
both bind ports 8080/8443. Expose the Deployment through the chart's Service.

### First production setup

1. **Give Warden a name.** `warden.home.lan` is the dashboard; `home.lan` is the
   WebAuthn RP ID. Create DNS records (or `/etc/hosts` entries) for the admin host
   and every route, all pointing at the Warden machine.

2. **Create a config.**

   ```bash
   warden init -o /etc/warden/warden.yaml \
     --admin-host warden.home.lan \
     --rp-id home.lan
   ```

   Then edit it. See [`warden.yaml.example`](warden.yaml.example)
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
example `http://10.0.0.5:3000/api`) is used as a prefix, unless the request path
already starts with it — `/api/users` is not sent on as `/api/api/users`.
WebSocket upgrades are
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
| `metrics_token` | unset | Bearer token for `/_warden/metrics`. When set, that endpoint (and the `/metrics` alias) also accepts `Authorization: Bearer <token>` or `?token=<token>` without a passkey session. Compare is constant-time. |
| `request_timeout_seconds` | `60` | Default upstream timeout. |
| `health_interval_seconds` | `30` | Dashboard health-check interval. |
| `cleanup_interval_seconds` | `3600` | How often expired sessions/challenges are pruned. Set `0` to disable. |
| `vacuum_enabled` | `true` | Run `VACUUM` after cleanup on SQLite (ignored on PostgreSQL, which uses autovacuum). |
| `max_vacuum_bytes` | `104857600` | Only vacuum SQLite when the database is larger than this many bytes. |
| `max_body_size_mb` | `10` | Maximum request body size in MB, enforced for both `Content-Length` and chunked uploads. |
| `max_sessions_per_user` | unset | Maximum concurrent sessions per user (`null` disables). |
| `require_otp_for_admins` | `false` | Refuse admin dashboard access until the admin has enrolled TOTP. The passkeys page stays reachable, so switching it on cannot lock anyone out. |
| `log_level` | `info` | `debug`, `info`, `warning`, `error`, or `critical`. |
| `log_file` | unset | Write logs to this path instead of stderr. |
| `log_rotation` | `size` | `size` for size-based rotation or `time` for time-based rotation. |
| `log_max_size_mb` | `10` | Rotate after this many MB (size mode). |
| `log_backup_count` | `5` | Number of rotated log files to keep. |
| `rate_limiter` | unset | Rate limiting: `backend` (`memory` or `redis`), `redis_url`, `ttl` (seconds). Memory is process-local; multi-worker requires Redis. |

### `server.tls`

| Key | Default | Purpose |
| --- | --- | --- |
| `enabled` | `false` | Serve HTTPS and the HTTP redirect/ACME companion. |
| `certfile` / `keyfile` | required | PEM certificate chain and private key. |
| `acme_webroot` | unset | Directory served at `/.well-known/acme-challenge/`. |
| `acme_directory` | unset | ACME directory URL for in-process issuance, e.g. `https://acme-v02.api.letsencrypt.org/directory`. |
| `acme_domain` | admin host | Domain requested when `acme_directory` is set. |
| `renew_command` | unset | Shell command run when renewal is due. |
| `renew_days_before` | `30` | Run the hook when the certificate has this many days left. |
| `check_interval_hours` | `12` | How often the renewal loop checks. |

Warden never reloads a certificate in place: after renewal, restart the
process (or use a certbot deploy hook that restarts it). The HTTP companion
stays up during renewal so webroot challenges keep working.

Setting `acme_directory` lets Warden issue the certificate itself through the
renewal loop and serve the HTTP-01 key authorization in memory, with no
`acme_webroot` needed. TLS still requires a readable certificate at startup, so
the **first** certificate comes from `acme_webroot` + certbot, or from a
placeholder written by `warden certs bootstrap`. The placeholder is self-signed:
browsers will warn until the real certificate arrives, and it does not help
validation, because HTTP-01 is fetched over plain HTTP on port 80 — the CA has to
be able to reach that port either way.

### `webauthn`

| Key | Default | Purpose |
| --- | --- | --- |
| `rp_id` | `localhost` | WebAuthn relying-party domain. Changing it invalidates passkeys. |
| `rp_name` | `Warden` | Name shown by the authenticator. |
| `require_user_verification` | `false` | Require PIN/biometric verification when authenticating. |
| `challenge_ttl_seconds` | `300` | Lifetime of a ceremony challenge. |
| `allowed_origins` | `[]` | Extra origins allowed to run passkey ceremonies. |

### `email`

Optional SMTP settings. When enabled, `POST /_warden/api/invites` emails the first-login invite token to the user's address instead of only returning it to the admin.

| Key | Default | Purpose |
| --- | --- | --- |
| `enabled` | `false` | Send invite emails through SMTP. |
| `host` | `localhost` | SMTP server hostname. |
| `port` | `587` | SMTP server port. |
| `user` | unset | SMTP username (omit for anonymous/relay auth). |
| `password` | unset | SMTP password. |
| `starttls` | `true` | Upgrade the SMTP connection with STARTTLS. |
| `ssl` | `false` | Use implicit TLS (SMTPS, usually port 465) instead of STARTTLS. Cannot be combined with `starttls`. |
| `from_address` | `warden@localhost` | `From:` address for invite mail. |
| `subject_prefix` | `Your first-login invite` | Subject prefix for invite mail. |

Keep SMTP credentials in a file readable only by the Warden service user. Invite
tokens are single-use and expire; email delivery failure is logged but does not
block invite creation, so the admin can still copy the token from the response.

### `database`

| Key | Default | Purpose |
| --- | --- | --- |
| `path` | `warden.db` | SQLite file path (when `type: sqlite`). |
| `type` | `sqlite` | `sqlite` or `postgres`. PostgreSQL adapter uses SQLAlchemy `asyncpg`; compatible with CockroachDB wire. |
| `url` | `postgresql+asyncpg://localhost/warden` | PostgreSQL URL (used when `type: postgres`). |

PostgreSQL / CockroachDB adapter (`warden.db_postgres.PostgresDatabase`) is provided for production or distributed deployments. SQLite remains the default (zero-config).

#### PostgreSQL setup

Install the PostgreSQL extra, create a database and role, then point Warden at it:

```bash
pip install 'warden[postgres]'

createuser --pwprompt warden
createdb --owner=warden warden
```

```yaml
database:
  type: postgres
  url: postgresql+asyncpg://warden:secret@localhost:5432/warden
```

The adapter uses SQLAlchemy Core with `asyncpg`; CockroachDB works over its PostgreSQL wire protocol. Warden creates and migrates the schema on startup. `warden backup` only handles SQLite — for PostgreSQL use `pg_dump` (or your managed provider's snapshot tooling).

The database stores the admin account, passkey public keys, hashed sessions, mesh private keys, challenges, settings, and the audit log. Back it up and keep it private.

### Database schema and migrations

Warden ships with an embedded, transactional schema-migration system so that upgrading between versions never leaves the database behind. The current schema version is defined by the `SCHEMA_VERSION` constant (currently `8`). Each upgrade step is a plain-SQL script stored in the `_MIGRATIONS` dictionary, keyed by the target version:

- **v1** – Users, settings, and the audit log (initial schema).
- **v2** – WireGuard `mesh_peers` table for peer configuration.
- **v3** – Credentials, sessions, challenges, backup codes, and OTP secrets (passkeys and MFA).
- **v4** – `invites` table for first-login passkey registration.
- **v5** – `users.email` column for invite delivery and account notices.
- **v6** – `acl_groups` / `acl_members` for per-route ACLs; every account joins the seeded `Users` group.
- **v7** – `otp_secrets.verified`, `pending_secret`, `pending_created_at`, so an enrolment never clobbers a working authenticator.
- **v8** – `otp_secrets.last_used_counter`, so an accepted TOTP code cannot be replayed inside its drift window.

When `Database.init()` runs, it reads the highest `version` already recorded in `schema_migrations` and applies every script for versions greater than that, in order, inside a single `BEGIN IMMEDIATE` transaction. If the DB already contains a newer version than this build supports, initialization fails loudly instead of silently applying a stale schema. SQLite runs the migration inside `BEGIN IMMEDIATE`; PostgreSQL inlines the same logic with `async with self.engine.begin()` and uses PostgreSQL-native types (`BIGINT GENERATED ALWAYS AS IDENTITY`, `DOUBLE PRECISION`, `BYTEA`, `BOOLEAN`, etc.).

The SQL scripts in `warden/db.py` and `warden/db_postgres.py` are the single source of truth for the schema. To add a new migration, bump `SCHEMA_VERSION`, append the DDL to `_MIGRATIONS`, and add the corresponding PG type mappings to `PostgresDatabase`'s script.

### `mesh` and `routes`

See the fully commented example in
[`warden.yaml.example`](warden.yaml.example). Route fields:

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
| `websocket_subprotocols` | `[]` | Allowed WebSocket subprotocols (e.g., `graphql-ws`). Empty = allow all. |
| `websocket_max_size` | `16777216` | Maximum size in bytes of a single incoming WebSocket message. |
| `allowed_ips` | `[]` | CIDR networks allowed to access this route. Unparseable client IPs are denied when this is set, and IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are matched against IPv4 networks. |
| `denied_ips` | `[]` | CIDR networks explicitly blocked from this route. Checked before `allowed_ips`; IPv4-mapped addresses are compared as IPv4. |
| `blocked_user_agents` | `[]` | Substrings matched case-insensitively against `User-Agent`; matches get `403`. |
| `blocked_paths` | `[]` | Exact paths or `prefix/*` patterns blocked with `403`. Matching ignores `.`/`..` segments, duplicate and trailing slashes, so `/public/../secret` is blocked too. |
| `allowed_groups` | `[]` | ACL groups allowed to reach this route. Empty means every signed-in user, so ACLs stay optional. Requires `auth: true`; admins always pass. |
| `rate_limit` | unset | Per-route limit in requests per minute. `null` disables per-route limiting (falls back to the global limiter). |

## User Access Control

Access is binary: an account is either admin (`is_admin: 1`) or not. Only admin
accounts can access the dashboard and manage users, routes, TLS, mesh, or audit
logs. The `Users` page lets administrators view users and toggle the `is_admin`
flag. There is no second-tier "roles" system — every privileged action is gated
on the `is_admin` flag.

### Per-route ACLs

Group ACLs are opt-in. Every account joins the built-in `Users` group when it is
created, and a route with no `allowed_groups` stays open to every signed-in user,
so an instance that never touches ACLs behaves exactly as it did before.

To restrict a route, list one or more group names in `allowed_groups`:

```yaml
routes:
  - host: media.home.lan
    upstream: http://192.168.1.20:8096
    allowed_groups: [Family]
```

Membership is managed on the `Users` page: create groups there, tick them in a
user's edit dialog, and set the groups for a service in the dashboard's
*Advanced routing* section (comma separated). Admins always pass group ACLs.
Group names are case-insensitive and whitespace-normalised. Deleting a group a
route still references leaves that route reachable by admins only, so update the
route before removing the group.

### Inviting a user

New accounts start with no passkey and cannot sign in until they register one.
The admin creates the account and a single-use invite:

1. `POST /_warden/api/users` creates the user (optionally with `email`). The
   account is locked until it has a passkey.
2. `POST /_warden/api/invites` with `{"user_id": 2, "expires_in": 86400}`
   returns a one-time token. If `email.enabled` is true, the token is also
   emailed to the user's address.
3. The user opens `/_warden/invite/complete?token=...`, which runs
   `POST /_warden/auth/invite/begin` and registers a passkey via
   `POST /_warden/auth/invite/complete`. The invite is consumed only after the
   passkey verifies successfully, so a failed ceremony can be retried with the
   same token until it expires.

Invites are hashed at rest, expire (default `86400` seconds), and are marked
used exactly once.

---

## API reference

All mutations require an authenticated admin session, the admin `Host`, and the
`X-Warden-Request: 1` header. The live OpenAPI schema is served at
`/_warden/openapi.json` (Swagger UI at `/_warden/docs`).

### Authentication and setup

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/_warden/health` | Public liveness/version/setup status. |
| `POST` | `/_warden/auth/setup/begin` | Start first-run admin passkey registration. |
| `POST` | `/_warden/auth/setup/complete` | Finish first-run registration and create the admin session. |
| `POST` | `/_warden/auth/login/begin` | Start passkey sign-in. |
| `POST` | `/_warden/auth/login/complete` | Finish passkey sign-in. |
| `POST` | `/_warden/auth/login/backup` | Sign in with a backup code. |
| `POST` | `/_warden/auth/logout` | Revoke the current session. |
| `POST` | `/_warden/auth/invite/begin` | Start invited-user passkey registration. |
| `POST` | `/_warden/auth/invite/complete` | Finish invited-user registration. |
| `POST` | `/_warden/auth/login/otp` | Finish a sign-in that requires a TOTP code. |
| `POST` | `/_warden/auth/otp/setup` | Provision TOTP for the current user (stored pending). |
| `GET` | `/_warden/auth/otp/status` | Report the current user's two-factor state. |
| `POST` | `/_warden/auth/otp/verify` | Verify a TOTP code and enable the pending secret. |
| `POST` | `/_warden/auth/otp/disable` | Remove TOTP (requires a current code). |
| `POST` | `/_warden/auth/register/begin` | Add another passkey for the current user. |
| `POST` | `/_warden/auth/register/complete` | Finish adding a passkey. |
| `GET` | `/_warden/auth/unsupported` | Explain that a browser lacks WebAuthn/secure-context support. |
| `GET` | `/_warden/login` | Sign-in page (redirects an existing session). |
| `GET` | `/_warden/setup` | First-run registration page. |
| `GET` | `/_warden/invite/complete` | Invited-user registration page (`?token=...`). |
| `GET` | `/_warden/openapi.json` | OpenAPI schema (admin host). |
| `GET` | `/_warden/docs` | Swagger UI (admin host). |

### Dashboard pages

These HTML pages are served only on the admin host and require a session
(except during first-run setup). Admin pages additionally require the
`is_admin` flag; non-admins get the portal and their own credential pages.

| Path | Purpose |
| --- | --- |
| `/` | Overview dashboard (admins; non-admins are redirected to `/portal`). |
| `/portal` | Signed-in landing page: links to every enabled service, plus the user's own passkeys, sessions, and backup codes. |
| `/activity` | Audit log, with JSON/CSV export. |
| `/backup_codes` | Recovery codes and one-time code generation. |
| `/config` | YAML editor, validation, import/export. |
| `/mesh` | WireGuard peers, hub key, apply/status. |
| `/passkeys` | Registered passkeys and active sessions. |
| `/tls` | Certificate status and renewal. |
| `/users` | User list, invites, admin flag. |
| `/metrics/view` | In-app metrics snapshot. |

### Admin API

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/_warden/api/status` | Instance status snapshot. |
| `GET` | `/_warden/api/database/health` | Database health. |
| `POST` | `/_warden/api/users` | Create a user (optionally with `email`). |
| `PATCH` | `/_warden/api/users/{id}` | Update display name, email, or `is_admin`. |
| `DELETE` | `/_warden/api/users/{id}` | Delete a user and their credentials/sessions. |
| `POST` | `/_warden/api/users/{id}/otp/reset` | Clear another user's TOTP enrolment (admins cannot clear their own here). |
| `POST` | `/_warden/api/invites` | Create a single-use first-login invite. |
| `POST` | `/_warden/api/services` | Add a route. |
| `PUT` | `/_warden/api/services/{host}` | Replace a route. |
| `DELETE` | `/_warden/api/services/{host}` | Delete a route. |
| `GET` | `/_warden/api/config` | Export the effective YAML. |
| `GET` | `/_warden/api/config/export` | Download the YAML file. |
| `POST` | `/_warden/api/config/import` | Import YAML (validated). |
| `POST` | `/_warden/api/config/validate` | Validate YAML without saving. |
| `POST` | `/_warden/api/config` | Save YAML changes. |
| `PATCH` | `/_warden/api/passkeys/{id}` | Rename a passkey. |
| `DELETE` | `/_warden/api/passkeys/{id}` | Remove a passkey. |
| `DELETE` | `/_warden/api/sessions/{id}` | Revoke one session. |
| `POST` | `/_warden/api/sessions/revoke-others` | Revoke all other sessions. |
| `GET` | `/_warden/api/backup_codes` | List backup codes. |
| `POST` | `/_warden/api/backup_codes` | Generate a backup code and return its plaintext once. |
| `POST` | `/backup_codes/generate` | Dashboard form: generate a code and render it once. |
| `GET` | `/_warden/api/audit/export` | Export audit events (`limit`, `offset`, optional `event`; JSON or `format=csv`). |
| `POST` | `/_warden/api/mesh/peers` | Add a WireGuard peer. |
| `GET` | `/_warden/api/mesh/peers/{id}/config` | Download a peer config. |
| `DELETE` | `/_warden/api/mesh/peers/{id}` | Remove a peer. |
| `POST` | `/_warden/api/mesh/apply` | Write and apply the hub config. |
| `GET` | `/_warden/api/mesh/status` | Interface and peer status. |
| `POST` | `/_warden/api/mesh/rotate-hub-key` | Rotate the hub key. |
| `POST` | `/_warden/api/proxy/reset-clients` | Drop pooled upstream clients. |

### Metrics

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/_warden/metrics` | Prometheus metrics (admin host/session). |
| `GET` | `/metrics` | Alias for the metrics endpoint. |
| `GET` | `/metrics/view` | HTML metrics snapshot. |

## Monitoring & Metrics

Warden exposes a rich set of Prometheus metrics at `GET /_warden/metrics`
(admin host, authenticated session):

* `warden_uptime_seconds` – process uptime.
* Per‑host request, error, latency, and authenticated request counters (`warden_route_*`).
* Authentication counters: `warden_auth_success_total` and `warden_auth_failure_total`.
* OTP counters: `warden_otp_success_total` and `warden_otp_failure_total`.
* Backup‑code counter: `warden_backup_code_used_total` – total times a backup code was used for login.

A starter Grafana dashboard is provided in `grafana/warden-dashboard.json`
(uid `warden-dashboard`, schema version 41). Import it with a `Prometheus`
datasource.

### Scraping with Prometheus

`/_warden/metrics` is admin-host protected: it requires the admin `Host` and a
valid passkey session. Browsers are redirected to the sign-in page; machine
clients (Prometheus, curl) get `401` JSON, never an HTML page.

For unattended scraping, set `server.metrics_token` to a long random value
(`openssl rand -hex 32`) and let Prometheus send it as a bearer token — no
session needed. Without a token, put a small reverse proxy in front of Warden
that injects the session cookie. Example `prometheus.yml` scrape config
(`job_name: warden_scrape`):

```yaml
scrape_configs:
  - job_name: 'warden_scrape'
    scrape_interval: 15s
    metrics_path: /_warden/metrics
    scheme: https
    bearer_token: '<server.metrics_token>'
    tls_config:
      insecure_skip_verify: true  # only if using self-signed TLS
    static_configs:
      - targets: ['warden-host:8443']
        labels:
          instance: 'warden-homelab'
```

The token is accepted as `Authorization: Bearer <token>` or `?token=<token>`,
and only unlocks the two metrics endpoints. Treat it like a password: it grants
read access to your traffic, auth, and mesh-handshake counters.

For cookie/session scraping (not recommended for Prometheus): use `scrape_interval` with `relabel_configs` that inject the session header via the `proxy_url` or a sidecar. The simpler path: run a small nginx/traefik sidecar on the cluster that proxies `/metrics` to the Warden admin port with basic auth, and point Prometheus at the proxy.

### In-app metrics

The live snapshot is viewable inside the app at `/metrics/view` (admin-host protected). It shows per-host state, request counts, errors, latency, and recent traffic events — useful before opening Grafana.

### Grafana wiring

1. Add a `Prometheus` datasource in Grafana → `http://prometheus:9090`.
2. Import `grafana/warden-dashboard.json`: **Dashboards → New → Import dashboard**
   (Grafana 13), then **Upload dashboard JSON file**. The file is a plain
   dashboard model, not a legacy `{"dashboard": …, "overwrite": …}` export
   envelope — Grafana 13 rejects the wrapped form.
3. Map the `Prometheus` input (`DS_PROMETHEUS`) to your datasource on the import
   screen.
4. The dashboard queries `warden_uptime_seconds`, `sum(warden_route_requests_total)`,
   `warden_auth_success_total`, etc., from the Prometheus server.
5. No additional Grafana plugin is needed (plain Prometheus expressions).

## Dashboard

The admin dashboard has these pages:

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
- **Portal** — the signed-in landing page for every user. Lists all enabled
  services with deep links and marks which ones are public. Non-admins land here
  when they open `/`; admins reach it from the sidebar.

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

### Running the mesh in Kubernetes / Docker Swarm

WireGuard is container-unfriendly: `wg0` is a host-level interface and
`wg-quick up` needs `NET_ADMIN`, `/dev/net/tun`, and (for `iptables`/`sysctl`)
root, all of which containers lack. For in-cluster deployments:

**Kubernetes** — run Warden as a privileged **DaemonSet** with `hostNetwork: true`:

```bash
kubectl apply -f deploy/helm/warden-mesh-daemonset.yaml
```

The manifest runs the container `privileged` with `hostNetwork: true`, mounts the
host `/etc/wireguard`, and exposes port 51820 (UDP) for peers dialing the node IP
via `mesh.endpoint`. It runs one pod per node so each peer can reach every other
node. The Warden proxy stays exposed via the chart's standard Service on ports
8080/8443.

**Docker Swarm** — same approach with `docker network connect host` / `--restart unless-stopped` and a `deploy.placement: constraints=[node.platform==linux]` rule. Peer `mesh.endpoint` must point at the worker's IP address, not a service DNS name.

In both cases `mesh.enabled: true` must stay off by default; enable it only when you've provisioned the privileged DaemonSet or host-managed interface yourself.

`mesh apply` is manual by design. Peer changes are saved immediately, but the
interface is only updated when you apply from the dashboard or CLI.

## CLI

```text
warden [--config PATH] COMMAND

serve                 run the proxy and dashboard
  --host ADDR         bind override
  --port PORT         HTTP port override
  --https-port PORT   HTTPS port override
  --dev-tls           generate/use a self-signed cert and force HTTPS
  --tls-dir PATH      directory for --dev-tls cert/key (default: .warden/dev-tls)
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

config show            print effective warden.yaml

certs status [--json]
certs renew [--dry-run]
certs bootstrap [--force]
                      write a self-signed placeholder at the configured paths so
                      TLS startup can run before the first ACME certificate exists

backup                write a timestamped, mode-0600 SQLite backup next to the DB

auth reset [--yes]    delete the account, passkeys, sessions, settings, audit log, and mesh peers
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

## OTP (One-Time Password)

Warden supports optional TOTP‑based two‑factor authentication. It is opt-in per
account: sign-in only asks for a code once that account has enrolled.

* **Enrol on the passkeys page.** `/passkeys` has a **Two-factor** panel. It
  calls `POST /_warden/auth/otp/setup`, shows the Base32 secret and the
  `otpauth://` URL for Google Authenticator, Authy, or any TOTP app, and enables
  the secret only after `POST /_warden/auth/otp/verify` accepts a code from it.
  The new secret is stored as *pending*, so abandoning the flow leaves a working
  secret untouched. The endpoints are CSRF‑protected (`X-Warden-Request: 1` and
  same‑origin).

* **Sign-in asks for the code.** When an enrolled user finishes the passkey
  ceremony, `POST /_warden/auth/login/complete` returns `otp_required` and a
  short-lived challenge instead of a session. The sign-in page shows a code
  field and posts to `/_warden/auth/login/otp`, which creates the session only
  after the code verifies. A mistyped code can be retried without repeating the
  passkey ceremony; the challenge expires after five minutes and is spent on
  success.

* **Turn it off again.** `POST /_warden/auth/otp/disable` requires a current
  code, so a stolen session cannot silently drop the second factor.
  `GET /_warden/auth/otp/status` reports `{"enabled": …, "pending": …}`.

* **Recovery codes still work.** A backup code is a single-use 64-bit factor in
  its own right, so `POST /_warden/auth/login/backup` finishes sign-in without a
  TOTP code. Without that rule a lost authenticator would need
  `warden auth reset` on the server.

* **Rate limiting** – 30 attempts per minute per IP for management endpoints and
  10 per minute for the sign-in step, which allows in-place retries.

* **Metrics** — Success and failure counters are exposed at `/_warden/metrics`,
  visualised in the Grafana dashboard, and available as a live snapshot inside
  the app at `/metrics/view` (admin-host protected).

* **A code works once.** The accepted time-step is recorded in
  `last_used_counter` by the same `UPDATE` that verifies the code, so replaying
  a code — or an older step still inside the drift window — is refused, and two
  concurrent requests cannot both spend it.

* **An admin can reset someone else's second factor.** The Users page has a
  **Reset 2FA** action for enrolled accounts, and
  `POST /_warden/api/users/{id}/otp/reset` does the same over the API. Your own
  factor is refused there: removing it requires a current code on the passkeys
  page, so a stolen admin session cannot silently drop it.

* **Require it for admins.** Set `server.require_otp_for_admins: true` and an
  admin without an enrolled authenticator is confined to the passkeys page until
  they enrol one; every other dashboard page redirects there (API clients get
  `403` with `otp_setup_required: true`). Because enrolment stays reachable, the
  policy cannot strand a deployment.

* **Storage** – The secret (or pending secret) is stored next to the account in
  SQLite/PostgreSQL; codes are time-based and generated by the client. A code
  stays valid for its 30-second step, plus one step either side for clock drift.

## Backup codes UI

The admin dashboard includes a **Backup Codes** page at `/backup_codes`. It lists
the current admin user's recovery codes with creation and usage timestamps. The
**Generate New Backup Code** button creates one 16-character code (64 bits), stores
only its hash, and shows the plaintext once so it can be copied. Backup codes are
single-use and log in through `POST /_warden/auth/login/backup`.

- `POST /_warden/api/backup_codes` – creates a backup code and returns the plaintext once.
- `POST /backup_codes/generate` – dashboard form that renders the plaintext once.
- `POST /_warden/auth/login/backup` – logs in using a backup code.

The metric `warden_backup_code_used_total` records each successful backup‑code login.

## Backup and recovery

Back up your configuration, database, and TLS certificates.

- the YAML config (contains secrets such as mesh settings and renewal hooks),
- the SQLite database — run `warden backup` for an atomic, mode-0600 copy, or
  stop Warden and copy the file,
- TLS certificates and keys if not managed by certbot.

`warden backup` writes `warden.db.backup-YYYYMMDD-HHMMSS` next to the configured
database. It is SQLite-only; use `pg_dump` for PostgreSQL.

To recover access when every passkey is lost:

```bash
warden auth reset --yes
# restart Warden and use the newly printed setup code
```

This deletes the admin account, all passkeys, sessions, settings, audit log, and
mesh peers (complete system reset). To start the whole instance over, remove the
database as well.

## Contributing and docs

Development setup, coding style, the test suite, schema migrations, the release
process, and an architecture glossary live in
[`CONTRIBUTING.md`](CONTRIBUTING.md). Supporting documents:

- [`SECURITY.md`](SECURITY.md) — vulnerability reporting and disclosure policy.
- [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) — community expectations.

## License

MIT. See [LICENSE](LICENSE).

## Sponsors

[![Powered by DartNode](dartnode-logo.png)](https://dartnode.com/open-source "Powered by DartNode - Free VPS for Open Source")


<!-- Verified on DartNode: DNOS-111A35E3 -->
