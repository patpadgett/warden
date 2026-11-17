# Contributing to Warden

We welcome contributions! This guide will help you get started.

## How to Contribute

1. **Fork the repository** on GitHub.
2. **Clone your fork** locally:

   ```bash
   git clone https://github.com/patpadgett/warden.git
   cd warden
   ```

3. **Create a virtual environment** and install development dependencies:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -e '.[dev]'
   ```

4. **Make your changes**.  Follow the project's coding style:
   - Use `ruff` formatting (line length 100, `py311`).
   - Add type hints where appropriate.
   - Update or add unit tests under `tests/`.
   - Ensure `pytest` passes (`pytest -q`).
   - Verify coverage is tracked (`pytest --cov=warden`); current baseline ~78% (fail-under 75).
   - Note: docstrings are kept concise and single; `ConfigManager` duplicate was cleaned.

5. **Run the test suite**:

   ```bash
   pytest
   ```

6. **Commit your changes** with a clear commit message.

7. **Push to your fork** and open a Pull Request against `main`.

## Pull Request Checklist

- [ ] Code builds (`python -m build` succeeds).
- [ ] All tests pass (`pytest -q`).
- [ ] New code has test coverage.
- [ ] Documentation is updated (docstrings, README, etc.).
- [ ] Linting passes (`ruff check .`).

## Coding Style

- Follow the existing code style (see `.ruff` configuration).
- Use `black`/`ruff` formatting.  The project uses `ruff` as the primary formatter.
- Write docstrings in Google style.

## Versioning

Versions come from git tags via [setuptools-scm](https://setuptools-scm.readthedocs.io/);
do not edit a version string in `pyproject.toml`.

- **Tagged release**: create an annotated tag such as `v1.2.3` on `main` and push it:

  ```bash
  git tag -a v1.2.3 -m "Warden 1.2.3"
  git push origin v1.2.3
  ```

  The `Release` workflow builds the sdist/wheel, publishes them to PyPI via
  trusted publishing (OIDC), and creates a GitHub release with the artifacts.

- **Development checkout**: an untagged commit on `main` reports a development
  version such as `1.2.4.dev5` (commits since the last tag). `warden --version`
  prints whatever setuptools-scm resolves.

- **PyPI setup (one-time)**: create the `warden-mesh` project on PyPI and add
  this repository as a trusted publisher (GitHub Actions, environment `pypi`).
  Until that is configured, the `publish-pypi` job will fail; the GitHub release
  job still runs. Trusted publishing requires no API token secret.

## Database schema and migrations

Warden ships with an embedded, transactional schema-migration system so that
upgrading between versions never leaves the database behind. The current schema
version is defined by the `SCHEMA_VERSION` constant (currently `5`). Each upgrade
step is a plain-SQL script stored in the `_MIGRATIONS` dictionary, keyed by the
target version:

- **v1** – Users, settings, and the audit log (initial schema).
- **v2** – WireGuard `mesh_peers` table for peer configuration.
- **v3** – Credentials, sessions, challenges, backup codes, and OTP secrets (passkeys and MFA).
- **v4** – `invites` table for first-login passkey registration.
- **v5** – `users.email` column for invite delivery and account notices.

When `Database.init()` runs, it reads the highest `version` already recorded in
`schema_migrations` and applies every script for versions greater than that, in
order, inside a single `BEGIN IMMEDIATE` transaction. If the DB already contains a
newer version than this build supports, initialization fails loudly instead of
silently applying a stale schema. SQLite runs the migration inside
`BEGIN IMMEDIATE`; PostgreSQL inlines the same logic with
`async with self.engine.begin()` and uses PostgreSQL-native types
(`BIGINT GENERATED ALWAYS AS IDENTITY`, `DOUBLE PRECISION`, `BYTEA`, `BOOLEAN`,
etc.).

The SQL scripts in `warden/db.py` and `warden/db_postgres.py` are the single
source of truth for the schema. To add a new migration, bump `SCHEMA_VERSION`,
append the DDL to `_MIGRATIONS`, and add the corresponding PG type mappings to
`PostgresDatabase`'s script.

## Test suite

The suite covers config validation, YAML round-tripping, SQLite persistence, TLS
inspection, mesh configs, authentication ceremonies (with mocked WebAuthn
verification), HTTP proxy behavior, admin APIs, WebSockets, and the CLI. It does
not replace a real browser passkey ceremony.

ACME issuance has a second, opt-in check that the suite cannot host: it starts a
real Pebble CA and a real `warden serve`. Run it after touching `warden/tls.py`,
the challenge route, or the renewal loop:

```bash
python scripts/pebble_issuance.py
```

The first run downloads the pinned Pebble binary into `tmp/pebble-cache/`; both
processes bind free loopback ports. It exits non-zero and keeps its scratch
directory when a check fails.

The Redis rate limiter has a similar opt-in check. `tests/test_rate_limiter_redis.py`
runs against a real server and skips when none answers, so point it at one (CI
starts a `redis:7` service):

```bash
redis-server --daemonize yes   # or export WARDEN_TEST_REDIS_URL
pytest tests/test_rate_limiter_redis.py
```

Without a server those tests skip silently; they fail only when Warden writes
nothing to Redis or stops blocking after the configured limit.

To run against a development config:

```bash
WARDEN_CONFIG=./warden.dev.yaml warden serve --host 127.0.0.1
```

## Architecture glossary

Terms naming seams and modules in this codebase:

- **Route** (`RouteConfig`) — a configured upstream service; the unit of proxy routing, metrics, and health checks.
- **Order** — not used here; the domain term for a routed proxy request is `RouteConfig` + `TrafficEvent`.
- **Mesh** (`MeshManager`) — WireGuard peer network managed by Warden; includes hub key, peer config, and apply lifecycle.
- **MeshPeerIntake** — deepened intake module (DB validation, address assignment, name regex, config render); backed by `MeshApplyAdapter` for apply/status.
- **MeshApplyAdapter** — apply adapter for WireGuard (`apply`, `status`, `refresh_handshakes`) backed by `wg`/`wg-quick`; routed through `MeshManager` facade.
- **Peer intake** — the sub-module of mesh responsible for peer validation and DB storage; deepened form is `MeshPeerIntake`.
- **Metrics module** (`MetricsModule`) — in-memory traffic recording, health monitoring, and Prometheus export; deepened into `MetricsModule` (stats) + `HealthMonitor` adapter (health adapter).
- **Health adapter** — the adapter that takes health checks from `Stats` and exposes them to external consumers (dashboard / Prometheus).

If you encounter a bug or have a feature request, please open an issue on GitHub with:
- A clear description.
- Steps to reproduce (if applicable).
- Expected vs. actual behavior.
