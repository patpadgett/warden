## Audit Summary  

### Critical / Security Bugs  
| ID | Location | Issue | Severity |
|------|----------|-------|----------|
| **B1** | `warden/db.py:838‑846` | `reset_auth()` does not delete `credentials`, `sessions`, `challenges`, `backup_codes`, `otp_secrets`, `invites` when wiping a user. | Critical |
| **B2** | `warden/db_postgres.py:768‑779` | Orphaned `async with` block – missing `async def reset_auth` signature, causing a syntax error / broken cleanup. | Critical |
| **B3** | `warden/db.py` | `create_user` / `_user()` reference an `email` column that does not exist until migration v5, while `_SCHEMA` (v1) lacks it. | Critical |

### High / Functional Bugs (to be addressed after critical)  
| ID | Location | Issue |
|----|----------|-------|
| **B4** | `warden/proxy.py:530` | 1xx HTTP status codes are not short‑circuited; request continues unnecessarily. |
| **B5** | `warden/middleware.py:379` | Admin WebSocket connection is rejected with 4404 because `route=None` is passed. |
| **B6** | `warden/cli.py:371` | Hard‑coded path `/tmp/opencode/warden-dev-tls`; should be configurable. |
| **B7** | `warden/auth/passkeys.py:183‑213` | When `WARDEN_SETUP_TOKEN` is set, `prepare_setup_code` returns `(None, expires)` → banner never prints the setup code. |
| **B8** | `warden/config.py:158‑166` | Allows non‑standard WebAuthn RP IDs (`127.0.0.1`, `::1`). |
| **B9** | `warden/__init__.py` vs `warden/_version.py` | Version mismatch (`0.1.0` vs vcs‑generated `0.1.2.dev28+gdc0127c35.d20261104`). |
| **B10** | `warden/README.md` | `SCHEMA_VERSION` says “3” but actual is 5; missing invite flow, backup command, `--dev-tls`, API reference, many config options, email section, PostgreSQL setup. |
| **B11** | `warden/docs/tickets.md` | Claims about test counts / specific test files; no `tests/` directory in repo → unverifiable. |
| **B12** | `warden/auth/routes.py` | Invite flow may lock out users (line 338) if `create_user` is called with an existing email that hasn't been verified. |
| **B13** | `warden/db.py` | `reset_auth()` does not clear `backup_codes`, `otp_secrets`, `invites` (duplicate of B1). |
| **B14** | `warden/db_postgres.py` | Orphaned `async with` block (duplicate of B2). |
| **B15** | `warden/cli.py` | Hard‑coded TLS path (duplicate of B6). |
| **B16** | `warden/config.py` | Missing documentation for several `ServerConfig` fields (lines 234‑260). |

### Documentation Gaps  

| Category | Missing / Inaccurate Docs |
|----------|---------------------------|
| **Missing entirely** | Invite flow description, `warden backup` command, `--dev-tls` flag, full API reference, email handling, PostgreSQL setup instructions, detailed list of ~15 config options. |
| **Inaccurate / outdated** | `README.md` `SCHEMA_VERSION` (states “3” vs actual “5”), version badge inconsistency (`__init__.py` vs `_version.py`). |
| **Completeness** | Docs files (`README.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `docs/tickets.md`) do not enumerate every user‑facing feature (e.g., mesh apply, mesh peer, admin routes, backup/restore, TLS management). |

### Improvement Plan (Phase 1 – Critical Bugs)  

1. **Fix B1 & B13** – Extend `reset_auth()` in `warden/db.py` to delete all credential‑related tables/collections (`credentials`, `sessions`, `challenges`, `backup_codes`, `otp_secrets`, `invites`).  
2. **Fix B2 & B14** – Add proper `async def reset_auth` signature to `warden/db_postgres.py` and clean up the orphaned `async with` block.  
3. **Fix B3** – Align `email` column handling: either add `email` to the v1 `_SCHEMA` (temporarily) or update `create_user`/`_user()` to handle the missing column until the v5 migration runs.  

### Next Steps  

- **Write the audit output** to `/home/pat/projects/warden/docs/code-work.md`.  
- **Switch to an implementation agent** (e.g., the “general” or “code‑review” sub‑agent) so I can start editing the code and the documentation file.  

---

**Please confirm** that you’d like me to:

1. Proceed with writing the above content to `docs/code-work.md`, **and**  
2. Switch to an implementation agent (or otherwise indicate you’re ready for me to start editing code).

Once you give the go‑ahead, I’ll create the file and begin the critical bug fixes.

---

## Implementation status (2026-11-07)

### Fixed in this pass

| ID | Change |
|----|--------|
| **B1 / B13** | `Database.reset_auth()` now clears `challenges`, `credentials`, `sessions`, `backup_codes`, `otp_secrets`, and `invites` before deleting users. |
| **B2 / B14** | Added the missing `PostgresDatabase.reset_auth` method; it deletes invites, users, credentials, sessions, challenges, backup codes, OTP secrets, settings, audit rows, and mesh peers. |
| **B3** | Email handling is now tolerant of pre-v5 schemas: `_user()` / `_session()` default to `None`, `create_user()` omits the column until it exists, and `update_user_email()` returns `False` instead of raising. The PostgreSQL adapter gained the `email` column, migration v5, `create_user(email=...)`, and `update_user_email()`. |
| **B4** | `ProxyEngine.handle_http` now rejects any upstream status `< 200` (informational responses), including `101`. |
| **B5** | Re-evaluated: `4404` is a valid private-use WebSocket close code and is asserted by `tests/test_ws.py`; left unchanged. |
| **B6 / B15** | `warden serve --tls-dir` is configurable; the default remains `/tmp/opencode/warden-dev-tls`. |
| **B7** | Startup banner now keys the “first-run setup” branch on `setup_expires` rather than the presence of `WARDEN_SETUP_TOKEN`, so an already-claimed instance is not mislabelled. |
| **B8** | WebAuthn RP IDs reject all bare IP addresses, including loopback. |
| **B9** | `warden.__version__` now imports the generated `_version.py` value, with a `0.1.0` fallback. |
| **B12** | Invite tokens are consumed only after the passkey verifies and the credential is saved; failed ceremonies no longer burn the invite. |
| **B16** | README and `warden.yaml.example` document all `ServerConfig` fields, the `email` section, invites, `warden backup`, `--dev-tls` / `--tls-dir`, PostgreSQL setup, schema v4/v5, and the admin/auth API surface. |
| — | Added a `postgres` extra to `pyproject.toml` (`sqlalchemy`, `greenlet`, `asyncpg`). |
| — | Implemented `create_invite`, `get_invite`, and `mark_invite_used` on `PostgresDatabase`; previously they were inherited from the SQLite class and would fail on a PostgreSQL connection. Session lookups now also select `users.email`. |
| — | Fixed `WardenMiddleware` clobbering `scope["app"]` with an `APIRouter`, which broke auth/admin routes on FastAPI 0.162 / Starlette 1.10. |
| — | Restored HTTP proxy dispatch in `WardenMiddleware._handle_http` (it was calling the FastAPI app for every non-admin host instead of `ProxyEngine.handle_http`). Disabled routes now show the “This service is paused” page. |

### Verification

- `pytest` (full suite): **389 passed**, coverage **78.12%**.
- `tests/test_db.py`, `test_db_postgres.py`, `test_config.py`, `test_invite_flow.py`, `test_app.py`, `test_ws.py`, `test_proxy_targeted.py`, `test_cli.py`, and `test_main_helpers.py` all pass.
- `docs/tickets.md` test-count references have been updated to 389.

### Remaining / follow-up

- The audit’s B10/B11 items are documentation-only and largely addressed above; no further code changes are required.
- The working tree also contains pre-existing uncommitted edits in `warden/admin/routes.py`, `warden/auth/routes.py`, and `warden/templates/base.html`; they were left intact.
