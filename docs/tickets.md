# Warden source audit — tracked ticket list

Audit run: 2026-11-02 (EST). No files were changed during the audit.

## Priority legend
- S = Security (must fix before anything else)
- H = High (functional/operational)
- M = Medium
- L = Low (cosmetic/deferred)

## Open tickets

| ID | Priority | Finding | Module / file | Status |
|----|----------|---------|---------------|--------|
| T0 | S | **Missing `is_admin` enforcement on admin pages & API mutations** — any authenticated (non-admin) user can view/edit users and mutate routes, config, mesh, backup codes, and audit export. Fix: require `_require_admin` in the middleware's admin block. | `warden/middleware.py` `_handle_http` | OPEN — awaiting direction; highest priority |
| T1 | H | **No passkey-based self-registration for users created by the admin.** `create_user` stores `webauthn_user_id=os.urandom(16)` and no passkey; there is no invite/registration flow, so created users are permanently locked out. | `warden/admin/routes.py` `create_user` | BLOCKED — needs design; conflicts with single-admin default posture |
| T2 | L | **Config import `db_sql` field is dead.** `ImportPayload` declared `db_sql` but the import handler never used it. | `warden/admin/routes.py` `ImportPayload` | FIXED — field removed; model now rejects unknown fields (`extra="forbid"`) |
| T3 | L | **Audit/activity pagination is hard-coded** (export `limit=500`, activity `150`). No `offset`/load-more or `since` filter. | `warden/admin/routes.py` + templates | FIXED — export supports `limit`/`offset` (+ total); activity supports `since` filter and hidden `since` input |
| T4 | M | **No DB schema-migration or backup tooling.** Migrations live only in embedded SQL strings; there is no guided backup command. | `warden/db.py` + CLI | FIXED — added `warden backup` (atomic SQLite `.backup`, mode 0600) |
| T5 | L | **Footer `app_version` is undefined.** `base.html` rendered `{{ app_version }}` but no template context supplied it, so every admin page showed "warden v". | `warden/main.py` `_error_response`, `warden/admin/routes.py` `_base_context` | FIXED — `app_version` exposed as a template global in `warden/templating.py` |
| T6 | H | **VACUUM silently never runs.** `Database.vacuum()` executed `PRAGMA database_path`, which returns no rows, so the path came back empty and the reclaim step was skipped. | `warden/db.py` `vacuum()` | OPEN |
| T7 | L | **Dead `request.stream()` no-op in `handle_http`.** `request.stream() if has_body else b""` discarded its result and may advance the ASGI receive iterator unexpectedly. | `warden/proxy.py` `handle_http` | OPEN |
| T8 | L | **Dashboard "Last sign-in" reads "never" even after sign-ins.** It reads the last of the most-recent 60 audit events, which can be older than today's sign-ins. | `warden/admin/routes.py` `dashboard` | OPEN |
| T9 | M | **Config-save in-memory config diverges from disk** (`_preserve_restart_fields` keeps restart-only fields at their *previous* values, so the running app never reconciles new TLS/config until a manual restart). | `warden/config.py` `save_text` | OPEN |
| T10 | L | **`X-RateLimit-Remaining` is not a real remaining count** (hard-coded `"0"`/ `limit-1`). | `warden/auth/routes.py` `_limited` | OPEN |
| T11 | L | **Dead code to remove** — `_rewrite_location` computes an unused `scheme`; `metrics_api` wraps a plain concat in a `try/except` that can't fire. | `warden/proxy.py`, `warden/admin/routes.py` | OPEN |

## Recommended fix order (per user instruction)
1. Missing items: T2, T3, T4, T5 — **completed in this batch** (357 tests pass, coverage 78.55%).
2. Next highest-priority items: T6, T7, T9, T8, T10, T11.
3. T0 (security) is still open and deliberately held; T1 (self-registration) is blocked on design.
