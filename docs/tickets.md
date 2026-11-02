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
| T6 | H | **VACUUM silently skipped** (`PRAGMA database_path` is not a valid pragma; the path lookup returned empty, so the reclaim step never ran. | `warden/db.py` `vacuum()` | FIXED |
| T7 | L | **Dead `request.stream() if has_body else b""` no-op discarded its result and advanced the ASGI receive iterator.** | `warden/proxy.py` `handle_http` | FIXED |
| T8 | L | **Dashboard "Last sign-in" read the most recent of the last 60 audit rows — sign-ins older than 60 events showed "never" despite `signins_today > 0`.** | `warden/admin/routes.py` `dashboard` | FIXED |
| T9 | M | Config-save divergence: `save_text` preserves restart-only fields at their previous runtime values in `manager.config` while the file holds the new values. | `warden/config.py` `save_text` | CLARIFIED — confirmed by design (restart-required UX); no change requested |
| T10 | L | `X-RateLimit-Remaining` was a hard-coded approximation (`0` or `limit-1`). | `warden/auth/routes.py` `_limited`, `warden/utils.py` | FIXED — `allow` now reports the real remaining count for both in-process and Redis limiters |
| T11 | L | **Dead code: discarded `request.stream()` no-op in `handle_http`; a `try/except` in `metrics_api` that can never fire; an unused `scheme` variable in `_rewrite_location`.** | `warden/proxy.py`, `warden/admin/routes.py` | FIXED |

## Recommended fix order (per user instruction)
1. Missing items: T2, T3, T4, T5 — **completed in this batch** (357 tests pass, coverage 78.55%).
2. Next highest-priority items: T6, T7, T8, T10, T11 — **completed in this batch** (357 tests pass, coverage 78.42%).
3. T0 (security) is still open and deliberately held; T1 (self-registration) is blocked on design.
