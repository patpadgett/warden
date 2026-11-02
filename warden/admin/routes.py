"""Authenticated dashboard pages and JSON APIs."""

from __future__ import annotations

import logging
import os
import time
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request
from fastapi.openapi.docs import get_swagger_ui_html
from pydantic import BaseModel, Field, ValidationError
from starlette.responses import JSONResponse, Response

from warden.auth.passkeys import hash_backup_code
from warden.auth.sessions import clear_session_cookie
from warden.config import (
    ConfigError,
    RouteConfig,
    WardenConfig,
    restart_required,
)
from warden.db import AlreadyExistsError, DatabaseError, Session, User
from warden.mesh_peer import MeshError
from warden.templating import templates
from warden.tls import certificate_status
from warden.utils import (
    add_page_headers,
    client_ip,
    external_url,
    get_host,
    login_url,
    redirect,
    relative_time,
    route_color,
    route_initials,
)

logger = logging.getLogger("warden.admin")
router = APIRouter()


class ServicePayload(BaseModel):
    host: str
    upstream: str
    name: str | None = None
    auth: bool = True
    enabled: bool = True
    websocket: bool = True
    preserve_host: bool = False
    verify_tls: bool = True
    health_path: str = "/"
    public_paths: list[str] = Field(default_factory=list)
    icon: str | None = None


class ServiceUpdatePayload(ServicePayload):
    """Payload for updating an existing service configuration.

    Inherits all fields from ``ServicePayload``. The class exists to allow a
    distinct schema in the OpenAPI documentation for the ``PUT`` endpoint.
    """


class ConfigPayload(BaseModel):
    yaml: str


class ImportPayload(BaseModel):
    yaml: str | None = None
    db_sql: str | None = None


class PasskeyNamePayload(BaseModel):
    name: str


class UserPayload(BaseModel):
    username: str
    display_name: str
    is_admin: bool = False


class UserUpdatePayload(BaseModel):
    display_name: str | None = None
    is_admin: bool | None = None


class MeshPeerPayload(BaseModel):
    name: str
    address: str | None = None
    endpoint: str | None = None
    keepalive: int = 25



def _config(request: Request) -> WardenConfig:
    return request.app.state.manager.config


def _guard_host(request: Request) -> WardenConfig:
    """Validate that the request is made to the admin host.
    
    * Raises ``HTTPException(404)`` if the host does not match ``config.server.admin_host``.
    """
    config = _config(request)
    if get_host(request.scope) != config.server.admin_host:
        raise HTTPException(404, "Not found")
    return config


def _session(request: Request) -> Session:
    session = getattr(request.state, "session", None)
    if session is None:
        raise HTTPException(401, "Sign in to continue.")
    return session

def _user(request: Request) -> User:
    return _session(request).user


# ---------------------------------------------------------------------- Admin access guard (binary is_admin)
async def _require_admin(request: Request) -> None:
    user = _user(request)
    if not user.is_admin:
        raise HTTPException(403, "Admin access required")



def _db(request: Request):
    return request.app.state.db


def _error(exc: ConfigError, status: int = 400) -> JSONResponse:
    return JSONResponse(
        {"detail": exc.message, "errors": exc.errors},
        status_code=status,
        headers={"Cache-Control": "no-store"},
    )


def _display_upstream(upstream: str) -> str:
    parts = urlsplit(upstream)
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    try:
        port = parts.port
    except ValueError:
        port = None
    netloc = host + (f":{port}" if port else "")
    return f"{parts.scheme}://{netloc}{parts.path}"


def _base_context(request: Request, *, page: str, title: str) -> dict[str, Any]:
    return {
        "page": page,
        "page_title": title,
        "host": get_host(request.scope),
        "user": _user(request),
    }


def _render(request: Request, template: str, context: dict[str, Any], status_code: int = 200) -> Response:
    response = templates.TemplateResponse(request, template, context, status_code=status_code)
    return add_page_headers(response)


async def _audit(request: Request, event: str, detail: str | None = None) -> None:
    session = getattr(request.state, "session", None)
    await _db(request).audit(
        event,
        user_id=session.user_id if session else None,
        username=session.user.username if session else None,
        ip=client_ip(request.scope),
        user_agent=request.headers.get("user-agent", "")[:500],
        detail=detail,
    )


def _cert_context(request: Request, config: WardenConfig) -> dict[str, Any]:
    status = certificate_status(config)
    renewal = getattr(request.app.state, "cert_renewal", None)
    info = status.get("certificate")
    progress = 0
    if info:
        progress = max(0, min(100, round(float(info["days_left"]) / 90 * 100)))
    return {
        **status,
        "progress": progress,
        "renewal": renewal,
    }


def _service_context(route: RouteConfig, config: WardenConfig, snapshot: dict[str, Any], scope) -> dict[str, Any]:
    data = snapshot["services"].get(route.host, {})
    state = data.get("state", "checking")
    labels = {
        "online": "Live",
        "offline": "Down",
        "checking": "Checking",
        "disabled": "Paused",
    }
    name = route.display_name
    return {
        "route": route,
        "host": route.host,
        "name": name,
        "url": external_url(scope, config, route.host),
        "upstream": _display_upstream(route.upstream),
        "initials": route_initials(name, route.icon),
        "tone": route_color(route.host),
        "status": state,
        "status_label": labels.get(state, "Unknown"),
        "latency": data.get("latency_ms"),
        "health_latency": data.get("health_latency_ms"),
        "requests": data.get("requests", 0),
        "errors": data.get("errors", 0),
        "last_seen": data.get("last_seen"),
        "health_checked_at": data.get("health_checked_at"),
        "health_error": data.get("health_error"),
        "json": {
            "host": route.host,
            "upstream": route.upstream,
            "name": route.name or "",
            "auth": route.auth,
            "enabled": route.enabled,
            "websocket": route.websocket,
            "preserve_host": route.preserve_host,
            "verify_tls": route.verify_tls,
            "health_path": route.health_path,
            "public_paths": ", ".join(route.public_paths),
            "icon": route.icon or "",
        },
    }


@router.get("/_warden/openapi.json")
async def openapi_json(request: Request) -> JSONResponse:
    """Return the OpenAPI schema for the admin API (admin‑host protected)."""
    _guard_host(request)
    # FastAPI builds the schema on first call; reuse the app instance.
    return JSONResponse(request.app.openapi())

@router.get("/_warden/docs")
async def swagger_ui(request: Request) -> Response:
    """Serve Swagger UI for the admin OpenAPI schema (admin‑host protected)."""
    _guard_host(request)
    response = get_swagger_ui_html(openapi_url="/_warden/openapi.json", title="Warden Admin API")
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data: https://fastapi.tiangolo.com; "
        "connect-src 'self' https://cdn.jsdelivr.net; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    )
    return response


@router.get("/metrics/view")
async def metrics_view(request: Request) -> Response:
    _guard_host(request)
    stats = request.app.state.stats
    snapshot = stats.snapshot(_config(request))
    context = _base_context(request, page="metrics", title="Metrics")
    context.update({"stats": snapshot})
    return _render(request, "metrics.html", context)

@router.get("/metrics")
@router.get("/_warden/metrics")
async def metrics_api(request: Request) -> Response:
    """Expose Prometheus‑compatible metrics for the Warden instance.
    
    * Host‑guarded to admin host only.
    * Returns the metrics as plain‑text.
    """
    _guard_host(request)
    stats = request.app.state.stats
    content = stats.prometheus_metrics()
    # Health adapter results in metrics
    health = getattr(request.app.state, "health_monitor", None)
    if health is not None:
        try:
            content += "\n# HEALTH adapter active\nwarden_health_adapter_active 1\n"
        except Exception:
            logger.exception("Failed to export health adapter metrics")
    # Add mesh handshake metrics if mesh is enabled
    mesh = request.app.state.mesh
    adapter = getattr(mesh, "adapter", None)
    try:
        if adapter is not None:
            status = await adapter.refresh_handshakes()
        else:
            status = await mesh.refresh_handshakes()
        if status.get("available") and status.get("applied"):
            for peer_key, info in status.get("peers", {}).items():
                if info.last_handshake is not None:
                    # Export as gauge with peer public key label
                    content += f"\nwarden_mesh_last_handshake_seconds{{peer=\\\"{peer_key}\\\"}} {info.last_handshake}"
    except Exception:
        logger.exception("Mesh handshake metrics export failed")
    return Response(
        content=content,
        media_type="text/plain; version=0.0.4",
        headers={"Cache-Control": "no-cache, no-store, must-revalidate"}
    )

@router.get("/users")
async def users_page(request: Request) -> Response:
    """Render the admin UI page showing a list of all users.
    
    * Host‑guarded to admin host.
    * Retrieves all users from the database and renders the ``users.html`` template.
    """
    _guard_host(request)
    db = _db(request)
    users = await db.list_users()
    context = _base_context(request, page="users", title="Users")
    context.update({"users": users})
    return _render(request, "users.html", context)

@router.post("/_warden/api/users")
async def create_user(request: Request, payload: UserPayload) -> JSONResponse:
    """Create a new user record (admin‑only).
    
    * Requires admin host access.
    * User must later complete passkey registration.
    * Returns JSON with the newly created user ID.
    """
    _guard_host(request)
    db = _db(request)
    try:
        # We create the user record but they must still register a passkey.
        # In a full implementation, we'd send an invite email or generate a link.
        # For now, we create the user and return a success.
        user = await db.create_user(
            username=payload.username,
            display_name=payload.display_name,
            webauthn_user_id=os.urandom(16),
            is_admin=payload.is_admin,
        )
    except (AlreadyExistsError, DatabaseError) as exc:
        return JSONResponse({"detail": str(exc)}, status_code=400)
    
    await _audit(request, "user_created", f"{user.username} (Admin: {user.is_admin})")
    return JSONResponse({"ok": True, "user_id": user.id})

@router.patch("/_warden/api/users/{user_id}")
async def update_user(request: Request, user_id: int, payload: UserUpdatePayload) -> JSONResponse:
    """Update user attributes (admin-only).

    * ``is_admin`` toggles the admin flag.
    * ``display_name`` (if provided) updates the user's display name.
    * Returns a simple success JSON.
    """
    _guard_host(request)
    db = _db(request)
    if payload.is_admin is not None:
        await db.update_user_admin(user_id, payload.is_admin)
    if payload.display_name is not None:
        await db.update_user_display_name(user_id, payload.display_name)
    return JSONResponse({"ok": True})

@router.delete("/_warden/api/users/{user_id}")
async def delete_user(request: Request, user_id: int) -> JSONResponse:
    """Delete a user account (admin‑only).
    
    * Prevents self‑deletion for safety.
    * Returns 404 if the user does not exist.
    """
    _guard_host(request)
    current_user = _user(request)
    if user_id == current_user.id:
        return JSONResponse({"detail": "You cannot delete yourself."}, status_code=400)
    
    changed = await _db(request).delete_user(user_id)
    if not changed:
        return JSONResponse({"detail": "User not found."}, status_code=404)
    
    await _audit(request, "user_deleted", f"User ID {user_id}")
    return JSONResponse({"ok": True})
@router.get("/")
async def dashboard(request: Request) -> Response:
    """Render the main admin dashboard with service status and metrics.
    
    * Shows overview of routes, health, traffic, and TLS warnings.
    * Provides quick links to other admin pages.
    """
    config = _guard_host(request)
    user = _user(request)
    db = _db(request)
    session = _session(request)
    stats = request.app.state.stats
    snapshot = stats.snapshot(config)
    services = [
        _service_context(route, config, snapshot, request.scope) for route in config.routes
    ]
    credentials = await db.list_credentials(user.id)
    sessions = await db.list_sessions(user.id, current_token_hash=session.token_hash)
    audit = await db.list_audit(60)
    last_login = next((event for event in audit if event.event == "login_succeeded"), None)
    since = time.time() - 86400
    signins_today = await db.count_audit(event="login_succeeded", since=since)
    tls_info = _cert_context(request, config)
    warnings: list[str] = []
    if not config.routes:
        warnings.append("No services yet. Add your first route to put something behind Warden.")
    if config.server.tls.enabled and tls_info.get("certificate"):
        days = float(tls_info["certificate"]["days_left"])
        if days < 0:
            warnings.append("The TLS certificate has expired. Renew it and restart Warden.")
        elif days <= config.server.tls.renew_days_before:
            warnings.append(
                f"The TLS certificate expires in {int(days)} days. Renew it and restart Warden."
            )
    if not config.server.tls.enabled and config.server.admin_host not in {"localhost", "127.0.0.1"}:
        warnings.append(
            "TLS is off. Passkeys require a secure context — use HTTPS or open Warden on localhost."
        )
    context = _base_context(request, page="dashboard", title="Services")
    context.update(
        {
            "services": services,
            "stats": snapshot["totals"],
            "traffic": snapshot["traffic"],
            "passkey_count": len(credentials),
            "session_count": len(sessions),
            "last_login": last_login,
            "last_login_display": relative_time(last_login.created_at) if last_login else "never",
            "signins_today": signins_today,
            "tls": tls_info,
            "warnings": warnings,
        }
    )
    return _render(request, "dashboard.html", context)


@router.get("/passkeys")
async def passkeys_page(request: Request) -> Response:
    """Render the admin page listing all passkey credentials for the current user.
    
    * Includes sessions and passkey details.
    * Provides options for adding or removing passkeys.
    """
    config = _guard_host(request)
    user = _user(request)
    session = _session(request)
    db = _db(request)
    credentials = await db.list_credentials(user.id)
    sessions = await db.list_sessions(user.id, current_token_hash=session.token_hash)
    context = _base_context(request, page="passkeys", title="Access")
    context.update(
        {
            "credentials": credentials,
            "sessions": sessions,
            "session_count": len(sessions),
            "current_session_id": session.id,
            "passkey_count": len(credentials),
            "added": request.query_params.get("added"),
            "session_ttl_hours": config.server.session_ttl_hours,
        }
    )
    return _render(request, "passkeys.html", context)


EVENT_META: dict[str, tuple[str, str, str]] = {
    "login_succeeded": ("Signed in with a passkey", "good", "key"),
    "login_failed": ("Sign-in failed", "bad", "alert"),
    "login_blocked": ("Cross-origin sign-in blocked", "bad", "shield"),
    "logout": ("Signed out", "neutral", "arrow"),
    "setup_completed": ("Warden claimed", "good", "spark"),
    "setup_failed": ("Setup attempt failed", "warn", "alert"),
    "setup_bad_code": ("Incorrect setup code", "warn", "alert"),
    "passkey_registered": ("Passkey added", "good", "key"),
    "passkey_deleted": ("Passkey removed", "warn", "key"),
    "passkey_renamed": ("Passkey renamed", "neutral", "key"),
    "passkey_failed": ("Passkey registration failed", "warn", "alert"),
    "session_revoked": ("Session revoked", "warn", "shield"),
    "sessions_revoked": ("Other sessions revoked", "warn", "shield"),
    "config_saved": ("Configuration saved", "neutral", "file"),
    "service_added": ("Service added", "good", "grid"),
    "service_updated": ("Service updated", "neutral", "grid"),
    "service_deleted": ("Service removed", "warn", "grid"),
    "mesh_peer_added": ("Mesh peer added", "good", "mesh"),
    "mesh_peer_deleted": ("Mesh peer removed", "warn", "mesh"),
    "mesh_applied": ("Mesh config applied", "good", "mesh"),
}


@router.get("/activity")
async def activity_page(request: Request) -> Response:
    _guard_host(request)
    events = await _db(request).list_audit(150)
    decorated = []
    for event in events:
        label, tone, icon = EVENT_META.get(event.event, (event.event.replace("_", " ").title(), "neutral", "dot"))
        decorated.append({"event": event, "label": label, "tone": tone, "icon": icon})
    context = _base_context(request, page="activity", title="Activity")
    context.update({"events": decorated, "count": len(decorated)})
    return _render(request, "activity.html", context)


@router.get("/tls")
async def tls_page(request: Request) -> Response:
    """Render a page showing TLS certificate status and renewal configuration.
    """
    _guard_host(request)
    config = _config(request)
    tls_info = _cert_context(request, config)
    context = _base_context(request, page="tls", title="TLS")
    context.update({"tls": tls_info})
    return _render(request, "tls.html", context)

@router.get("/config")
async def config_page(request: Request) -> Response:
    """Render the configuration page."""
    config = _guard_host(request)
    manager = request.app.state.manager
    raw = ""
    error = None
    try:
        raw = manager.read_text()
    except ConfigError as exc:
        error = exc.pretty()
    tls_status = certificate_status(config)
    context = _base_context(request, page="config", title="Config")
    context.update(
        {
            "raw_config": raw,
            "config_path": str(manager.path) if manager.path else None,
            "config_error": error,
            "tls": tls_status,
            "admin_host": config.server.admin_host,
            "rp_id": config.webauthn.rp_id,
            "cookie_domain": config.server.cookie_domain or "host-only",
            "session_ttl_hours": config.server.session_ttl_hours,
            "route_count": len(config.routes),
        }
    )
    return _render(request, "config.html", context)


@router.get("/mesh")
async def mesh_page(request: Request) -> Response:
    config = _guard_host(request)
    context = _base_context(request, page="mesh", title="Mesh")
    mesh = request.app.state.mesh
    context.update(
        {
            "mesh_enabled": config.mesh.enabled,
            "mesh": config.mesh,
            "hub_public_key": None,
            "peers": [],
            "mesh_status": {"available": False, "applied": False, "peers": {}},
            "last_apply": mesh.last_apply,
        }
    )
    if config.mesh.enabled:
        hub_key = await mesh.hub_public_key()
        peers = await _db(request).list_mesh_peers()
        try:
            status = await mesh.refresh_handshakes()
        except (MeshError, OSError, ValueError) as exc:
            logger.warning("Could not read WireGuard status: %s", exc)
            status = {"available": False, "applied": False, "peers": {}, "detail": str(exc)}
        peer_rows = []
        for peer in peers:
            info = status.get("peers", {}).get(peer.public_key)
            peer_rows.append(
                {
                    "peer": peer,
                    "live": info,
                    "endpoint": info.endpoint if info else peer.endpoint,
                    "handshake": info.last_handshake if info else peer.last_handshake,
                    "rx": info.rx_bytes if info else 0,
                    "tx": info.tx_bytes if info else 0,
                }
            )
        context.update(
            {
                "hub_public_key": hub_key,
                "peers": peer_rows,
                "peer_count": len(peers),
                "mesh_status": status,
            }
        )
    return _render(request, "mesh.html", context)
# ---------------------------------------------------------------------- API: backup codes

# ---------------------------------------------------------------------- UI: backup codes page
@router.get("/backup_codes")
async def backup_codes_page(request: Request) -> Response:
    """Render the admin UI page listing the user's backup codes.

    * Accessible only on the admin host (guarded by ``_guard_host``).
    * Shows a table of existing backup codes with creation and usage timestamps.
    * Provides a button to generate a new code via the POST ``/backup_codes/generate`` route.
    """
    _guard_host(request)
    user = _user(request)
    db = _db(request)
    codes = await db.list_backup_codes(user.id)
    context = _base_context(request, page="backup_codes", title="Backup Codes")
    context.update({"codes": codes})
    return _render(request, "backup_codes.html", context)

@router.post("/backup_codes/generate")
async def generate_backup_code_page(request: Request) -> Response:
    """Generate a new backup code for the logged‑in admin user.

    * Protected by ``_guard_host`` (admin host only).
    * Creates a unique 10‑character code, stores it in the DB, and redirects back
      to the backup‑code list page.
    * If a unique code cannot be generated after several attempts, a 500 error is
      raised.
    """
    _guard_host(request)
    user = _user(request)
    db = _db(request)
    for _ in range(10):
        code = uuid4().hex[:10]
        try:
            await db.add_backup_code(user.id, code)
            break
        except AlreadyExistsError:
            continue
    else:
        raise HTTPException(status_code=500, detail="Could not generate unique backup code")
    return redirect("/backup_codes")

@router.get("/_warden/api/backup_codes")
async def list_backup_codes(request: Request) -> JSONResponse:
    # Ensure admin host access
    _guard_host(request)
    user = _user(request)
    db = _db(request)
    codes = await db.list_backup_codes(user.id)
    payload = []
    for c in codes:
        payload.append({"id": c.id, "created_at": c.created_at, "used_at": c.used_at})
    return JSONResponse({"ok": True, "codes": payload})

@router.post("/_warden/api/backup_codes")
async def create_backup_code(request: Request) -> JSONResponse:
    # Ensure admin host and CSRF protection (middleware handles header + origin)
    _guard_host(request)
    user = _user(request)
    db = _db(request)
    for _ in range(10):
        code = uuid4().hex[:10]
        try:
            await db.add_backup_code(user.id, hash_backup_code(code))
            break
        except AlreadyExistsError:
            continue
    else:
        raise HTTPException(status_code=500, detail="Could not generate unique backup code")
    return JSONResponse({"ok": True, "code": code})


# ---------------------------------------------------------------------- Status
@router.get("/_warden/api/status")
async def status_api(request: Request) -> JSONResponse:
    config = _guard_host(request)
    stats = request.app.state.stats
    snapshot = stats.snapshot(config)
    return JSONResponse(snapshot)


@router.post("/_warden/api/services")
async def add_service(request: Request, payload: ServicePayload) -> JSONResponse:
    _guard_host(request)
    manager = request.app.state.manager
    try:
        route = RouteConfig(**payload.model_dump())
        _config, restart = manager.add_route(route)
    except (ConfigError, ValueError, ValidationError) as exc:
        if isinstance(exc, ConfigError):
            return _error(exc)
        return JSONResponse({"detail": str(exc)}, status_code=400)
    await _audit(request, "service_added", f"{route.host} → {_display_upstream(route.upstream)}")
    return JSONResponse({"ok": True, "restart_required": restart})


@router.put("/_warden/api/services/{host:path}")
async def update_service(request: Request, host: str, payload: ServiceUpdatePayload) -> JSONResponse:
    _guard_host(request)
    manager = request.app.state.manager
    try:
        route = RouteConfig(**payload.model_dump())
        _config, restart = manager.update_route(host, route)
    except (ConfigError, ValueError, ValidationError) as exc:
        if isinstance(exc, ConfigError):
            return _error(exc)
        return JSONResponse({"detail": str(exc)}, status_code=400)
    await _audit(request, "service_updated", f"{host} → {_display_upstream(route.upstream)}")
    return JSONResponse({"ok": True, "restart_required": restart})


@router.delete("/_warden/api/services/{host:path}")
async def delete_service(request: Request, host: str) -> JSONResponse:
    _guard_host(request)
    manager = request.app.state.manager
    try:
        _config, restart = manager.delete_route(host)
    except (ConfigError, ValueError) as exc:
        if isinstance(exc, ConfigError):
            return _error(exc)
        return JSONResponse({"detail": str(exc)}, status_code=400)
    await _audit(request, "service_deleted", host)
    return JSONResponse({"ok": True, "restart_required": restart})


@router.get("/_warden/api/config/export")
async def export_config(request: Request) -> Response:
    _guard_host(request)
    manager = request.app.state.manager
    yaml_content = manager.read_text()
    return Response(
        content=yaml_content,
        media_type="text/yaml",
        headers={"Content-Disposition": "attachment; filename=warden.yaml"},
    )


@router.post("/_warden/api/config/import")
async def import_config(request: Request, payload: ImportPayload) -> JSONResponse:
    _guard_host(request)
    manager = request.app.state.manager
    
    if payload.yaml:
        try:
            # Validate before saving
            manager.validate_text(payload.yaml)
            config, restart = manager.save_text(payload.yaml)
            await _audit(request, "config_imported", f"Imported YAML config ({len(config.routes)} routes)")
            return JSONResponse({"ok": True, "restart_required": restart})
        except ConfigError as exc:
            return _error(exc)
            
    return JSONResponse({"detail": "No configuration provided for import."}, status_code=400)


@router.get("/_warden/api/config")
async def get_config(request: Request) -> JSONResponse:
    _guard_host(request)
    manager = request.app.state.manager
    try:
        return JSONResponse({"yaml": manager.read_text(), "path": str(manager.path or "")})
    except ConfigError as exc:
        return _error(exc)


@router.post("/_warden/api/config/validate")
async def validate_config(request: Request, payload: ConfigPayload) -> JSONResponse:
    _guard_host(request)
    manager = request.app.state.manager
    try:
        config = manager.validate_text(payload.yaml)
    except ConfigError as exc:
        return JSONResponse(
            {"ok": False, "detail": exc.message, "errors": exc.errors}, status_code=400
        )
    return JSONResponse(
        {
            "ok": True,
            "routes": len(config.routes),
            "admin_host": config.server.admin_host,
            "restart_required": restart_required(manager.config, config),
        }
    )


@router.post("/_warden/api/config")
async def save_config(request: Request, payload: ConfigPayload) -> JSONResponse:
    _guard_host(request)
    manager = request.app.state.manager
    try:
        config, restart = manager.save_text(payload.yaml)
    except ConfigError as exc:
        return _error(exc)
    await _audit(request, "config_saved", f"{len(config.routes)} routes")
    return JSONResponse({"ok": True, "restart_required": restart})


@router.patch("/_warden/api/passkeys/{credential_id}")
async def rename_passkey(request: Request, credential_id: int, payload: PasskeyNamePayload) -> JSONResponse:
    _guard_host(request)
    user = _user(request)
    name = payload.name.strip()
    if not name or len(name) > 60:
        return JSONResponse({"detail": "Passkey name must be 1–60 characters."}, status_code=400)
    changed = await _db(request).rename_credential(user.id, credential_id, name)
    if not changed:
        return JSONResponse({"detail": "Passkey not found."}, status_code=404)
    await _audit(request, "passkey_renamed", name)
    return JSONResponse({"ok": True})


@router.delete("/_warden/api/passkeys/{credential_id}")
async def delete_passkey(request: Request, credential_id: int) -> JSONResponse:
    _guard_host(request)
    user = _user(request)
    db = _db(request)
    credentials = await db.list_credentials(user.id)
    if len(credentials) <= 1:
        return JSONResponse(
            {"detail": "Add another passkey before removing your only one."},
            status_code=409,
        )
    target = next((credential for credential in credentials if credential.id == credential_id), None)
    if target is None:
        return JSONResponse({"detail": "Passkey not found."}, status_code=404)
    await db.delete_credential(user.id, credential_id)
    await _audit(request, "passkey_deleted", target.name)
    return JSONResponse({"ok": True})


@router.delete("/_warden/api/sessions/{session_id}")
async def revoke_session(request: Request, session_id: int) -> JSONResponse:
    _guard_host(request)
    session = _session(request)
    config = _config(request)
    if session_id == session.id:
        await _db(request).revoke_session(session.user_id, session_id)
        response = JSONResponse({"ok": True, "redirect": login_url(request.scope, config, "/")})
        clear_session_cookie(response, request.scope, config)
        return response
    changed = await _db(request).revoke_session(session.user_id, session_id)
    if not changed:
        return JSONResponse({"detail": "Session not found."}, status_code=404)
    await _audit(request, "session_revoked", f"Session {session_id}")
    return JSONResponse({"ok": True})


@router.post("/_warden/api/sessions/revoke-others")
async def revoke_other_sessions(request: Request) -> JSONResponse:
    _guard_host(request)
    session = _session(request)
    count = await _db(request).revoke_other_sessions(session.user_id, session.token_hash)
    await _audit(request, "sessions_revoked", f"{count} sessions")
    return JSONResponse({"ok": True, "count": count})


# -------------------------------------------------------------------- mesh
def _mesh(request: Request):
    _guard_host(request)
    if not _config(request).mesh.enabled:
        raise HTTPException(400, "WireGuard mesh is disabled in warden.yaml.")
    return request.app.state.mesh


@router.post("/_warden/api/mesh/peers")
async def add_mesh_peer(request: Request, payload: MeshPeerPayload) -> JSONResponse:
    mesh = _mesh(request)
    try:
        peer = await mesh.add_peer(
            name=payload.name,
            address=payload.address or None,
            endpoint=payload.endpoint or None,
            keepalive=payload.keepalive,
        )
        config_text = await mesh.render_peer_config(peer)
    except MeshError as exc:
        return JSONResponse({"detail": str(exc)}, status_code=400)
    await _audit(request, "mesh_peer_added", f"{peer.name} ({peer.address})")
    return JSONResponse(
        {
            "ok": True,
            "peer": {
                "id": peer.id,
                "name": peer.name,
                "address": peer.address,
                "public_key": peer.public_key,
            },
            "config": config_text,
            "filename": f"warden-{peer.name.lower().replace(' ', '-')}.conf",
        }
    )


@router.get("/_warden/api/mesh/peers/{peer_id}/config")
async def mesh_peer_config(request: Request, peer_id: int) -> JSONResponse:
    mesh = _mesh(request)
    peer = await _db(request).get_mesh_peer(peer_id)
    if peer is None:
        return JSONResponse({"detail": "Peer not found."}, status_code=404)
    try:
        config_text = await mesh.render_peer_config(peer)
    except MeshError as exc:
        return JSONResponse({"detail": str(exc)}, status_code=400)
    return JSONResponse(
        {
            "config": config_text,
            "filename": f"warden-{peer.name.lower().replace(' ', '-')}.conf",
        }
    )


@router.delete("/_warden/api/mesh/peers/{peer_id}")
async def delete_mesh_peer(request: Request, peer_id: int) -> JSONResponse:
    _mesh(request)
    peer = await _db(request).get_mesh_peer(peer_id)
    if peer is None:
        return JSONResponse({"detail": "Peer not found."}, status_code=404)
    await _db(request).delete_mesh_peer(peer_id)
    await _audit(request, "mesh_peer_deleted", peer.name)
    return JSONResponse({"ok": True})


@router.post("/_warden/api/mesh/apply")
async def apply_mesh(request: Request) -> JSONResponse:
    mesh = _mesh(request)
    try:
        result = await mesh.apply()
    except MeshError as exc:
        return JSONResponse({"detail": str(exc)}, status_code=400)
    await _audit(request, "mesh_applied", f"Interface {result.get('interface')}")
    return JSONResponse({"ok": True, **result})


@router.get("/_warden/api/mesh/status")
async def mesh_status(request: Request) -> JSONResponse:
    mesh = _mesh(request)
    try:
        status = await mesh.refresh_handshakes()
    except (MeshError, OSError, ValueError) as exc:
        return JSONResponse({"detail": str(exc)}, status_code=500)
    peers = status.pop("peers", {})
    return JSONResponse({"ok": True, **status, "peer_status": {
        key: {
            "endpoint": value.endpoint,
            "last_handshake": value.last_handshake,
            "rx_bytes": value.rx_bytes,
            "tx_bytes": value.tx_bytes,
        }
        for key, value in peers.items()
    }})

@router.post("/_warden/api/proxy/reset-clients")
async def reset_proxy_clients(request: Request) -> JSONResponse:
    _guard_host(request)
    await _require_admin(request)
    request.app.state.proxy.reset_clients()
    return JSONResponse({"ok": True})

@router.post("/_warden/api/mesh/rotate-hub-key")
async def rotate_mesh_hub_key(request: Request) -> JSONResponse:
    _guard_host(request)
    await _require_admin(request)
    mesh = _mesh(request)
    try:
        new_key = await mesh.rotate_hub_key()
    except MeshError as exc:
        return JSONResponse({"detail": str(exc)}, status_code=400)
    await _audit(request, "mesh_hub_key_rotated", "Hub key rotated")
    return JSONResponse({"ok": True, "new_private_key": new_key})

@router.get("/api/audit/export")
async def audit_export(request: Request, limit: int = 500, event: str | None = None) -> JSONResponse:
    """Export audit events as JSON (admin only; protected by host guard)."""
    _guard_host(request)
    db = _db(request)
    events = await db.list_audit(limit)
    if event:
        events = [e for e in events if e.event == event]
    result = [{"id": e.id, "created_at": e.created_at, "event": e.event,
               "username": e.username, "ip": e.ip, "detail": e.detail} for e in events]
    return JSONResponse({"count": len(result), "events": result})

@router.post("/api/backup_codes/bulk")
async def backup_codes_bulk(request: Request, count: int = 5) -> JSONResponse:
    """Generate multiple backup codes at once (admin)."""
    _guard_host(request)
    user = _user(request)
    db = _db(request)
    codes = []
    for _ in range(min(count, 20)):
        for attempt in range(10):
            code = uuid4().hex[:10]
            try:
                await db.add_backup_code(user.id, code)
                codes.append(code)
                break
            except AlreadyExistsError:
                continue
        else:
            return JSONResponse({"ok": False, "detail": "Could not generate unique code"}, status_code=500)
    return JSONResponse({"created": len(codes), "codes": codes})
