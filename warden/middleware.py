"""ASGI middleware: host routing, session gates, admin protection, and proxying.

This module implements the :class:`WardenMiddleware` class, which is the top‑level ASGI
middleware for Warden. It determines whether a request is for the internal admin UI,
an ACME challenge, a public auth endpoint, or a proxied upstream service. It also
enforces session authentication, CSRF protection for state‑changing admin APIs, and
adds a strict set of security response headers to every outgoing response.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable, MutableMapping
from typing import Any

from starlette.datastructures import Headers, MutableHeaders
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.websockets import WebSocket

from warden.auth.sessions import authenticate_scope
from warden.config import ConfigManager, WardenConfig
from warden.db import Database
from warden.proxy import ProxyEngine
from warden.stats import MetricsModule
from warden.templating import templates
from warden.utils import (
    INTERNAL_PREFIX,
    add_page_headers,
    apply_security_headers,
    check_origin,
    get_host,
    is_navigation,
    login_url,
    next_from_scope,
    request_wants_json,
)

logger = logging.getLogger("warden.middleware")

_PUBLIC_AUTH_PREFIXES = (
    f"{INTERNAL_PREFIX}/login",
    f"{INTERNAL_PREFIX}/setup",
    f"{INTERNAL_PREFIX}/auth/",
    f"{INTERNAL_PREFIX}/health",
    f"{INTERNAL_PREFIX}/static/",
    f"{INTERNAL_PREFIX}/invite/complete",
)
#: Admin-host pages a signed-in non-admin may open. These pages only show or
#: change the requesting user's own data.
_USER_PAGE_PATHS = ("/portal", "/passkeys", "/backup_codes")
#: Admin-host APIs that are scoped to the session user, so non-admins may use
#: them from those pages (passkey rename/remove, session revoke).
_USER_API_PREFIXES = (
    f"{INTERNAL_PREFIX}/api/passkeys",
    f"{INTERNAL_PREFIX}/api/sessions",
)
_ACME_PREFIX = "/.well-known/acme-challenge/"


class WardenMiddleware:
    """Top‑level ASGI middleware for Warden.

    Handles routing, admin‑only guards, session extraction, CSRF checks for the
    internal API, and proxies requests to upstream services via :class:`ProxyEngine`.
    """
    def __init__(
        self,
        app: Callable,
        *,
        manager: ConfigManager,
        db: Database,
        proxy: ProxyEngine,
        stats: MetricsModule,
    ) -> None:
        """Create the middleware instance.

        * ``app`` – the underlying FastAPI application.
        * ``manager`` – configuration manager.
        * ``db`` – async SQLite wrapper.
        * ``proxy`` – reverse‑proxy engine.
        * ``stats`` – metrics collector.
        """
        self.app = app
        self.manager = manager
        self.db = db
        self.proxy = proxy
        self.stats = stats

    async def __call__(self, scope: MutableMapping[str, Any], receive: Callable, send: Callable) -> None:
        """__call__."""
        if scope["type"] not in {"http", "websocket"}:
            await self.app(scope, receive, send)
            return
        # FastAPI/Starlette set scope["app"] to the application instance before
        # calling the middleware stack. Keep that reference (it exposes
        # ``state``); only fall back to walking the chain if it is missing.
        if not hasattr(scope.get("app"), "state"):
            _scope_app = self.app
            _depth = 0
            while _depth < 10:
                if hasattr(_scope_app, "state"):
                    break
                if not hasattr(_scope_app, "app"):
                    break
                _scope_app = _scope_app.app
                _depth += 1
            scope["app"] = _scope_app
        config = self.manager.config
        host = get_host(scope)
        path = scope.get("path", "/")
        is_admin = host == config.server.admin_host
        state = scope.setdefault("state", {})
        state.setdefault("request_id", uuid.uuid4().hex)
        if scope["type"] == "websocket":
            await self._handle_websocket(scope, receive, send, config, host, is_admin, path)
            return
        await self._handle_http(scope, receive, send, config, host, is_admin, path)

    # ------------------------------------------------------------------ paths
    def _is_public_auth_path(self, path: str) -> bool:
        """Return ``True`` if *path* is an internal auth/public endpoint.

        These endpoints (login, setup, health, static assets) are served by the
        FastAPI app itself and are not proxied to upstream services.
        """
        return path == INTERNAL_PREFIX or path.startswith(_PUBLIC_AUTH_PREFIXES)

    def _is_static(self, path: str) -> bool:
        """Return ``True`` if *path* points to a static asset under ``/_warden/static/``.
        """
        return path.startswith(f"{INTERNAL_PREFIX}/static/")

    def _is_user_portal_path(self, path: str) -> bool:
        """Return ``True`` if a non-admin may open *path* on the admin host."""
        allowed = _USER_PAGE_PATHS + _USER_API_PREFIXES
        return any(path == prefix or path.startswith(f"{prefix}/") for prefix in allowed)

    # ------------------------------------------------------------------- http
    async def _handle_http(
        self,
        scope: MutableMapping[str, Any],
        receive: Callable,
        send: Callable,
        config: WardenConfig,
        host: str,
        is_admin: bool,
        path: str,
    ) -> None:
        """Process an HTTP request.

        * Handles ACME challenges, public auth paths, and admin‑host logic.
        * Enforces authentication for admin routes and for routes that require it.
        * Delegates to the configured :class:`ProxyEngine` for proxied traffic.
        """
        method = scope.get("method", "GET").upper()
        state = scope.setdefault("state", {})
        session = await authenticate_scope(scope, self.db)
        state["session"] = session
        state["user"] = session.user if session else None

        if path.startswith(_ACME_PREFIX):
            await self._call_app(scope, receive, send, config)
            return

        if self._is_public_auth_path(path):
            await self._call_app(scope, receive, send, config)
            return

        if is_admin:
            setup_required = await self.db.user_count() == 0
            if setup_required and path != f"{INTERNAL_PREFIX}/setup":
                if is_navigation(scope):
                    response = self._redirect(f"{INTERNAL_PREFIX}/setup")
                    await response(scope, receive, send)
                    return
                response = self._json_unauthorized(
                    "Warden has not been set up yet.",
                    extra={"setup_required": True, "setup_url": f"{INTERNAL_PREFIX}/setup"},
                )
                await response(scope, receive, send)
                return
            if session is None:
                if request_wants_json(scope):
                    await self._json_unauthorized("Sign in to continue.")(scope, receive, send)
                    return
                if method in {"GET", "HEAD"}:
                    target = login_url(scope, config, next_from_scope(scope))
                    response = self._redirect(target)
                    await response(scope, receive, send)
                    return
                await self._json_unauthorized("Sign in to continue.")(scope, receive, send)
                return
            if not session.user.is_admin:
                # The portal and the per-user credential pages are the only
                # admin-host destinations open to non-admins. ``/`` lands them
                # on the portal instead of the admin dashboard.
                if path == "/" and method in {"GET", "HEAD"}:
                    response = self._redirect("/portal")
                    await response(scope, receive, send)
                    return
                if self._is_user_portal_path(path):
                    if method not in {"GET", "HEAD", "OPTIONS"}:
                        if path.startswith(f"{INTERNAL_PREFIX}/api/"):
                            header = Headers(scope=scope).get("x-warden-request")
                            if header != "1":
                                response = JSONResponse(
                                    {"detail": "Missing X-Warden-Request header."},
                                    status_code=403,
                                )
                                response.headers["Cache-Control"] = "no-store"
                                await response(scope, receive, send)
                                return
                        if not check_origin(scope, config):
                            response = JSONResponse(
                                {"detail": "Cross-origin request blocked."}, status_code=403
                            )
                            response.headers["Cache-Control"] = "no-store"
                            await response(scope, receive, send)
                            return
                    await self._call_app(scope, receive, send, config)
                    return
                if is_navigation(scope):
                    await self._no_dashboard_access(scope, receive, send, host)
                    return
                response = self._json_unauthorized("Admin access required.")
                await response(scope, receive, send)
                return
            if path.startswith(f"{INTERNAL_PREFIX}/api/") and method not in {"GET", "HEAD", "OPTIONS"}:
                header = Headers(scope=scope).get("x-warden-request")
                if header != "1":
                    response = JSONResponse(
                        {"detail": "Missing X-Warden-Request header."}, status_code=403
                    )
                    response.headers["Cache-Control"] = "no-store"
                    await response(scope, receive, send)
                    return
                if not check_origin(scope, config):
                    response = JSONResponse(
                        {"detail": "Cross-origin request blocked."}, status_code=403
                    )
                    response.headers["Cache-Control"] = "no-store"
                    await response(scope, receive, send)
                    return
            elif method not in {"GET", "HEAD", "OPTIONS"} and not check_origin(scope, config):
                # Admin UI forms post without the API header, so apply the
                # origin check to every other state-changing admin request.
                response = JSONResponse(
                    {"detail": "Cross-origin request blocked."}, status_code=403
                )
                response.headers["Cache-Control"] = "no-store"
                await response(scope, receive, send)
                return
            await self._call_app(scope, receive, send, config)
            return

        if path == INTERNAL_PREFIX or path.startswith(f"{INTERNAL_PREFIX}/"):
            await self._not_found(
                scope,
                receive,
                send,
                host,
                title="Not found",
                message="That Warden URL does not exist.",
            )
            return

        route = config.match_route(host)
        if route is None:
            await self._not_found(scope, receive, send, host)
            return
        if not route.enabled:
            await self._not_found(
                scope,
                receive,
                send,
                host,
                title="This service is paused",
                message=(
                    "This service is paused in Warden. Enable it in the dashboard "
                    "to restore access."
                ),
            )
            return

        if route.auth and not route.is_public_path(path):
            if session is None:
                target = login_url(scope, config, next_from_scope(scope))
                if request_wants_json(scope):
                    await self._json_unauthorized(
                        "Sign in to continue.", extra={"login_url": target}
                    )(scope, receive, send)
                    return
                if method in {"GET", "HEAD"}:
                    response = self._redirect(target)
                    await response(scope, receive, send)
                    return
                await self._json_unauthorized(
                    "Sign in to continue.", extra={"login_url": target}
                )(scope, receive, send)
                return
            user = session.user
        else:
            user = None

        await self.proxy.handle_http(scope, receive, send, route, user)


    async def _call_app(
        self,
        scope: MutableMapping[str, Any],
        receive: Callable,
        send: Callable,
        config: WardenConfig,
    ) -> None:
        """Invoke the underlying FastAPI application, applying security headers to the response.
        """
        async def send_with_security(message: MutableMapping[str, Any]) -> None:
            """send_with_security."""
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers.setdefault("X-Request-ID", scope.get("state", {}).get("request_id", ""))
                headers.setdefault("X-Content-Type-Options", "nosniff")
                headers.setdefault("X-Frame-Options", "DENY")
                headers.setdefault("Referrer-Policy", "no-referrer")
                headers.setdefault(
                    "Permissions-Policy",
                    "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
                )
                headers.setdefault(
                    "Content-Security-Policy",
                    "default-src 'self'; script-src 'self'; "
                    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                    "img-src 'self' data:; connect-src 'self'; "
                    "font-src 'self' https://fonts.gstatic.com; "
                    "frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
                )
                if config.server.external_scheme == "https" or str(scope.get("scheme")) == "https":
                    headers.setdefault(
                        "Strict-Transport-Security", "max-age=15552000"
                    )
                path = scope.get("path", "")
                if path.startswith(INTERNAL_PREFIX) and not path.startswith(
                    f"{INTERNAL_PREFIX}/static/"
                ):
                    headers.setdefault("Cache-Control", "no-store")
                scope.setdefault("state", {})["_status_code"] = message.get("status", 0)
            await send(message)

        await self.app(scope, receive, send_with_security)
        status_code = scope.get("state", {}).get("_status_code", 0)
        if status_code:
            logger.info(
                "%s %s %d %s",
                scope.get("method", "?"),
                scope.get("path", "/"),
                status_code,
                scope.get("state", {}).get("request_id", "-"),
            )

    # -------------------------------------------------------------- responses
    def _redirect(self, target: str) -> Response:
        """Return a 303 *RedirectResponse* to *target* with security headers applied.
        """
        response = Response(status_code=303)
        response.headers["Location"] = target
        response.headers["Cache-Control"] = "no-store"
        apply_security_headers(response)
        return response

    def _json_unauthorized(
        self, message: str, *, extra: dict[str, Any] | None = None
    ) -> JSONResponse:
        """Return a 401 JSON error payload with optional additional fields.
        """
        payload: dict[str, Any] = {"detail": message}
        if extra:
            payload.update(extra)
        response = JSONResponse(payload, status_code=401)
        response.headers["Cache-Control"] = "no-store"
        return response

    async def _no_dashboard_access(
        self,
        scope: MutableMapping[str, Any],
        receive: Callable,
        send: Callable,
        host: str,
    ) -> None:
        """Explain the admin-only dashboard to a signed-in non-admin visitor."""
        template = templates.get_template("error.html")
        body = template.render(
            page_title="No dashboard access",
            code="403",
            title="This dashboard is for admins",
            message=(
                "You're signed in, but the Warden dashboard is admin-only. "
                "Your portal lists the services you can open and lets you "
                "manage your passkeys and backup codes."
            ),
            detail="",
            host=host,
            retry_url="/portal",
            retry_label="Open portal",
            admin_url=None,
            retry_after=None,
            signed_in=True,
        )
        response = HTMLResponse(body, status_code=403)
        add_page_headers(response)
        await response(scope, receive, send)

    async def _not_found(
        self,
        scope: MutableMapping[str, Any],
        receive: Callable,
        send: Callable,
        host: str,
        *,
        title: str = "No service here",
        message: str | None = None,
    ) -> None:
        """Render a 404 response for unknown routes.

        Returns JSON if the request prefers JSON, otherwise renders the ``error.html``
        template with the given *title* and *message*.
        """
        if request_wants_json(scope):
            response: Response = JSONResponse({"detail": title}, status_code=404)
            response.headers["Cache-Control"] = "no-store"
            await response(scope, receive, send)
            return
        template = templates.get_template("error.html")
        body = template.render(
            page_title=title,
            code="404",
            title=title,
            message=message
            or f"{host or 'This address'} isn't connected to a service in Warden yet. Check the address, or add a route in the dashboard.",
            detail="",
            host=host,
            retry_url=scope.get("path", "/"),
        )
        response = HTMLResponse(body, status_code=404)
        add_page_headers(response)
        await response(scope, receive, send)

    # --------------------------------------------------------------- websocket
    async def _handle_websocket(
        self,
        scope: MutableMapping[str, Any],
        receive: Callable,
        send: Callable,
        config: WardenConfig,
        host: str,
        is_admin: bool,
        path: str,
    ) -> None:
        """Process a WebSocket connection.

        Handles admin‑only access, service routing, and passes the connection to the
        :class:`ProxyEngine` for upstream websockets.
        """
        session = await authenticate_scope(scope, self.db)
        scope.setdefault("state", {})["session"] = session
        scope.setdefault("state", {})["user"] = session.user if session else None
        route = None if is_admin else config.match_route(host)
        if route is None or not route.enabled:
            websocket = WebSocket(scope, receive, send)
            await websocket.accept()
            await websocket.close(code=4404, reason="No service here")
            return
        if route.auth and not route.is_public_path(path):
            if session is None:
                websocket = WebSocket(scope, receive, send)
                await websocket.accept()
                await websocket.close(code=4401, reason="Sign in required")
                return
            user = session.user
        else:
            user = None
        await self.proxy.handle_websocket(scope, receive, send, route, user)
