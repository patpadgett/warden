"""Async reverse proxy engine (streaming HTTP + WebSocket relay).

The :class:`ProxyEngine` class implements the core reverse‑proxy functionality for Warden.
It forwards HTTP requests and WebSocket connections to configured upstream services,
rewriting ``Location`` redirects and ``Set-Cookie`` headers as needed, and enforcing
IP allow/deny lists. The engine also inserts security‑related forwarded headers and
optionally strips or rewrites request/response headers according to the route
configuration.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import ssl
import time
from collections import deque
from collections.abc import MutableMapping
from typing import Any
from urllib.parse import urlsplit

import httpx
from starlette.background import BackgroundTask
from starlette.datastructures import Headers
from starlette.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from starlette.websockets import WebSocket
from websockets.asyncio.client import connect as ws_connect
from websockets.exceptions import ConnectionClosed, InvalidHandshake, InvalidStatus

from warden.config import HOP_BY_HOP, ConfigManager, RouteConfig, normalize_path
from warden.stats import MetricsModule
from warden.templating import templates
from warden.utils import (
    apply_security_headers,
    client_ip,
    get_host,
    get_host_header,
    host_port,
    is_reserved_cookie,
    is_secure_request,
    public_scheme,
    request_wants_json,
    strip_reserved_cookies,
    upstream_url,
)

logger = logging.getLogger("warden.proxy")

#: Upper bound on tracked rate-limit windows before a sweep of stale keys.
_RATE_WINDOW_MAX_KEYS = 4096

# Headers that must never be trusted from the public edge.
_STRIP_REQUEST_HEADERS = HOP_BY_HOP | {
    "host",
    "expect",
    "content-length",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-forwarded-port",
    "x-real-ip",
    "forwarded",
    "x-warden-user",
    "x-warden-user-id",
    "x-forwarded-user",
    "x-forwarded-email",
    "remote-user",
    "remote-email",
    "x-auth-request-user",
    "x-auth-request-email",
}


class _BodyTooLarge(Exception):
    """Raised when a request body exceeds ``server.max_body_size_mb``."""


class _BoundedReceive:
    """ASGI ``receive`` wrapper that rejects bodies above a byte limit.

    Enforcing only ``Content-Length`` is insufficient because chunked requests
    do not carry one. This wrapper counts bytes as Starlette reads them, so the
    limit also applies to chunked uploads.
    """

    def __init__(self, receive: Any, max_bytes: int) -> None:
        """__init__."""
        self._receive = receive
        self._max_bytes = max_bytes
        self._total = 0

    async def __call__(self) -> Any:
        """__call__."""
        message = await self._receive()
        if message.get("type") == "http.request":
            self._total += len(message.get("body", b""))
            if self._total > self._max_bytes:
                raise _BodyTooLarge
        return message


class _BoundedStream(httpx.AsyncByteStream):
    """Stream an ASGI request body upstream, enforcing the byte limit as it flows.

    Responses already stream; buffering requests meant a large upload sat in
    Warden's memory in full before a single byte reached the upstream.
    """

    def __init__(self, receive: Any, max_bytes: int) -> None:
        self._bounded = _BoundedReceive(receive, max_bytes)

    async def __aiter__(self):
        while True:
            message = await self._bounded()
            if message.get("type") == "http.disconnect":
                break
            body = message.get("body", b"")
            if body:
                yield body
            if not message.get("more_body", False):
                break


class ProxyEngine:
    """Reverse‑proxy engine handling HTTP and WebSocket streams.

    * Manages a pool of ``httpx.AsyncClient`` instances for TLS‑verified and
      non‑TLS connections.
    * Performs request header sanitisation, forwards user identity headers,
      rewrites redirect locations, and sanitises ``Set‑Cookie`` values.
    * Enforces per‑route IP allow/deny lists and request‑size limits.
    """
    def __init__(self, manager: ConfigManager, stats: MetricsModule, health_monitor: Any = None) -> None:
        """Create a new ``ProxyEngine``.

        * ``manager`` – provides configuration and the mesh manager.
        * ``stats`` – used to record request and health‑check metrics.
        * ``health_monitor`` – optional upstream health monitor for pre‑flight checks.
        """
        self.manager = manager
        self.stats = stats
        self.health_monitor = health_monitor
        # ACME challenge token store: token -> response token (clear after successful renewal)
        self.acme_tokens: dict[str, str] = {}

        self._clients: dict[bool, httpx.AsyncClient] = {}
        # ACME challenge store: token -> response
        self._rate_windows: dict[str, deque[float]] = {}

    def _per_route_rate_limit(
        self, route: RouteConfig, client: str, now: float | None = None
    ) -> bool:
        """Return ``True`` if this client should be rate-limited for *route*."""
        limit = route.rate_limit
        if limit is None:
            return False
        now = now if now is not None else time.monotonic()
        # Purge entries older than 60 seconds
        cutoff = now - 60.0
        key = f"{route.host}:{route.upstream}:{client}"
        window = self._rate_windows.get(key)
        if window is None:
            self._rate_windows[key] = deque([now], maxlen=limit)
            # One entry per source address would otherwise accumulate forever.
            # Sweep only when the table grows, so the common path stays O(1).
            if len(self._rate_windows) > _RATE_WINDOW_MAX_KEYS:
                self._prune_rate_windows(cutoff)
            return False
        while window and window[0] < cutoff:
            window.popleft()
        if len(window) >= limit:
            return True
        window.append(now)
        return False

    def _prune_rate_windows(self, cutoff: float) -> None:
        """Drop rate-limit windows whose newest sample has aged out."""
        stale = [
            key
            for key, window in self._rate_windows.items()
            if not window or window[-1] < cutoff
        ]
        for key in stale:
            self._rate_windows.pop(key, None)

    def _client(self, verify: bool) -> httpx.AsyncClient:
        """_client."""
        client = self._clients.get(verify)
        if client is None:
            client_kwargs: dict[str, Any] = {
                "verify": verify,
                "follow_redirects": False,
                "trust_env": False,
                "limits": httpx.Limits(max_connections=200, max_keepalive_connections=50),
                "timeout": httpx.Timeout(60.0, connect=10.0),
                "headers": {"User-Agent": "warden/1"},
            }
            try:
                client = httpx.AsyncClient(http2=True, **client_kwargs)
            except ImportError:
                client = httpx.AsyncClient(**client_kwargs)
            self._clients[verify] = client
        return client

    async def close(self) -> None:
        """close."""
        for client in self._clients.values():
            await client.aclose()
        self._clients.clear()

    async def reset_clients(self) -> None:
        """Clear cached httpx.AsyncClient instances, forcing recreation on next request."""
        for client in self._clients.values():
            await client.aclose()
        self._clients.clear()

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _connection_tokens(values: list[str]) -> set[str]:
        """Extract token names from ``Connection`` header values.

        ``Connection`` may contain a comma‑separated list of tokens; this helper
        returns a set of lower‑cased token names.
        """
        tokens: set[str] = set()
        for value in values:
            for token in value.split(","):
                token = token.strip().lower()
                if token:
                    tokens.add(token)
        return tokens

    @staticmethod
    def _normalized_path(path: str) -> str:
        """Collapse ``.``/``..`` segments and duplicate slashes for ACL matching.

        Warden forwards the original path, so this is only used to decide
        whether a blocked path matches: ``/public/../secret`` and ``//secret``
        must not slip past a blocked ``/secret``. The same helper backs
        ``public_paths`` so the deny and allow rules cannot disagree.
        """
        return normalize_path(path)

    @staticmethod
    def _ip_denial(route: RouteConfig, client: str) -> str | None:
        """Return why *client* may not reach *route*, or ``None`` when it may.

        Shared by the HTTP and WebSocket paths so an allow-list cannot be
        bypassed by opening a WebSocket instead of a request.
        """
        try:
            address = ipaddress.ip_address(client)
        except ValueError:
            return "Invalid client IP address." if route.allowed_ips else None
        # A dual-stack listener reports IPv4 clients as ``::ffff:a.b.c.d``,
        # which never matches an IPv4 network: an allow-list would reject
        # legitimate clients and a deny-list would let blocked ones through.
        mapped = getattr(address, "ipv4_mapped", None)
        if mapped is not None:
            address = mapped
        if any(address in ipaddress.ip_network(net) for net in route.denied_ips):
            return "Your IP address is explicitly blocked from this service."
        if route.allowed_ips and not any(
            address in ipaddress.ip_network(net) for net in route.allowed_ips
        ):
            return "Your IP address is not authorized to access this service."
        return None

    @staticmethod
    def _user_agent_denial(route: RouteConfig, user_agent: str) -> str | None:
        """Return a denial message for a blocked user agent, or ``None``."""
        lowered = user_agent.lower()
        if any(blocked.lower() in lowered for blocked in route.blocked_user_agents):
            return "This service does not accept requests from your client."
        return None

    @staticmethod
    def _path_denial(route: RouteConfig, path: str) -> str | None:
        """Return a denial message when *path* is blocked on *route*.

        Both sides are normalised first, so a blocked ``/secret`` also matches
        ``/secret/``, ``//secret`` and ``/public/../secret``.
        """
        normalized = ProxyEngine._normalized_path(path).casefold()
        for blocked in route.blocked_paths:
            if blocked.endswith("/*"):
                prefix = ProxyEngine._normalized_path(blocked[:-1]).casefold()
                if prefix == "/" or normalized == prefix or normalized.startswith(
                    prefix + "/"
                ):
                    return "This path is not allowed."
            elif normalized == ProxyEngine._normalized_path(blocked).casefold():
                return "This path is not allowed."
        return None

    def _request_headers(
        self,
        scope: MutableMapping[str, Any],
        route: RouteConfig,
        user: Any | None,
    ) -> list[tuple[str, str]]:
        """Build the list of HTTP request headers to send upstream.

        * Strips hop‑by‑hop and unsafe headers.
        * Removes Warden‑managed cookies.
        * Adds ``X‑Forwarded-*`` headers for client IP, host and scheme.
        * Optionally forwards the authenticated user's name via ``forward_user_header``.
        """
        raw_headers = scope.get("headers", [])
        decoded: list[tuple[str, str]] = [
            (key.decode("latin-1"), value.decode("latin-1")) for key, value in raw_headers
        ]
        connections = self._connection_tokens(
            [value for key, value in decoded if key.lower() == "connection"]
        )
        skip = _STRIP_REQUEST_HEADERS | connections
        output: list[tuple[str, str]] = []
        for key, value in decoded:
            lower = key.lower()
            if lower in skip:
                continue
            if lower == "cookie":
                cleaned = strip_reserved_cookies(value)
                if cleaned:
                    output.append((key, cleaned))
                continue
            if lower == "accept-encoding" and not value.strip():
                continue
            output.append((key, value))
        if not any(key.lower() == "accept-encoding" for key, _ in output):
            output.append(("accept-encoding", "identity"))
        if route.preserve_host:
            output.append(("host", get_host_header(scope)))
        ip = client_ip(scope)
        host_header = get_host_header(scope)
        scheme = public_scheme(scope, self.manager.config)
        
        output.extend(
            [
                ("x-forwarded-for", ip),
                ("x-forwarded-host", host_header),
                ("x-forwarded-proto", scheme),
                ("x-real-ip", ip),
            ]
        )
        # Only the port the client used: behind a TLS terminator the listener
        # port is not reachable from outside, so forwarding it makes apps build
        # absolute URLs against an address that does not exist for the user.
        port = host_port(scope)
        if port:
            output.append(("x-forwarded-port", str(port)))
        if route.auth and user is not None:
            config = self.manager.config
            forwarded = config.server.forward_user_header
            if forwarded and forwarded.lower() not in {"x-warden-user", "x-warden-user-id"}:
                output.append((forwarded, str(user.username)))
            output.append(("x-warden-user", str(user.username)))
            output.append(("x-warden-user-id", str(user.id)))
        for key, value in route.headers.items():
            lower = key.lower()
            output = [(k, v) for k, v in output if k.lower() != lower]
            output.append((key, value))
        return output

    def _rewrite_location(
        self, location: str, route: RouteConfig, scope: MutableMapping[str, Any]
    ) -> str:
        """Rewrite an upstream ``Location`` header to a public URL when appropriate.

        The rewrite only occurs if ``route.rewrite_redirects`` is enabled and the
        location points back to the same host/port as the configured upstream.
        """
        if not route.rewrite_redirects or not location:
            return location
        try:
            target = urlsplit(location)
            upstream = urlsplit(route.upstream)
        except ValueError:
            return location
        if not target.netloc or not upstream.hostname:
            return location
        try:
            target_port = target.port or (443 if target.scheme == "https" else 80)
            upstream_port = upstream.port or (443 if upstream.scheme == "https" else 80)
        except ValueError:
            # A malformed port (out of range, non-numeric) makes the header
            # unparseable; pass it through instead of failing the request.
            return location
        if (target.hostname or "").lower() != upstream.hostname.lower() or target_port != upstream_port:
            return location
        public = f"{public_scheme(scope, self.manager.config)}://{get_host_header(scope)}"
        return f"{public}{target.path or '/'}" + (f"?{target.query}" if target.query else "") + (
            f"#{target.fragment}" if target.fragment else ""
        )

    def _rewrite_set_cookie(
        self, value: str, scope: MutableMapping[str, Any], route: RouteConfig
    ) -> str | None:
        """Rewrite a ``Set‑Cookie`` header value for public consumption.

        * Drops cookies that belong to Warden’s internal session/csrf cookies.
        * Adjusts ``Domain`` and ``Secure`` attributes based on the public request.
        """
        name = value.split(";", 1)[0].split("=", 1)[0].strip()
        if is_reserved_cookie(name):
            return None
        if not route.rewrite_cookies:
            return value
        public_host = get_host(scope)
        secure = is_secure_request(scope, self.manager.config)
        parts = value.split(";")
        output = [parts[0].strip()]
        for part in parts[1:]:
            attr = part.strip()
            if not attr:
                continue
            attr_name = attr.split("=", 1)[0].strip().lower()
            if attr_name == "domain":
                if "=" not in attr:
                    # A bare ``Domain`` attribute carries no value; drop it
                    # rather than raising.
                    continue
                domain = attr.split("=", 1)[1].strip().lstrip(".").lower()
                if domain and (
                    public_host == domain or public_host.endswith("." + domain)
                ):
                    output.append(attr)
                # Otherwise drop it: the upstream domain is not reachable from here.
                continue
            if attr_name == "secure" and not secure:
                # Secure cookies would be silently dropped on plain-HTTP dev setups.
                continue
            output.append(attr)
        return "; ".join(output)

    def _response_headers(
        self,
        upstream: httpx.Response,
        route: RouteConfig,
        scope: MutableMapping[str, Any],
    ) -> list[tuple[bytes, bytes]]:
        """Prepare response headers for the client, filtering and rewriting as needed.

        * Strips hop‑by‑hop and ``Connection`` tokens.
        * Rewrites ``Location`` and ``Set‑Cookie`` according to route settings.
        """
        connection_values = upstream.headers.get_list("connection")
        skip = HOP_BY_HOP | self._connection_tokens(connection_values)
        skip |= {"alt-svc"}
        headers: list[tuple[bytes, bytes]] = []
        for key, value in upstream.headers.multi_items():
            lower = key.lower()
            if lower in skip:
                continue
            if lower == "location":
                value = self._rewrite_location(value, route, scope)
            if lower == "set-cookie":
                rewritten = self._rewrite_set_cookie(value, scope, route)
                if rewritten is None:
                    continue
                value = rewritten
            headers.append((key.encode("latin-1"), value.encode("latin-1")))
        return headers

    def _error_response(
        self,
        scope: MutableMapping[str, Any],
        *,
        status: int,
        title: str,
        message: str,
        detail: str = "",
    ) -> Response:
        """Return an error page or JSON payload based on request expectations.

        * If ``request_wants_json`` is true, returns a JSONResponse.
        * Otherwise renders the ``error.html`` template.
        """
        if request_wants_json(scope):
            return JSONResponse(
                {"detail": message, "status": status},
                status_code=status,
                headers={"Cache-Control": "no-store"},
            )
        template = templates.get_template("error.html")
        body = template.render(
            page_title=title,
            code=str(status),
            title=title,
            message=message,
            detail=detail,
            host=Headers(scope=scope).get("host", ""),
            retry_url=scope.get("path", "/"),
        )
        response = HTMLResponse(body, status_code=status)
        response.headers["Cache-Control"] = "no-store"
        return apply_security_headers(response)

    async def _send(self, response: Response, scope: Any, receive: Any, send: Any) -> None:
        """_send."""
        await response(scope, receive, send)

    @staticmethod
    def _group_denial(route: RouteConfig, user: Any | None) -> str | None:
        """Return why *user* may not reach *route*, or ``None`` when it may.

        Shared by the HTTP and WebSocket paths. A route with no
        ``allowed_groups`` is open to every signed-in user, so a missing ACL
        cannot accidentally lock a service down.
        """
        if route.allows_user(user):
            return None
        return "Your account is not in a group allowed to use this service."

    def _record_edge(
        self,
        route: RouteConfig,
        scope: MutableMapping[str, Any],
        status: int,
        user: Any | None,
    ) -> None:
        """Record a response Warden generated itself (denial, limit, 413/503).

        These never reach the upstream, so without this they were invisible in
        the dashboard and in ``warden_route_requests_total``: a route under a
        brute-force or scan attempt reported zero requests.
        """
        self.stats.record_request(
            route,
            method=scope.get("method", "GET"),
            path=scope.get("path", "/"),
            status=status,
            latency_ms=0.0,
            user=str(user.username) if user else None,
        )

    # --------------------------------------------------------------------- HTTP
    async def handle_http(
        self,
        scope: MutableMapping[str, Any],
        receive: Any,
        send: Any,
        route: RouteConfig,
        user: Any | None,
    ) -> None:
        """Handle an incoming HTTP request by proxying it to *route*.

        * Serves ACME challenges when applicable.
        * Enforces IP allow/deny lists and request‑size limits.
        * Streams the upstream response back to the client, handling redirects,
          ``Set‑Cookie`` rewriting and error cases.
        """
        path = scope.get("path", "")
        # Serve ACME challenges before the per-route rate limit: a CA fetching
        # `/.well-known/acme-challenge/...` must not be refused because the
        # route is under a scan, or a renewal fails for an unrelated reason.
        if path.startswith("/.well-known/acme-challenge/"):
            token = path[len("/.well-known/acme-challenge/"):]
            response_token = None
            if token in self.acme_tokens:
                response_token = self.acme_tokens[token]
            elif hasattr(self, "acme_manager"):
                response_token = self.acme_manager.get_challenge_response(token)
            if response_token is not None:
                response = Response(
                    response_token,
                    status_code=200,
                    headers={"Content-Type": "text/plain"},
                )
                await self._send(response, scope, receive, send)
                return

        if self._per_route_rate_limit(route, client_ip(scope)):
            self._record_edge(route, scope, 429, user)
            response = Response("Rate limit exceeded", status_code=429, media_type="text/plain")
            response.headers["Retry-After"] = "60"
            await self._send(apply_security_headers(response), scope, receive, send)
            return

        headers = Headers(scope=scope)
        config = self.manager.config


        # Access control: IP allow/deny lists, blocked clients, blocked paths.
        client_ip_str = client_ip(scope)
        denial = (
            self._ip_denial(route, client_ip_str)
            or self._user_agent_denial(route, headers.get("user-agent", ""))
            or self._path_denial(route, scope.get("path", ""))
            or self._group_denial(route, user)
        )
        if denial is not None:
            self._record_edge(route, scope, 403, user)
            response = self._error_response(
                scope, status=403, title="Access denied", message=denial
            )
            await self._send(response, scope, receive, send)
            return

        if self.health_monitor is not None:
            # Health state is recorded under the route host (see HealthMonitor),
            # so look it up by route.host rather than the upstream hostname.
            health = self.stats.health.get(route.host)
            if health is not None and health.online is False and health.checked_at is not None:
                self._record_edge(route, scope, 503, user)
                response = self._error_response(
                    scope,
                    status=503,
                    title="Service unavailable",
                    message="The upstream service is currently offline.",
                )
                await self._send(response, scope, receive, send)
                return

        # Enforce max request body size.
        # Per RFC 7230, Transfer-Encoding (e.g. chunked) takes precedence over
        # Content-Length; when it is present, ignore Content-Length for the size
        # check instead of rejecting the request. The actual read below is
        # bounded as well so chunked bodies cannot bypass the limit.
        max_bytes = config.server.max_body_size_mb * 1024 * 1024
        content_length = headers.get("content-length")
        transfer_encoding = headers.get("transfer-encoding")
        if content_length and not transfer_encoding:
            try:
                length_bytes = int(content_length)
                if length_bytes > max_bytes:
                    self._record_edge(route, scope, 413, user)
                    response = self._error_response(
                        scope,
                        status=413,
                        title="Request entity too large",
                        message=f"Request body exceeds the maximum limit of {config.server.max_body_size_mb} MB.",
                    )
                    await self._send(response, scope, receive, send)
                    return
            except ValueError:
                pass
        # Stream the request body with the same bounded receive, so large
        # uploads no longer sit in memory in full before being forwarded.
        url = upstream_url(route, scope.get("raw_path"), scope.get("query_string", b""))
        timeout_seconds = route.timeout_seconds or config.server.request_timeout_seconds
        timeout = httpx.Timeout(timeout_seconds, connect=min(10.0, timeout_seconds))
        started = time.perf_counter()
        method = scope.get("method", "GET")
        upstream: httpx.Response | None = None
        try:
            client = self._client(route.verify_tls)
            request_headers = self._request_headers(scope, route, user)
            if content_length and not transfer_encoding:
                # A streamed body has no length of its own, so httpx would switch
                # the forwarded request to chunked encoding and drop the declared
                # length. Upstreams that read exactly Content-Length bytes (many
                # WSGI servers and hand-written handlers) would then see an empty
                # body, so keep the original length when one was declared.
                request_headers = [
                    (key, value) for key, value in request_headers if key.lower() != "content-length"
                ]
                request_headers.append(("content-length", content_length))
            upstream_request = client.build_request(
                method,
                url,
                headers=request_headers,
                content=_BoundedStream(receive, max_bytes),
                timeout=timeout,
            )
            upstream = await client.send(upstream_request, stream=True, follow_redirects=False)
            elapsed = (time.perf_counter() - started) * 1000
            if upstream.status_code < 200:
                await upstream.aclose()
                raise httpx.RemoteProtocolError("Unexpected upstream response status")
            self.stats.record_request(
                route,
                method=method,
                path=scope.get("path", "/"),
                status=upstream.status_code,
                latency_ms=elapsed,
                user=str(user.username) if user else None,
            )
            response_headers = self._response_headers(upstream, route, scope)
            if method.upper() == "HEAD" or upstream.status_code in {204, 304}:
                response = Response(status_code=upstream.status_code)
                response.raw_headers = response_headers
                await upstream.aclose()
                await self._send(response, scope, receive, send)
                return

            async def body_iterator():
                """body_iterator."""
                try:
                    async for chunk in upstream.aiter_raw():
                        if chunk:
                            yield chunk
                finally:
                    await upstream.aclose()

            response = StreamingResponse(
                body_iterator(),
                status_code=upstream.status_code,
                background=BackgroundTask(upstream.aclose),
            )
            response.raw_headers = response_headers
            await self._send(response, scope, receive, send)
        except asyncio.CancelledError:
            if upstream is not None:
                await upstream.aclose()
            raise
        except _BodyTooLarge:
            # The limit was exceeded while streaming the body to the upstream.
            if upstream is not None:
                await upstream.aclose()
            self._record_edge(route, scope, 413, user)
            response = self._error_response(
                scope,
                status=413,
                title="Request entity too large",
                message=f"Request body exceeds the maximum limit of {config.server.max_body_size_mb} MB.",
            )
            await self._send(response, scope, receive, send)
        except httpx.TimeoutException:
            elapsed = (time.perf_counter() - started) * 1000
            logger.warning("Upstream timeout for %s %s", route.host, scope.get("path"))
            self.stats.record_request(
                route,
                method=method,
                path=scope.get("path", "/"),
                status=504,
                latency_ms=elapsed,
                user=str(user.username) if user else None,
            )
            response = self._error_response(
                scope,
                status=504,
                title="The service is taking too long",
                message="Warden reached the service, but it didn't answer in time. Try again in a moment.",
            )
            await self._send(response, scope, receive, send)
        except httpx.HTTPError as exc:
            elapsed = (time.perf_counter() - started) * 1000
            logger.warning(
                "Upstream error for %s %s: %s: %s",
                route.host,
                scope.get("path"),
                exc.__class__.__name__,
                exc,
            )
            self.stats.record_request(
                route,
                method=method,
                path=scope.get("path", "/"),
                status=502,
                latency_ms=elapsed,
                user=str(user.username) if user else None,
            )
            response = self._error_response(
                scope,
                status=502,
                title="The service is out of reach",
                message="The service behind this address isn't responding. Check that it's running and reachable.",
            )
            await self._send(response, scope, receive, send)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            logger.exception("Proxy failure for %s", route.host)
            response = self._error_response(
                scope,
                status=502,
                title="The service is out of reach",
                message="Warden couldn't complete the request to this service.",
            )
            await self._send(response, scope, receive, send)

    # ---------------------------------------------------------------- WebSocket
    def _websocket_headers(
        self, scope: MutableMapping[str, Any], route: RouteConfig, user: Any | None
    ) -> list[tuple[str, str]]:
        """_websocket_headers."""
        decoded = [
            (key.decode("latin-1"), value.decode("latin-1"))
            for key, value in scope.get("headers", [])
        ]
        skip = set(_STRIP_REQUEST_HEADERS) | {
            "sec-websocket-key",
            "sec-websocket-version",
            "sec-websocket-extensions",
            "sec-websocket-protocol",
            "origin",
        }
        output: list[tuple[str, str]] = []
        for key, value in decoded:
            lower = key.lower()
            if lower in skip:
                continue
            if lower == "cookie":
                cleaned = strip_reserved_cookies(value)
                if cleaned:
                    output.append(("cookie", cleaned))
                continue
            output.append((key, value))
        output.append(("x-forwarded-for", client_ip(scope)))
        output.append(("x-forwarded-host", get_host_header(scope)))
        output.append(("x-forwarded-proto", public_scheme(scope, self.manager.config)))
        port = host_port(scope)
        if port:
            output.append(("x-forwarded-port", str(port)))
        if route.auth and user is not None:
            config = self.manager.config
            forwarded = config.server.forward_user_header
            if forwarded and forwarded.lower() not in {"x-warden-user", "x-warden-user-id"}:
                output.append((forwarded, str(user.username)))
            output.append(("x-warden-user", str(user.username)))
            output.append(("x-warden-user-id", str(user.id)))
        for key, value in route.headers.items():
            lower = key.lower()
            output = [(k, v) for k, v in output if k.lower() != lower]
            output.append((key, value))
        return output

    async def handle_websocket(
        self,
        scope: MutableMapping[str, Any],
        receive: Any,
        send: Any,
        route: RouteConfig,
        user: Any | None,
    ) -> None:
        """Proxy a WebSocket connection to the upstream service defined by *route*.

        Performs origin checks, enforces authentication (if ``route.auth``), and
        forwards messages bidirectionally between client and upstream.
        """
        if self._per_route_rate_limit(route, client_ip(scope)):
            # The HTTP path enforces `route.rate_limit`; without this the limit
            # could be skipped entirely by opening a WebSocket instead.
            websocket = WebSocket(scope, receive, send)
            await websocket.accept()
            await websocket.close(code=4429, reason="Rate limit exceeded")
            self.stats.record_request(
                route,
                method="WS",
                path=scope.get("path", "/"),
                status=429,
                latency_ms=0.0,
                user=str(user.username) if user else None,
            )
            return
        headers = Headers(scope=scope)
        # The same access rules as the HTTP path: without this an IP allow-list
        # or blocked path could be bypassed by opening a WebSocket.
        denial = (
            self._ip_denial(route, client_ip(scope))
            or self._user_agent_denial(route, headers.get("user-agent", ""))
            or self._path_denial(route, scope.get("path", "/"))
            or self._group_denial(route, user)
        )
        if denial is not None:
            websocket = WebSocket(scope, receive, send)
            await websocket.accept()
            await websocket.close(code=4403, reason="Access denied")
            return
        if not route.websocket:
            websocket = WebSocket(scope, receive, send)
            await websocket.accept()
            await websocket.close(code=1008, reason="WebSockets are disabled for this service")
            return
        origin = headers.get("origin")
        config = self.manager.config
        if origin and not config.origin_allowed(origin):
            websocket = WebSocket(scope, receive, send)
            await websocket.accept()
            await websocket.close(code=4403, reason="Origin not allowed")
            return
        offered = [
            item.strip()
            for item in headers.get("sec-websocket-protocol", "").split(",")
            if item.strip()
        ]
        if route.websocket_subprotocols:
            allowed = set(route.websocket_subprotocols)
            if offered and not any(p in allowed for p in offered):
                websocket = WebSocket(scope, receive, send)
                await websocket.accept(subprotocol="")
                await websocket.close(code=1008, reason="Subprotocol not allowed")
                return
        url = upstream_url(
            route, scope.get("raw_path"), scope.get("query_string", b""), websocket=True
        )
        ssl_context: ssl.SSLContext | bool | None = None
        if url.startswith("wss://"):
            if route.verify_tls:
                ssl_context = ssl.create_default_context()
            else:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
        started = time.perf_counter()
        websocket = WebSocket(scope, receive, send)
        try:
            upstream = await ws_connect(
                url,
                origin=origin or None,
                subprotocols=offered or None,
                additional_headers=self._websocket_headers(scope, route, user),
                user_agent_header=None,
                proxy=None,
                ssl=ssl_context,
                open_timeout=10,
                ping_interval=20,
                ping_timeout=20,
                max_size=route.websocket_max_size,
                compression="deflate",
            )
        except (TimeoutError, InvalidStatus, InvalidHandshake, OSError) as exc:
            logger.warning("WebSocket upstream failed for %s: %s", route.host, exc)
            await websocket.accept()
            await websocket.close(code=1011, reason="Upstream unavailable")
            self.stats.record_request(
                route,
                method="WS",
                path=scope.get("path", "/"),
                status=502,
                latency_ms=(time.perf_counter() - started) * 1000,
                user=str(user.username) if user else None,
            )
            return

        chosen = upstream.subprotocol
        if chosen and route.websocket_subprotocols and chosen not in route.websocket_subprotocols:
            # The pre-flight check only proves that *some* offered protocol is
            # allowed; the upstream is free to pick another offered one, so the
            # selection has to be checked before the client is told it won.
            logger.warning(
                "WebSocket upstream chose disallowed subprotocol %r for %s", chosen, route.host
            )
            await upstream.close()
            await websocket.accept()
            await websocket.close(code=1008, reason="Subprotocol not allowed")
            self.stats.record_request(
                route,
                method="WS",
                path=scope.get("path", "/"),
                status=403,
                latency_ms=(time.perf_counter() - started) * 1000,
                user=str(user.username) if user else None,
            )
            return

        try:
            await websocket.accept(subprotocol=upstream.subprotocol)
            self.stats.record_request(
                route,
                method="WS",
                path=scope.get("path", "/"),
                status=101,
                latency_ms=(time.perf_counter() - started) * 1000,
                user=str(user.username) if user else None,
            )
        except (KeyboardInterrupt, SystemExit):
            await upstream.close()
            raise
        except Exception:
            await upstream.close()
            raise

        async def client_to_upstream() -> None:
            """client_to_upstream."""
            while True:
                message = await websocket.receive()
                if message["type"] == "websocket.disconnect":
                    return
                if message.get("text") is not None:
                    await upstream.send(message["text"])
                elif message.get("bytes") is not None:
                    await upstream.send(message["bytes"])

        async def upstream_to_client() -> None:
            """upstream_to_client."""
            async for message in upstream:
                if isinstance(message, str):
                    await websocket.send_text(message)
                else:
                    await websocket.send_bytes(message)

        tasks = [
            asyncio.create_task(client_to_upstream()),
            asyncio.create_task(upstream_to_client()),
        ]
        try:
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            for task in done:
                try:
                    task.result()
                except (ConnectionClosed, Exception):  # noqa: BLE001, S110
                    pass
        finally:
            close_code = upstream.close_code
            if close_code is None or close_code == 1005 or close_code == 1006:
                close_code = 1000
            try:
                await upstream.close()
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:  # noqa: BLE001, S110
                pass
            try:
                await websocket.close(code=close_code)
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:  # noqa: BLE001, S110
                pass
