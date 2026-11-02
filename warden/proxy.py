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
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from starlette.websockets import WebSocket
from websockets.asyncio.client import connect as ws_connect
from websockets.exceptions import ConnectionClosed, InvalidHandshake, InvalidStatus

from warden.config import HOP_BY_HOP, ConfigManager, RouteConfig
from warden.stats import MetricsModule
from warden.templating import templates
from warden.utils import (
    RESERVED_COOKIES,
    apply_security_headers,
    client_ip,
    get_host,
    get_host_header,
    get_port,
    is_secure_request,
    public_scheme,
    request_wants_json,
    strip_reserved_cookies,
    upstream_url,
)

logger = logging.getLogger("warden.proxy")

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


class ProxyEngine:
    """Reverse‑proxy engine handling HTTP and WebSocket streams.

    * Manages a pool of ``httpx.AsyncClient`` instances for TLS‑verified and
      non‑TLS connections.
    * Performs request header sanitisation, forwards user identity headers,
      rewrites redirect locations, and sanitises ``Set‑Cookie`` values.
    * Enforces per‑route IP allow/deny lists and request‑size limits.
    """
    def __init__(self, manager: ConfigManager, stats: MetricsModule) -> None:
        """Create a new ``ProxyEngine``.

        * ``manager`` – provides configuration and the mesh manager.
        * ``stats`` – used to record request and health‑check metrics.
        """
        self.manager = manager
        self.stats = stats
        # ACME challenge token store: token -> response token (clear after successful renewal)
        self.acme_tokens: dict[str, str] = {}

        self._clients: dict[bool, httpx.AsyncClient] = {}
        # ACME challenge store: token -> response
        self._rate_windows: dict[str, deque[float]] = {}

    def _per_route_rate_limit(self, route: RouteConfig, now: float | None = None) -> bool:
        """Return ``True`` if the request should be rate-limited."""
        limit = route.rate_limit
        if limit is None:
            return False
        now = now if now is not None else time.monotonic()
        key = f"{route.host}:{route.upstream}"
        window = self._rate_windows.get(key)
        if window is None:
            self._rate_windows[key] = deque([now], maxlen=limit)
            return False
        # Purge entries older than 60 seconds
        cutoff = now - 60.0
        while window and window[0] < cutoff:
            window.popleft()
        if len(window) >= limit:
            return True
        window.append(now)
        return False

    def _client(self, verify: bool) -> httpx.AsyncClient:
        client = self._clients.get(verify)
        if client is None:
            client = httpx.AsyncClient(
                verify=verify,
                follow_redirects=False,
                trust_env=False,
                limits=httpx.Limits(max_connections=200, max_keepalive_connections=50),
                timeout=httpx.Timeout(60.0, connect=10.0),
                headers={"User-Agent": "warden/1"},
            )
            self._clients[verify] = client
        return client

    async def close(self) -> None:
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
        port = get_port(scope)
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
        target_port = target.port or (443 if target.scheme == "https" else 80)
        upstream_port = upstream.port or (443 if upstream.scheme == "https" else 80)
        if (target.hostname or "").lower() != upstream.hostname.lower() or target_port != upstream_port:
            return location
        scheme = str(scope.get("scheme", "http"))
        if scheme in {"ws", "wss"}:
            scheme = "http" if scheme == "ws" else "https"
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
        if name in RESERVED_COOKIES:
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
        await response(scope, receive, send)

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
        # ACME challenge response.
        path = scope.get("path", "")
        if self._per_route_rate_limit(route):
            response = Response("Rate limit exceeded", status_code=429, media_type="text/plain")
            response.headers["Retry-After"] = "60"
            await self._send(apply_security_headers(response), scope, receive, send)
            return
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

        headers = Headers(scope=scope)
        config = self.manager.config


        # IP Access Control.
        client_ip_str = client_ip(scope)
        try:
            client_ip_obj = ipaddress.ip_address(client_ip_str)
            for net in route.denied_ips:
                if client_ip_obj in ipaddress.ip_network(net):
                    response = self._error_response(
                        scope,
                        status=403,
                        title="Access denied",
                        message="Your IP address is explicitly blocked from this service.",
                    )
                    await self._send(response, scope, receive, send)
                    return
            if route.allowed_ips:  # noqa: SIM102
                if not any(client_ip_obj in ipaddress.ip_network(net) for net in route.allowed_ips):
                    response = self._error_response(
                        scope,
                        status=403,
                        title="Access denied",
                        message="Your IP address is not authorized to access this service.",
                    )
                    await self._send(response, scope, receive, send)
                    return
        except ValueError:
            # If we can't parse the IP, we default to blocking if there are allowed_ips
            if route.allowed_ips:
                response = self._error_response(
                    scope,
                    status=403,
                    title="Access denied",
                    message="Invalid client IP address.",
                )
                await self._send(response, scope, receive, send)
                return

        # Enforce max request body size.
        # Per RFC 7230, Transfer-Encoding (e.g. chunked) takes precedence over
        # Content-Length; when it is present, ignore Content-Length for the size
        # check instead of rejecting the request.
        content_length = headers.get("content-length")
        transfer_encoding = headers.get("transfer-encoding")
        if content_length and not transfer_encoding:
            try:
                length_bytes = int(content_length)
                max_bytes = config.server.max_body_size_mb * 1024 * 1024
                if length_bytes > max_bytes:
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
        request = Request(scope, receive)
        content_length = headers.get("content-length")
        has_body = bool(
            (content_length and content_length != "0") or "transfer-encoding" in headers
        )
        request.stream() if has_body else b""
        url = upstream_url(route, scope.get("raw_path"), scope.get("query_string", b""))
        config = self.manager.config
        timeout_seconds = route.timeout_seconds or config.server.request_timeout_seconds
        timeout = httpx.Timeout(timeout_seconds, connect=min(10.0, timeout_seconds))
        started = time.perf_counter()
        method = request.method
        upstream: httpx.Response | None = None
        try:
            client = self._client(route.verify_tls)
            request_headers = self._request_headers(scope, route, user)
            upstream_request = client.build_request(
                method,
                url,
                headers=request_headers,
                content=await request.body(),
                timeout=timeout,
            )
            upstream = await client.send(upstream_request, stream=True, follow_redirects=False)
            elapsed = (time.perf_counter() - started) * 1000
            if upstream.status_code < 100 or upstream.status_code == 101:
                await upstream.aclose()
                raise httpx.RemoteProtocolError("Unexpected upstream response status")
            self.stats.record_request(
                route,
                method=method,
                path=request.url.path,
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
        except httpx.TimeoutException:
            elapsed = (time.perf_counter() - started) * 1000
            logger.warning("Upstream timeout for %s %s", route.host, scope.get("path"))
            self.stats.record_request(
                route,
                method=method,
                path=request.url.path,
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
                path=request.url.path,
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
        finally:
            if upstream is not None:
                # For streaming responses this is a no-op after the generator closes.
                pass

    # ---------------------------------------------------------------- WebSocket
    def _websocket_headers(
        self, scope: MutableMapping[str, Any], route: RouteConfig, user: Any | None
    ) -> list[tuple[str, str]]:
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
        port = get_port(scope)
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
        if not route.websocket:
            websocket = WebSocket(scope, receive, send)
            await websocket.accept()
            await websocket.close(code=1008, reason="WebSockets are disabled for this service")
            return
        headers = Headers(scope=scope)
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
            while True:
                message = await websocket.receive()
                if message["type"] == "websocket.disconnect":
                    return
                if message.get("text") is not None:
                    await upstream.send(message["text"])
                elif message.get("bytes") is not None:
                    await upstream.send(message["bytes"])

        async def upstream_to_client() -> None:
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
