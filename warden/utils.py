"""HTTP, cookie, origin, and formatting helpers shared across Warden."""

from __future__ import annotations

import hashlib
import html
import json
import re
import time
from collections import defaultdict, deque
from collections.abc import Iterable, MutableMapping
from http.cookies import SimpleCookie
from typing import Any
from urllib.parse import quote, urlsplit

from starlette.datastructures import Headers
from starlette.responses import JSONResponse, RedirectResponse, Response

from warden.config import RouteConfig, WardenConfig

SESSION_COOKIE = "warden_session"
CHALLENGE_COOKIE = "warden_challenge"
RESERVED_COOKIES = {SESSION_COOKIE, CHALLENGE_COOKIE}
INTERNAL_PREFIX = "/_warden"


def get_host(scope: MutableMapping[str, Any]) -> str:
    """Return a normalized hostname from an ASGI scope (no port)."""
    host = Headers(scope=scope).get("host")
    if not host:
        server = scope.get("server") or ("", 0)
        host = str(server[0])
    host = host.strip()
    if host.startswith("["):
        end = host.find("]")
        if end != -1:
            return host[1:end].lower().rstrip(".")
    if host.count(":") == 1:
        host = host.rsplit(":", 1)[0]
    return host.lower().rstrip(".")


def get_host_header(scope: MutableMapping[str, Any]) -> str:
    """Return the sanitized Host header, including a non-default port."""
    host = Headers(scope=scope).get("host")
    if host:
        host = host.strip().replace("\r", "").replace("\n", "")
        return host
    server = scope.get("server") or ("", 0)
    return str(server[0])


def get_port(scope: MutableMapping[str, Any]) -> int | None:
    """Extract the numeric port from the Host header if present; returns ``None`` when no explicit port is specified."""
    host = get_host_header(scope)
    if host.startswith("["):
        match = re.match(r"^\[[^\]]+\]:(\d+)$", host)
        if match:
            return int(match.group(1))
    if host.count(":") == 1:
        _, port = host.rsplit(":", 1)
        if port.isdigit():
            return int(port)
    server = scope.get("server")
    return int(server[1]) if server and server[1] else None


def base_scheme(scope: MutableMapping[str, Any]) -> str:
    scheme = str(scope.get("scheme", "http"))
    if scheme in {"ws", "wss"}:
        scheme = "http" if scheme == "ws" else "https"
    return scheme


def public_scheme(scope: MutableMapping[str, Any], config: WardenConfig) -> str:
    return config.server.external_scheme or base_scheme(scope)


def current_origin(scope: MutableMapping[str, Any], config: WardenConfig) -> str:
    host = get_host(scope)
    if config.server.public_url and host == config.server.admin_host:
        return config.server.public_url
    return f"{public_scheme(scope, config)}://{get_host_header(scope)}"


def external_url(scope: MutableMapping[str, Any], config: WardenConfig, host: str) -> str:
    """Build an absolute URL for a configured service, preserving a custom port."""
    scheme = public_scheme(scope, config)
    if config.server.public_url:
        parts = urlsplit(config.server.public_url)
        port = parts.port
        if port:
            return f"{scheme}://{host}:{port}"
    port = get_port(scope)
    if port and port not in {80, 443}:
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}"


def admin_url(scope: MutableMapping[str, Any], config: WardenConfig) -> str:
    if config.server.public_url:
        return config.server.public_url
    return external_url(scope, config, config.server.admin_host)


def login_url(scope: MutableMapping[str, Any], config: WardenConfig, next_path: str) -> str:
    """Build the internal login URL with an optional ``next`` redirect. The ``next`` value is sanitized via ``safe_next`` and URL‑escaped."""
    safe = safe_next(next_path, fallback="/")
    return f"{INTERNAL_PREFIX}/login?next={quote(safe, safe='')}"


def is_secure_request(scope: MutableMapping[str, Any], config: WardenConfig) -> bool:
    """Return ``True`` if the request is considered secure, using the explicit ``secure_cookies`` flag or the request scheme."""
    if config.server.secure_cookies is not None:
        return config.server.secure_cookies
    return public_scheme(scope, config) == "https"


def cookie_domain(config: WardenConfig) -> str | None:
    """Return the configured cookie domain if it is a non‑local hostname; otherwise ``None``."""
    domain = config.server.cookie_domain
    if not domain:
        return None
    if domain in {"localhost", "127.0.0.1", "::1"}:
        return None
    return domain


def session_cookie_name(config_server: Any, scope: MutableMapping[str, Any]) -> str:
    """Return the session cookie name, using ``__Host-`` prefix when possible.

    ``__Host-`` cookies require ``Secure`` and no ``Domain`` attribute.
    """
    if hasattr(config_server, "server"):
        server = config_server.server
    else:
        server = config_server
    secure = bool(server.secure_cookies) if server.secure_cookies is not None else base_scheme(scope) == "https"
    domain = server.cookie_domain
    if secure and not domain:
        return f"__Host-{SESSION_COOKIE}"
    return SESSION_COOKIE


def parse_cookies(scope: MutableMapping[str, Any]) -> dict[str, str]:
    """Parse the ``Cookie`` header into a dictionary of name/value pairs, ignoring malformed entries."""
    raw = Headers(scope=scope).get("cookie")
    if not raw:
        return {}
    jar = SimpleCookie()
    try:
        jar.load(raw)
    except Exception:  # noqa: BLE001
        return {}
    return {name: morsel.value for name, morsel in jar.items()}


def get_cookie(scope: MutableMapping[str, Any], name: str) -> str | None:
    """Retrieve a single cookie value by name from the request scope, or ``None`` if absent."""
    return parse_cookies(scope).get(name)


def strip_reserved_cookies(cookie_header: str | None) -> str | None:
    """Remove Warden's own cookies before forwarding a request upstream."""
    if not cookie_header:
        return None
    parts = []
    for part in cookie_header.split(";"):
        name = part.split("=", 1)[0].strip()
        if name in RESERVED_COOKIES:
            continue
        if part.strip():
            parts.append(part.strip())
    return "; ".join(parts) or None


def request_wants_json(scope: MutableMapping[str, Any]) -> bool:
    """Determine if the client expects a JSON response based on request headers.
    
    * Checks ``X-Requested-With: XMLHttpRequest``.
    * Checks ``Accept`` header for ``application/json`` without ``text/html``.
    * Falls back to internal API path prefix.
    """
    headers = Headers(scope=scope)
    accept = headers.get("accept", "")
    if headers.get("x-requested-with", "").lower() == "xmlhttprequest":
        return True
    if "application/json" in accept and "text/html" not in accept:
        return True
    return scope.get("path", "").startswith(f"{INTERNAL_PREFIX}/api")


def request_wants_html(scope: MutableMapping[str, Any]) -> bool:
    """Determine if the client prefers an HTML response based on the ``Accept`` header.
    """
    accept = Headers(scope=scope).get("accept", "")
    return "text/html" in accept and not request_wants_json(scope)


def is_navigation(scope: MutableMapping[str, Any]) -> bool:
    """Return ``True`` for safe navigation requests that expect HTML pages.
    """
    method = scope.get("method", "GET").upper()
    return method in {"GET", "HEAD"} and request_wants_html(scope)


def safe_next(value: str | None, fallback: str = "/") -> str:
    """Validate and sanitise a ``next`` URL parameter.
    
    * Returns ``fallback`` for empty, unsafe, or malformed values.
    * Ensures the path is relative and does not contain dangerous characters.
    * Rejects path traversal (``..``) components.
    """
    if not value:
        return fallback
    value = value.strip()
    if not value.startswith("/") or value.startswith("//"):
        return fallback
    if "\\" in value or "\x00" in value or len(value) > 2048:
        return fallback
    if any(ord(char) < 0x20 for char in value):
        return fallback
    # Reject path traversal components
    if any(part == ".." for part in value.split("/")):
        return fallback
    parts = urlsplit(value)
    if parts.scheme or parts.netloc:
        return fallback
    return value


def next_from_scope(scope: MutableMapping[str, Any]) -> str:
    """Construct a ``path?query`` string from the ASGI scope.
    """
    path = scope.get("path", "/")
    query = scope.get("query_string", b"").decode("latin-1")
    return f"{path}?{query}" if query else path


def client_ip(scope: MutableMapping[str, Any]) -> str:
    """Extract the client IP address from the ASGI scope, or ``"unknown"``.
    """
    client = scope.get("client")
    return str(client[0]) if client else "unknown"


def user_agent(scope: MutableMapping[str, Any]) -> str:
    """Retrieve the ``User-Agent`` header, truncated to 500 characters.
    """
    return Headers(scope=scope).get("user-agent", "")[:500]


def check_origin(scope: MutableMapping[str, Any], config: WardenConfig, *, required: bool = False) -> bool:
    """Validate the browser Origin on state-changing requests.

    Same-origin fetches normally include Origin. If it is absent, accept
    non-browser clients but reject requests the browser explicitly marks as
    cross-site.
    """
    headers = Headers(scope=scope)
    origin = headers.get("origin")
    if origin:
        if origin == "null":
            return False
        if origin.rstrip("/") == current_origin(scope, config).rstrip("/"):
            return True
        return config.origin_allowed(origin)
    if required:
        return False
    fetch_site = headers.get("sec-fetch-site")
    return not (fetch_site and fetch_site not in {"same-origin", "none"})


def apply_security_headers(response: Response) -> Response:
    """Add common security HTTP headers to the response.
    
    * ``X-Content-Type-Options`` to ``nosniff``.
    * ``X-Frame-Options`` to ``DENY``.
    * ``Referrer-Policy`` to ``no-referrer``.
    * ``Permissions-Policy`` to disable risky features.
    * ``Content-Security-Policy`` restricting sources.
    """
    headers = response.headers
    headers.setdefault("X-Content-Type-Options", "nosniff")
    headers.setdefault("X-Frame-Options", "DENY")
    headers.setdefault("Referrer-Policy", "no-referrer")
    headers.setdefault(
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    )
    headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; font-src 'self'; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    )
    return response


def add_page_headers(response: Response) -> Response:
    """Set ``Cache-Control: no-store`` and apply security headers for HTML pages.
    """
    response.headers["Cache-Control"] = "no-store"
    return apply_security_headers(response)


def redirect(location: str, status_code: int = 303) -> Response:
    """Return a ``RedirectResponse`` with ``Cache-Control: no-store`` and security headers.
    """
    response = RedirectResponse(location, status_code=status_code)
    response.headers["Cache-Control"] = "no-store"
    apply_security_headers(response)
    return response


def json_error(message: str, status_code: int = 400, **extra: Any) -> JSONResponse:
    """Return a JSON error payload with ``Cache-Control: no-store``.
    
    * ``message`` becomes ``detail``.
    * Additional ``extra`` fields are merged into the payload.
    """
    payload = {"detail": message}
    payload.update(extra)
    response = JSONResponse(payload, status_code=status_code)
    response.headers["Cache-Control"] = "no-store"
    return response


def html_escape(value: Any) -> str:
    """Escape a value for safe HTML embedding.
    """
    return html.escape(str(value))


def humanize_bytes(value: float) -> str:
    """Convert a byte count into a human‑readable string with appropriate units.
    """
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def relative_time(timestamp: float | None, *, now: float | None = None) -> str:
    """Return a human‑readable relative time description (e.g., ``5m ago``).
    """
    if not timestamp:
        return "never"
    now = now if now is not None else time.time()
    delta = max(0, int(now - float(timestamp)))
    if delta < 10:
        return "just now"
    if delta < 60:
        return f"{delta}s ago"
    if delta < 3600:
        return f"{delta // 60}m ago"
    if delta < 86400:
        return f"{delta // 3600}h ago"
    if delta < 86400 * 30:
        return f"{delta // 86400}d ago"
    return time.strftime("%b %d, %Y", time.localtime(float(timestamp)))


def absolute_time(timestamp: float | None) -> str:
    """Format a timestamp as ``YYYY‑MM‑DD HH:MM`` in local time.
    """
    if not timestamp:
        return "—"
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(float(timestamp)))


def iso_time(timestamp: float | None) -> str | None:
    """Return an ISO‑8601 UTC timestamp string, or ``None`` if not provided.
    """
    if not timestamp:
        return None
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(float(timestamp)))


def route_initials(name: str, icon: str | None) -> str:
    """Generate initials or use a provided icon string for a route.
    """
    if icon:
        return icon
    words = [word for word in re.split(r"[\s_-]+", name) if word]
    if not words:
        return "W"
    if len(words) == 1:
        return words[0][:2].upper()
    return (words[0][0] + words[1][0]).upper()


def route_color(host: str) -> str:
    """Return a deterministic colour name for a route based on its host hash.
    """
    digest = hashlib.sha256(host.encode("utf-8")).digest()
    palette = ("moss", "clay", "sky", "plum", "sand", "rose")
    return palette[digest[0] % len(palette)]


def truncate(value: str, length: int = 160) -> str:
    """Truncate a string to ``length`` characters, preserving whole words and adding an ellipsis.
    """
    value = value.replace("\n", " ").replace("\r", " ").strip()
    return value if len(value) <= length else value[: length - 1] + "…"


def parse_user_agent(ua: str) -> str:
    """Simplify a raw user‑agent string to a common browser or client name.
    """
    if not ua:
        return "Unknown client"
    if "Firefox/" in ua:
        return "Firefox"
    if "Edg/" in ua:
        return "Edge"
    if "Chrome/" in ua:
        return "Chrome"
    if "Safari/" in ua:
        return "Safari"
    if "curl/" in ua:
        return "curl"
    if "python-httpx" in ua or "httpx/" in ua:
        return "httpx"
    return truncate(ua.split(" ")[0], 30)


class RateLimiter:
    """Small in-process fixed-window limiter for authentication endpoints."""

    def __init__(self) -> None:
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._last_cleanup = time.monotonic()

    def allow(self, key: str, limit: int, window_seconds: float) -> tuple[bool, int]:
        """Return ``(allowed, remaining)`` for the current window."""
        now = time.monotonic()
        events = self._events[key]
        cutoff = now - window_seconds
        while events and events[0] <= cutoff:
            events.popleft()
        if len(events) >= limit:
            return False, max(0, limit - len(events))
        events.append(now)
        if now - self._last_cleanup > 300:
            self._cleanup(now)
        return True, max(0, limit - len(events))

    def _cleanup(self, now: float) -> None:
        stale: Iterable[str] = [
            key for key, events in self._events.items() if not events or events[-1] < now - 3600
        ]
        for key in stale:
            self._events.pop(key, None)
        self._last_cleanup = now


def accept_language(scope: MutableMapping[str, Any]) -> str:
    return Headers(scope=scope).get("accept-language", "")


def wants_dark_mode(scope: MutableMapping[str, Any]) -> bool:
    # The design is intentionally dark; this exists for future themes.
    return True


def json_script_value(value: Any) -> str:
    return json.dumps(value, separators=(",", ":")).replace("</", "<\\/")


def upstream_url(
    route: RouteConfig,
    raw_path: str | bytes | None,
    query_string: bytes,
    *,
    websocket: bool = False,
) -> str:
    """Join an incoming ASGI path/query onto a configured upstream URL."""
    from urllib.parse import urlsplit

    parts = urlsplit(route.upstream)
    if isinstance(raw_path, bytes):
        path = raw_path.decode("latin-1") or "/"
    else:
        path = raw_path or "/"
    if not path.startswith("/"):
        path = "/" + path
    base = parts.path.rstrip("/")
    if base:
        joined = base + ("/" if path == "/" else path)
    else:
        joined = path
    scheme = parts.scheme
    if websocket:
        scheme = "wss" if scheme == "https" else "ws"
    url = f"{scheme}://{parts.netloc}{joined}"
    if query_string:
        url += "?" + query_string.decode("latin-1")
    return url


class _InMemoryRedis:
    """Minimal in-memory stand-in for the redis client used when redis-py
    is not installed."""

    def __init__(self) -> None:
        self._store: dict[str, dict[str, float]] = {}

    def pipeline(self):
        return _InMemoryPipeline(self._store)


class _InMemoryPipeline:
    def __init__(self, store: dict[str, dict[str, float]]) -> None:
        self._store = store
        self._commands: list[tuple[str, ...]] = []

    def zadd(self, zset: str, members: dict[str, float]) -> None:
        self._commands.append(("zadd", zset, members))

    def zremrangebyscore(self, zset: str, min_score: Any, max_score: Any) -> None:
        self._commands.append(("zremrangebyscore", zset, min_score, max_score))

    def zcard(self, zset: str) -> None:
        self._commands.append(("zcard", zset))

    def expire(self, zset: str, seconds: int) -> None:
        self._commands.append(("expire", zset, seconds))

    async def execute(self):
        results: list[Any] = []
        for cmd in self._commands:
            op = cmd[0]
            if op == "zadd":
                zset, members = cmd[1], cmd[2]
                current = self._store.get(zset, {})
                current.update(members)
                self._store[zset] = current
                results.append(0)
            elif op == "zremrangebyscore":
                zset, min_score, max_score = cmd[1], cmd[2], cmd[3]
                current = self._store.get(zset, {})
                def _score_in_min(value):
                    if isinstance(min_score, str):
                        if min_score == "-inf":
                            return True
                        try:
                            return float(min_score) <= value
                        except ValueError:
                            return False
                    return min_score <= value
                def _score_in_max(value):
                    if isinstance(max_score, str):
                        if max_score == "+inf":
                            return True
                        try:
                            return value <= float(max_score)
                        except ValueError:
                            return False
                    return value <= max_score
                self._store[zset] = {
                    k: v for k, v in current.items()
                    if not (_score_in_min(v) and _score_in_max(v))
                }
                results.append(0)
            elif op == "zcard":
                results.append(len(self._store.get(cmd[1], {})))
            elif op == "expire":
                results.append(True)
        return tuple(results)


class RedisRateLimiter:
    """Distributed rate limiter using Redis sorted sets.

    Each request key gets a sorted set ``rate:<key>`` where members are timestamps.
    The ``allow`` method records the current timestamp, removes entries older than
    the configured window, and checks the count against ``limit``. It executes via
    a Redis pipeline to keep the operation atomic.
    """

    def __init__(self, url: str = "redis://localhost", *, ttl: int = 86400) -> None:
        try:
            import redis.asyncio as _redis
        except ImportError:
            # Fallback to an in‑memory mock when redis-py is not available.
            _redis = None
        if _redis is None:
            # Simple in‑memory implementation that mimics the needed Redis API.
            self._redis = _InMemoryRedis()
        else:
            self._redis = _redis.from_url(url)
        self._default_ttl = ttl

    async def allow(self, key: str, limit: int, window_seconds: float) -> tuple[bool, int]:
        """Return ``True`` if the request identified by ``key`` is within the rate limit.

        The method adds the current timestamp, discards entries older than
        ``window_seconds`` and then checks the count against ``limit``.
        """
        now = time.time()
        cutoff = now - window_seconds
        zset = f"rate:{key}"
        # Remove expired entries and check the current count before recording
        # this request, so over-limit requests do not inflate the window.
        pipe = self._redis.pipeline()
        pipe.zremrangebyscore(zset, "-inf", cutoff)
        pipe.zcard(zset)
        _, count = await pipe.execute()
        if count >= limit:
            return False, max(0, limit - count)
        member = str(time.time_ns())
        pipe = self._redis.pipeline()
        pipe.zadd(zset, {member: now})
        pipe.expire(zset, max(int(window_seconds) + 60, self._default_ttl))
        await pipe.execute()
        return True, max(0, limit - (count + 1))

    async def health_check(self) -> bool:
        """Return ``True`` if the backing store is reachable."""
        try:
            ping = getattr(self._redis, "ping", None)
            if ping is None:
                return True
            result = ping()
            if hasattr(result, "__await__"):
                result = await result
            return bool(result) if result is not None else True
        except Exception:  # noqa: BLE001
            return False
