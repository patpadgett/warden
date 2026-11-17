from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from warden.config import ConfigManager, RouteConfig, WardenConfig
from warden.proxy import ProxyEngine
from warden.stats import MetricsModule


def test_proxy_engine_init() -> None:
    manager = MagicMock(spec=ConfigManager)
    manager.config = WardenConfig()
    stats = MetricsModule()
    engine = ProxyEngine(manager, stats)
    assert engine is not None
    assert engine.manager is manager
    assert engine.stats is stats


def test_proxy_engine_close_resets_clients() -> None:
    manager = MagicMock(spec=ConfigManager)
    manager.config = WardenConfig()
    engine = ProxyEngine(manager, MetricsModule())
    # Access _clients to trigger lazy creation
    _ = engine._client(False)
    engine._clients[True] = AsyncMock()
    asyncio.run(engine.close())
    assert len(engine._clients) == 0


def test_proxy_engine_reset_clients() -> None:
    manager = MagicMock(spec=ConfigManager)
    manager.config = WardenConfig()
    engine = ProxyEngine(manager, MetricsModule())
    _ = engine._client(False)
    asyncio.run(engine.reset_clients())
    assert len(engine._clients) == 0


def test_per_route_rate_limit_is_per_client() -> None:
    manager = MagicMock(spec=ConfigManager)
    manager.config = WardenConfig()
    engine = ProxyEngine(manager, MetricsModule())
    route = RouteConfig(host="app.home.lan", upstream="http://127.0.0.1:9", rate_limit=3)

    allowed = [engine._per_route_rate_limit(route, "192.0.2.1", now=100.0) for _ in range(3)]
    assert allowed == [False, False, False]
    assert engine._per_route_rate_limit(route, "192.0.2.1", now=100.0) is True
    # A different client has its own window.
    assert engine._per_route_rate_limit(route, "192.0.2.2", now=100.0) is False


def test_per_route_rate_limit_prunes_stale_windows(monkeypatch) -> None:
    monkeypatch.setattr("warden.proxy._RATE_WINDOW_MAX_KEYS", 10)
    manager = MagicMock(spec=ConfigManager)
    manager.config = WardenConfig()
    engine = ProxyEngine(manager, MetricsModule())
    route = RouteConfig(host="app.home.lan", upstream="http://127.0.0.1:9", rate_limit=5)

    for index in range(40):
        engine._per_route_rate_limit(route, f"2001:db8::{index}", now=1000.0 + index * 0.01)
    assert len(engine._rate_windows) >= 10

    # Past the 60-second window the old keys are dropped instead of retained.
    engine._per_route_rate_limit(route, "198.51.100.9", now=1120.0)
    assert len(engine._rate_windows) == 1


def test_proxy_subprotocol_filter() -> None:
    route = RouteConfig(host="ws.local", upstream="http://localhost:8000", websocket_subprotocols=["chat", "graphql-ws"])
    assert route.websocket_subprotocols == ["chat", "graphql-ws"]


def test_proxy_connection_tokens() -> None:
    tokens = ProxyEngine._connection_tokens(["keep-alive, upgrade", "close"])
    assert tokens == {"keep-alive", "upgrade", "close"}


def test_proxy_build_request_headers_basic() -> None:
    manager = MagicMock(spec=ConfigManager)
    manager.config = WardenConfig()
    engine = ProxyEngine(manager, MetricsModule())
    route = RouteConfig(host="test.local", upstream="http://localhost:8000", preserve_host=False)
    scope = {
        "headers": [
            (b"host", b"test.local"),
            (b"user-agent", b"test-agent"),
            (b"x-forwarded-for", b"1.2.3.4"),
            (b"cookie", b"session=abc; warden_csrf=xyz"),
        ],
        "scheme": "http",
        "path": "/",
        "query_string": b"",
    }
    headers = engine._request_headers(scope, route, user=None)
    [k.lower() for k, _ in headers]
    # Warden strips client-supplied forwarding headers (including x-forwarded-for)
    assert any(k.lower() == "x-forwarded-for" for k, _ in headers)


def test_proxy_rewrite_location() -> None:
    manager = MagicMock(spec=ConfigManager)
    manager.config = WardenConfig()
    engine = ProxyEngine(manager, MetricsModule())
    route = RouteConfig(host="app.local", upstream="http://192.168.1.5:3000/api", rewrite_redirects=True)
    scope = {"scheme": "https", "headers": [(b"host", b"app.local")]}
    # Location pointing to upstream -> should rewrite to public
    rewritten = engine._rewrite_location("http://192.168.1.5:3000/api/foo", route, scope)
    assert rewritten == "https://app.local/api/foo"
    # Location not matching upstream -> unchanged
    assert engine._rewrite_location("https://other.com/", route, scope) == "https://other.com/"


def test_proxy_rewrite_set_cookie_drops_secure_on_http() -> None:
    manager = MagicMock(spec=ConfigManager)
    manager.config = WardenConfig()
    engine = ProxyEngine(manager, MetricsModule())
    route = RouteConfig(host="app.local", upstream="http://192.168.1.5:3000", rewrite_cookies=True)
    scope = {"scheme": "http", "headers": [(b"host", b"app.local")]}
    cookie = "session=abc; Secure; HttpOnly; Path=/"
    rewritten = engine._rewrite_set_cookie(cookie, scope, route)
    assert rewritten is not None
    assert "Secure" not in rewritten


def test_proxy_rewrite_set_cookie_drops_prefixed_session_cookie() -> None:
    manager = MagicMock(spec=ConfigManager)
    manager.config = WardenConfig()
    engine = ProxyEngine(manager, MetricsModule())
    route = RouteConfig(host="app.local", upstream="http://192.168.1.5:3000")
    scope = {"scheme": "https", "headers": [(b"host", b"app.local")]}
    assert engine._rewrite_set_cookie("__Host-warden_session=abc; Path=/", scope, route) is None
    assert engine._rewrite_set_cookie("__Host-warden_challenge=abc; Path=/", scope, route) is None


def test_proxy_access_denials_cover_ws_rules() -> None:
    route = RouteConfig(
        host="app.local",
        upstream="http://192.168.1.5:3000",
        allowed_ips=["10.0.0.0/8"],
        denied_ips=["10.9.9.9/32"],
        blocked_paths=["/admin/*", "/secret"],
        blocked_user_agents=["BadBot"],
    )
    assert ProxyEngine._ip_denial(route, "10.1.2.3") is None
    assert "explicitly blocked" in ProxyEngine._ip_denial(route, "10.9.9.9")
    assert "not authorized" in ProxyEngine._ip_denial(route, "192.0.2.1")
    # An unparseable client address is denied whenever an allow-list exists.
    assert ProxyEngine._ip_denial(route, "unknown") == "Invalid client IP address."
    assert ProxyEngine._user_agent_denial(route, "curl/8 badbot") is not None
    assert ProxyEngine._user_agent_denial(route, "Mozilla/5.0") is None
    assert ProxyEngine._path_denial(route, "/admin/users") is not None
    assert ProxyEngine._path_denial(route, "/secret") is not None
    assert ProxyEngine._path_denial(route, "/administrator") is None


def test_proxy_ip_denial_unwraps_ipv4_mapped_addresses() -> None:
    # A dual-stack listener reports IPv4 clients as ``::ffff:a.b.c.d``; an
    # allow-list must still accept them and a deny-list must still block them.
    route = RouteConfig(
        host="app.local",
        upstream="http://192.168.1.5:3000",
        allowed_ips=["10.0.0.0/8"],
    )
    assert ProxyEngine._ip_denial(route, "::ffff:10.1.2.3") is None
    blocked = RouteConfig(
        host="app.local",
        upstream="http://192.168.1.5:3000",
        denied_ips=["10.9.9.9/32"],
    )
    assert "explicitly blocked" in ProxyEngine._ip_denial(blocked, "::ffff:10.9.9.9")


def test_proxy_path_denial_normalizes_dot_segments() -> None:
    route = RouteConfig(
        host="app.local",
        upstream="http://192.168.1.5:3000",
        blocked_paths=["/secret", "/admin/*"],
    )
    for path in ("/secret/", "//secret", "/./secret", "/public/../secret"):
        assert ProxyEngine._path_denial(route, path) is not None, path
    assert ProxyEngine._path_denial(route, "/admin/./users") is not None
    assert ProxyEngine._path_denial(route, "/public/secret") is None
    assert ProxyEngine._path_denial(route, "/administrator") is None
    # ``/*`` still blocks everything, as it did before normalisation.
    everything = RouteConfig(
        host="app.local", upstream="http://192.168.1.5:3000", blocked_paths=["/*"]
    )
    assert ProxyEngine._path_denial(everything, "/") is not None
    assert ProxyEngine._path_denial(everything, "/anything") is not None


def test_proxy_rewrite_set_cookie_drops_unreachable_domain() -> None:
    manager = MagicMock(spec=ConfigManager)
    manager.config = WardenConfig()
    engine = ProxyEngine(manager, MetricsModule())
    route = RouteConfig(host="app.local", upstream="http://192.168.1.5:3000", rewrite_cookies=True)
    scope = {"scheme": "https", "headers": [(b"host", b"app.local")]}
    cookie = "session=abc; Domain=internal.service; Path=/"
    rewritten = engine._rewrite_set_cookie(cookie, scope, route)
    assert rewritten is not None
    assert "Domain" not in rewritten


def test_proxy_response_headers_strip_hop_by_hop() -> None:
    manager = MagicMock(spec=ConfigManager)
    manager.config = WardenConfig()
    engine = ProxyEngine(manager, MetricsModule())
    route = RouteConfig(host="app.local", upstream="http://192.168.1.5:3000")
    scope = {"scheme": "https", "headers": [(b"host", b"app.local")]}
    upstream_resp = MagicMock()
    upstream_resp.headers = MagicMock()
    upstream_resp.headers.get_list.side_effect = lambda k: ["keep-alive"] if k.lower() == "connection" else []
    upstream_resp.headers.multi_items.side_effect = lambda: [
        ("content-type", "text/html"),
        ("connection", "keep-alive"),
        ("location", "http://192.168.1.5:3000/redirect"),
        ("set-cookie", "session=xyz; Path=/"),
    ]
    headers = engine._response_headers(upstream_resp, route, scope)
    lower = [k.decode().lower() for k, _ in headers]
    assert "connection" not in lower
    # location should be rewritten
    loc = next((v.decode() for k, v in headers if k.decode().lower() == "location"), None)
    assert loc == "https://app.local/redirect"


def test_proxy_websocket_subprotocol_filter() -> None:
    route = RouteConfig(host="ws.local", upstream="http://localhost:8000", websocket_subprotocols=["chat", "graphql-ws"])
    offered = ["chat", "graphql-ws"]
    allowed = set(route.websocket_subprotocols)
    assert any(p in allowed for p in offered) is True
    # Offering unknown -> should reject
    offered2 = ["unknown"]
    assert any(p in allowed for p in offered2) is False


def test_proxy_error_response_json() -> None:
    manager = MagicMock(spec=ConfigManager)
    manager.config = WardenConfig()
    engine = ProxyEngine(manager, MetricsModule())
    scope = {"path": "/api/test", "headers": [(b"accept", b"application/json")]}
    resp = engine._error_response(scope, status=502, title="Bad", message="Upstream down")
    assert resp.status_code == 502
    import json
    body = json.loads(resp.body.decode())
    assert body["detail"] == "Upstream down"


def test_proxy_error_response_html() -> None:
    manager = MagicMock(spec=ConfigManager)
    manager.config = WardenConfig()
    engine = ProxyEngine(manager, MetricsModule())
    scope = {"path": "/", "headers": [(b"accept", b"text/html")]}
    resp = engine._error_response(scope, status=404, title="Not Found", message="Missing")
    assert resp.status_code == 404
    assert b"Not Found" in resp.body


def test_proxy_upstream_url() -> None:
    route = RouteConfig(host="app.local", upstream="http://192.168.1.5:3000/api")
    from warden.utils import upstream_url
    url = upstream_url(route, b"/test", b"foo=bar")
    assert url == "http://192.168.1.5:3000/api/test?foo=bar"


class TestProxyHandleHttp:
    """Public handle_http control flow (largest proxy.py coverage gap)."""

    @pytest.fixture
    def engine(self):
        manager = MagicMock(spec=ConfigManager)
        manager.config = WardenConfig()
        manager.config.server.max_body_size_mb = 10
        manager.config.server.request_timeout_seconds = 30
        engine = ProxyEngine(manager, MetricsModule())
        # Mock client and send so we can assert control-flow branch coverage
        engine._clients = {}
        engine._clients = {}
        engine._send = AsyncMock()
        engine._client = AsyncMock()
        return engine

    def _client(self, upstream):
        client = MagicMock()
        client.send = AsyncMock(return_value=upstream)
        return client

    def _scope(
        self,
        method="GET",
        path="/",
        client=("127.0.0.1", 12345),
        headers=None,
        query_string=b"",
    ):
        return {
            "type": "http",
            "method": method,
            "path": path,
            "raw_path": (method + " " + path).encode(),
            "query_string": query_string,
            "scheme": "http",
            "client": client,
            "headers": headers or [(b"host", b"test.local")],
        }

    def _route(self, **kwargs):
        defaults = {
            "host": "app.local",
            "upstream": "http://192.168.1.5:3000/api",
            "verify_tls": True,
            "denied_ips": [],
            "allowed_ips": [],
            "preserve_host": False,
            "rewrite_redirects": False,
            "rewrite_cookies": False,
            "auth": False,
            "enabled": True,
        }
        defaults.update(kwargs)
        return RouteConfig(**defaults)

    def _upstream(self, status=200, body=b"", aiter_raw=None):
        upstream = MagicMock()
        upstream.status_code = status
        upstream.headers = MagicMock()
        upstream.headers.get_list.side_effect = lambda k: (
            ["keep-alive"] if k.lower() == "connection" else []
        )
        upstream.headers.multi_items.return_value = []
        if aiter_raw is None:
            aiter_raw = [body]
        upstream.aiter_raw = AsyncMock()
        if aiter_raw:

            def _aiter():
                yield from aiter_raw

            upstream.aiter_raw.return_value = _aiter()
        upstream.aclose = AsyncMock()
        upstream.reason = None
        upstream.request = MagicMock()
        return upstream

    def _make_request(self, body=b"", method="GET"):
        async def _body():
            return body
        req = MagicMock()
        req.body = _body
        req.method = method
        return req

    async def _call(self, engine, scope, receive, send, route, body=b"", method="GET"):
        with patch(
            "warden.proxy.Request",
            return_value=self._make_request(body=body, method=method),
        ):
            return await engine.handle_http(scope, receive, send, route, None)

    async def test_handle_http_acme_challenge(self, engine):
        # ACME challenge returns early with the challenge token.
        route = self._route()
        scope = self._scope(path="/.well-known/acme-challenge/abc123")
        engine.acme_tokens = {"abc123": "token-response"}
        receive = AsyncMock()
        send = MagicMock()
        with patch("warden.proxy.Request", return_value=self._make_request()):
            await self._call(engine, scope, receive, send, route)
        engine._client.assert_not_called()
        engine._send.assert_awaited_once()
        assert engine._send.call_args[0][0].status_code == 200
        assert engine._send.call_args[0][0].body == b"token-response"

    async def test_handle_http_ip_denied(self, engine):
        # Client IP is in route.denied_ips -> 403.
        route = self._route(denied_ips=["192.168.1.100/32"])
        scope = self._scope(client=("192.168.1.100", 12345))
        upstream = self._upstream(status=403)
        engine._client = MagicMock(return_value=self._client(upstream))
        with patch("warden.proxy.Request", return_value=self._make_request()):
            await self._call(engine, scope, AsyncMock(), MagicMock(), route)
        engine._client.assert_not_called()
        engine._send.assert_awaited_once()
        assert engine._send.call_args[0][0].status_code == 403

    async def test_handle_http_ip_not_allowed(self, engine):
        # Client IP is not in route.allowed_ips -> 403.
        route = self._route(allowed_ips=["10.0.0.0/8"])
        scope = self._scope(client=("192.168.1.100", 12345))
        upstream = self._upstream(status=403)
        engine._client = MagicMock(return_value=self._client(upstream))
        with patch("warden.proxy.Request", return_value=self._make_request()):
            await self._call(engine, scope, AsyncMock(), MagicMock(), route)
        engine._client.assert_not_called()
        engine._send.assert_awaited_once()
        assert engine._send.call_args[0][0].status_code == 403

    async def test_handle_http_ip_invalid_no_allowed(self, engine):
        # Client IP is unparseable; with allowed_ips set, a 403 is returned.
        route = self._route(allowed_ips=["10.0.0.0/8"])
        scope = self._scope(client=("not-an-ip", 12345))
        upstream = self._upstream(status=403)
        engine._client = MagicMock(return_value=self._client(upstream))
        with patch("warden.proxy.Request", return_value=self._make_request()):
            await self._call(engine, scope, AsyncMock(), MagicMock(), route)
        engine._client.assert_not_called()
        engine._send.assert_awaited_once()
        assert engine._send.call_args[0][0].status_code == 403

    async def test_handle_http_blocked_path_cannot_be_dodged(self, engine):
        # ``/public/../secret`` reaches the upstream as ``/secret`` but must
        # still be refused before the request is forwarded.
        route = self._route(blocked_paths=["/secret"])
        scope = self._scope(path="/public/../secret")
        upstream = self._upstream(status=200)
        engine._client = MagicMock(return_value=self._client(upstream))
        with patch("warden.proxy.Request", return_value=self._make_request()):
            await self._call(engine, scope, AsyncMock(), MagicMock(), route)
        engine._client.assert_not_called()
        engine._send.assert_awaited_once()
        assert engine._send.call_args[0][0].status_code == 403

    async def test_handle_http_max_body_too_large(self, engine):
        # Request body exceeds max_body_size_mb -> 413.
        route = self._route()
        scope = self._scope()
        upstream = self._upstream(status=413)
        engine._client = MagicMock(return_value=self._client(upstream))
        with patch("warden.proxy.Request", return_value=self._make_request()):
            await self._call(engine, scope, AsyncMock(), MagicMock(), route, body=b"x" * 10485761)
        engine._client.assert_called_once()
        engine._send.assert_awaited_once()
        assert engine._send.call_args[0][0].status_code == 413

    async def test_handle_http_head_no_body(self, engine):
        # HEAD request returns the response without streaming a body.
        route = self._route()
        scope = self._scope(method="HEAD")
        upstream = self._upstream(status=200)
        engine._client = MagicMock(return_value=self._client(upstream))
        with patch("warden.proxy.Request", return_value=self._make_request(method="HEAD")):
            await self._call(engine, scope, AsyncMock(), MagicMock(), route)
        engine._client.assert_called_once()
        engine._send.assert_awaited_once()
        assert engine._send.call_args[0][0].status_code == 200

    async def test_handle_http_status_204_no_body(self, engine):
        # 204 / 304 responses are streamed without a body.
        route = self._route()
        scope = self._scope()
        upstream = self._upstream(status=204)
        engine._client = MagicMock(return_value=self._client(upstream))
        with patch("warden.proxy.Request", return_value=self._make_request()):
            await self._call(engine, scope, AsyncMock(), MagicMock(), route)
        engine._client.assert_called_once()
        engine._send.assert_awaited_once()
        assert engine._send.call_args[0][0].status_code == 204

    async def test_handle_http_timeout(self, engine):
        # Upstream timeout -> 504.
        route = self._route()
        scope = self._scope()
        upstream = self._upstream(status=504)
        client = self._client(upstream)
        client.send = AsyncMock(side_effect=httpx.TimeoutException("timed out"))
        engine._client = MagicMock(return_value=client)
        with patch("warden.proxy.Request", return_value=self._make_request()):
            await self._call(engine, scope, AsyncMock(), MagicMock(), route)
        engine._client.assert_called_once()
        engine._send.assert_awaited_once()
        assert engine._send.call_args[0][0].status_code == 504

    async def test_handle_http_upstream_error(self, engine):
        # Upstream HTTP error -> 502.
        route = self._route()
        scope = self._scope()
        upstream = self._upstream(status=502)
        client = self._client(upstream)
        client.send = AsyncMock(side_effect=httpx.HTTPError("boom"))
        engine._client = MagicMock(return_value=client)
        with patch("warden.proxy.Request", return_value=self._make_request()):
            await self._call(engine, scope, AsyncMock(), MagicMock(), route)
        engine._client.assert_called_once()
        engine._send.assert_awaited_once()
        assert engine._send.call_args[0][0].status_code == 502

    async def test_handle_http_success_streaming(self, engine):
        # Normal upstream response is streamed through and recorded.
        route = self._route()
        scope = self._scope()
        upstream = self._upstream(status=200, body=b"hello", aiter_raw=[b"hel", b"lo"])
        engine._client = MagicMock(return_value=self._client(upstream))
        with patch("warden.proxy.Request", return_value=self._make_request()):
            await self._call(engine, scope, AsyncMock(), MagicMock(), route)
        engine._client.assert_called_once()
        engine._send.assert_awaited_once()
        assert engine._send.call_args[0][0].status_code == 200

    async def test_handle_http_error_response_body(self, engine):
        # Upstream error response body contains the expected message.
        route = self._route()
        scope = self._scope()
        upstream = self._upstream(status=502)
        client = self._client(upstream)
        client.send = AsyncMock(side_effect=httpx.HTTPError("boom"))
        engine._client = MagicMock(return_value=client)
        with patch("warden.proxy.Request", return_value=self._make_request()):
            await self._call(engine, scope, AsyncMock(), MagicMock(), route)
        sent = engine._send.call_args[0][0]
        assert sent.status_code == 502
        assert b"out of reach" in sent.body
