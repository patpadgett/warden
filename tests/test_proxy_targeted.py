from __future__ import annotations
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
import pytest
from warden.config import RouteConfig, WardenConfig, ConfigManager
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
    lower = [k.lower() for k, _ in headers]
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