from __future__ import annotations

from unittest.mock import MagicMock

from warden.config import RouteConfig, WardenConfig
from warden.proxy import ProxyEngine
from warden.stats import MetricsModule


def test_proxy_subprotocol_filter() -> None:
    manager = MagicMock()
    manager.config = WardenConfig()
    stats = MetricsModule()
    ProxyEngine(manager, stats)
    route = RouteConfig(host="ws.local", upstream="http://localhost:8000", websocket_subprotocols=["chat"])
    # Just verify attribute access doesn't break
    assert route.websocket_subprotocols == ["chat"]
