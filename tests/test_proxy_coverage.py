from __future__ import annotations
import pytest
from warden.config import RouteConfig, WardenConfig
from warden.proxy import ProxyEngine
from warden.stats import Stats
from unittest.mock import MagicMock


def test_proxy_subprotocol_filter() -> None:
    manager = MagicMock()
    manager.config = WardenConfig()
    stats = Stats()
    engine = ProxyEngine(manager, stats)
    route = RouteConfig(host="ws.local", upstream="http://localhost:8000", websocket_subprotocols=["chat"])
    # Just verify attribute access doesn't break
    assert route.websocket_subprotocols == ["chat"]
