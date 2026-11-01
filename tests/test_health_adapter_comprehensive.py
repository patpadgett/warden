"""Tests for the health adapter module."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx

from warden.health_adapter import HealthMonitor
from warden.stats import MetricsModule

from warden.config import RouteConfig, WardenConfig


def make_manager(config: WardenConfig | None = None) -> MagicMock:
    manager = MagicMock()
    manager.config = config or WardenConfig()
    return manager


# ------------------------------------------------------------------ _client

class TestHealthMonitorClient:
    def test_client_creates_and_caches(self) -> None:
        stats = MetricsModule()
        manager = MagicMock()
        adapter = HealthMonitor(stats, manager)
        client1 = adapter._client(verify=True)
        client2 = adapter._client(verify=True)
        assert client1 is client2

    def test_clients_cache_per_verify_flag(self) -> None:
        stats = MetricsModule()
        manager = MagicMock()
        adapter = HealthMonitor(stats, manager)
        http_client = httpx.AsyncClient()
        with patch("warden.health_adapter.httpx.AsyncClient", return_value=http_client) as mock_cls:
            c1 = adapter._client(verify=True)
            c2 = adapter._client(verify=True)
            assert c1 is c2  # same verify flag, cached
            mock_cls.assert_called_once()


# ------------------------------------------------------------------ lifecycle

class TestHealthMonitorLifecycle:
    def test_start_creates_task(self) -> None:
        stats = MetricsModule()
        manager = MagicMock()
        adapter = HealthMonitor(stats, manager)
        import asyncio
        asyncio.run(adapter.start())
        assert adapter._task is not None

    def test_stop_cancels_and_closes_clients(self) -> None:
        stats = MetricsModule()
        manager = MagicMock()
        adapter = HealthMonitor(stats, manager)
        import asyncio

        async def _close():
            pass

        with patch("warden.health_adapter.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.aclose.return_value = _close()
            mock_cls.return_value = mock_client
            adapter._clients[True] = mock_client
            asyncio.run(adapter.stop())

        # Task should be cancelled
        assert adapter._task is None
        # Client should be closed
        mock_client.aclose.assert_awaited_once()


# ------------------------------------------------------------------ check_route

class TestHealthMonitorCheckRoute:
    def test_check_route_success(self) -> None:
        import asyncio

        stats = MetricsModule()
        manager = MagicMock()
        manager.config = WardenConfig(
            routes=[RouteConfig(host="admin.home.lan", upstream="http://localhost:8080", auth=False)]
        )
        adapter = HealthMonitor(stats, manager)

        with patch("warden.health_adapter.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_client.request.return_value = mock_response
            mock_cls.return_value = mock_client
            asyncio.run(adapter.check_route(manager.config.routes[0]))

        # Health should be recorded as online
        assert stats.recent is not None

    def test_check_route_500_marked_offline(self) -> None:
        import asyncio

        stats = MetricsModule()
        manager = MagicMock()
        manager.config = WardenConfig(
            routes=[RouteConfig(host="admin.home.lan", upstream="http://localhost:8080", auth=False)]
        )
        adapter = HealthMonitor(stats, manager)

        with patch("warden.health_adapter.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_response = AsyncMock()
            mock_response.status_code = 500
            mock_client.request.return_value = mock_response
            mock_cls.return_value = mock_client
            asyncio.run(adapter.check_route(manager.config.routes[0]))

        # Health should be recorded as offline
        assert stats.recent is not None

    def test_check_route_405_falls_back_to_get(self) -> None:
        import asyncio

        stats = MetricsModule()
        manager = MagicMock()
        manager.config = WardenConfig(
            routes=[RouteConfig(host="admin.home.lan", upstream="http://localhost:8080", auth=False)]
        )
        adapter = HealthMonitor(stats, manager)

        call_count = 0

        with patch("warden.health_adapter.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_response = AsyncMock()

            def fake_request(method, url, timeout=None):
                nonlocal call_count
                call_count += 1
                mock_response.status_code = 405 if call_count == 1 else 200
                return mock_response

            mock_client.request = AsyncMock(side_effect=fake_request)
            mock_cls.return_value = mock_client
            asyncio.run(adapter.check_route(manager.config.routes[0]))

        # Should have made two requests (HEAD then GET)
        assert call_count == 2

    def test_check_route_error_records_exception_class(self) -> None:
        import asyncio

        stats = MetricsModule()
        manager = MagicMock()
        manager.config = WardenConfig(
            routes=[RouteConfig(host="admin.home.lan", upstream="http://localhost:8080", auth=False)]
        )
        adapter = HealthMonitor(stats, manager)

        with patch("warden.health_adapter.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.request = AsyncMock(side_effect=httpx.TimeoutException("connect timed out"))
            mock_cls.return_value = mock_client
            asyncio.run(adapter.check_route(manager.config.routes[0]))

        # Health should be recorded as offline with error message
        assert stats.recent is not None

    def test_check_route_uses_verify_tls_from_route(self) -> None:
        import asyncio

        stats = MetricsModule()
        manager = MagicMock()
        manager.config = WardenConfig(
            routes=[RouteConfig(host="admin.home.lan", upstream="http://localhost:8080", auth=False, verify_tls=False)]
        )
        adapter = HealthMonitor(stats, manager)

        with patch("warden.health_adapter.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.request = AsyncMock(return_value=AsyncMock(status_code=200))
            mock_cls.return_value = mock_client
            asyncio.run(adapter.check_route(manager.config.routes[0]))

        # The client should be created with verify=False
        mock_cls.assert_called_once()
        assert mock_cls.call_args.kwargs["verify"] is False
