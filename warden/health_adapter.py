"""Health adapter: periodic upstream health checks backed by MetricsModule."""

from __future__ import annotations

import asyncio
import logging
import time

import httpx

from warden.config import ConfigManager, RouteConfig, WardenConfig
logger = logging.getLogger("warden.health")

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from warden.stats import MetricsModule
from warden.utils import upstream_url

logger = logging.getLogger("warden.health")


class HealthMonitor:
    """Periodic upstream health monitor (adapter over MetricsModule)."""

    def __init__(self, stats: MetricsModule, manager: ConfigManager) -> None:
        self.stats = stats
        self.manager = manager
        self._task: asyncio.Task[None] | None = None
        self._clients: dict[bool, httpx.AsyncClient] = {}
        self._stop = asyncio.Event()

    def _client(self, verify: bool) -> httpx.AsyncClient:
        client = self._clients.get(verify)
        if client is None:
            client = httpx.AsyncClient(
                verify=verify,
                follow_redirects=False,
                trust_env=False,
                timeout=httpx.Timeout(6.0, connect=3.0),
                headers={"User-Agent": "warden-health/1"},
            )
            self._clients[verify] = client
        return client

    async def start(self) -> None:
        if self._task is None:
            self._stop.clear()
            self._task = asyncio.create_task(self._loop(), name="warden-health")

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        for client in self._clients.values():
            await client.aclose()
        self._clients.clear()

    async def _loop(self) -> None:
        await asyncio.sleep(0.7)
        while not self._stop.is_set():
            config = self.manager.config
            try:
                await self.check_all(config)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Health check cycle failed")
            interval = max(10, min(300, config.server.health_interval_seconds))
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=interval)
            except asyncio.TimeoutError:
                continue

    async def check_all(self, config: WardenConfig) -> None:
        routes = config.enabled_routes()
        if not routes:
            return
        await asyncio.gather(*(self.check_route(route) for route in routes))

    async def check_route(self, route: RouteConfig) -> None:
        url = upstream_url(route, route.health_path, b"")
        started = time.perf_counter()
        try:
            client = self._client(route.verify_tls)
            method = "HEAD"
            response = await client.request(method, url, timeout=min(route.timeout_seconds or 6, 6))
            if response.status_code in {405, 501}:
                await response.aclose()
                method = "GET"
                response = await client.request(
                    method, url, timeout=min(route.timeout_seconds or 6, 6)
                )
            elapsed = (time.perf_counter() - started) * 1000
            status_code = response.status_code
            await response.aclose()
            self.stats.record_health(
                route.host,
                online=status_code < 500,
                status_code=status_code,
                latency_ms=elapsed,
                error=None if status_code < 500 else f"HTTP {status_code}",
            )
        except Exception as exc:
            elapsed = (time.perf_counter() - started) * 1000
            self.stats.record_health(
                route.host,
                online=False,
                status_code=None,
                latency_ms=elapsed,
                error=exc.__class__.__name__,
            )
