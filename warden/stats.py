"""In-memory traffic metrics and upstream health checks."""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

import httpx

from warden.config import ConfigManager, RouteConfig, WardenConfig
from warden.utils import truncate, upstream_url

logger = logging.getLogger("warden.health")


@dataclass(slots=True)
class RouteMetrics:
    requests: int = 0
    errors: int = 0
    last_status: int | None = None
    last_seen: float | None = None
    total_latency_ms: float = 0.0
    last_latency_ms: float | None = None
    authenticated: int = 0

    @property
    def average_latency_ms(self) -> float | None:
        if not self.requests:
            return None
        return self.total_latency_ms / self.requests


@dataclass(slots=True)
class Health:
    online: bool | None = None
    status_code: int | None = None
    latency_ms: float | None = None
    checked_at: float | None = None
    error: str | None = None


@dataclass(slots=True)
class TrafficEvent:
    timestamp: float
    host: str
    method: str
    path: str
    status: int
    latency_ms: float
    user: str | None = None
    public: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "host": self.host,
            "method": self.method,
            "path": self.path,
            "status": self.status,
            "latency_ms": round(self.latency_ms, 1),
            "user": self.user,
            "public": self.public,
        }


# Metric name constants for easy reference
OTP_SUCCESS_METRIC = "warden_otp_success_total"
OTP_FAILURE_METRIC = "warden_otp_failure_total"
BACKUP_CODE_USED_METRIC = "warden_backup_code_used_total"

class Stats:
    def __init__(self) -> None:
        self.started_at = time.time()
        self.metrics: dict[str, RouteMetrics] = {}
        self.health: dict[str, Health] = {}
        self.recent: deque[TrafficEvent] = deque(maxlen=60)
        # New RBAC and auth metrics
        self.auth_success = 0
        self.auth_failure = 0
        self.otp_success = 0
        self.otp_failure = 0
        self.role_created = 0
        self.role_deleted = 0
        self.role_assigned = 0
        self.role_removed = 0
        self.backup_code_used = 0
        self.rate_limit_allowed = 0
        self.rate_limit_blocked = 0


    def record_request(
        self,
        route: RouteConfig,
        *,
        method: str,
        path: str,
        status: int,
        latency_ms: float,
        user: str | None,
    ) -> None:
        metrics = self.metrics.setdefault(route.host, RouteMetrics())
        metrics.requests += 1
        metrics.last_status = status
        metrics.last_seen = time.time()
        metrics.total_latency_ms += latency_ms
        metrics.last_latency_ms = latency_ms
        if status >= 500 or status == 0:
            metrics.errors += 1
        if user:
            metrics.authenticated += 1
        self.recent.appendleft(
            TrafficEvent(
                timestamp=time.time(),
                host=route.host,
                method=method,
                path=truncate(path, 90),
                status=status,
                latency_ms=latency_ms,
                user=user,
                public=not route.auth,
            )
        )

    def record_health(self, host: str, *, online: bool, status_code: int | None, latency_ms: float | None, error: str | None) -> None:
        """Record health check result for a route.
        
        * Updates the ``Health`` entry for ``host`` with the latest status.
        """
        health = self.health.setdefault(host, Health())
        health.online = online
        health.status_code = status_code
        health.latency_ms = latency_ms
        health.checked_at = time.time()
        health.error = error

    def inc_auth_success(self) -> None:
        self.auth_success += 1

    def inc_auth_failure(self) -> None:
        self.auth_failure += 1

    def inc_otp_success(self) -> None:
        self.otp_success += 1

    def inc_otp_failure(self) -> None:
        self.otp_failure += 1

    def inc_role_created(self) -> None:
        self.role_created += 1

    def inc_role_deleted(self) -> None:
        self.role_deleted += 1

    def inc_role_assigned(self) -> None:
        self.role_assigned += 1

    def inc_role_removed(self) -> None:
        self.role_removed += 1

    def inc_backup_code_used(self) -> None:
        self.backup_code_used += 1

    def inc_rate_limit_blocked(self) -> None:
        self.rate_limit_blocked += 1

    def inc_rate_limit_allowed(self) -> None:
        self.rate_limit_allowed += 1


    def route_snapshot(self, config: WardenConfig) -> dict[str, dict[str, Any]]:
        snapshots: dict[str, dict[str, Any]] = {}
        for route in config.routes:
            metrics = self.metrics.get(route.host, RouteMetrics())
            health = self.health.get(route.host, Health())
            if not route.enabled:
                state = "disabled"
            elif health.online is None:
                state = "checking"
            elif health.online:
                state = "online"
            else:
                state = "offline"
            snapshots[route.host] = {
                "requests": metrics.requests,
                "errors": metrics.errors,
                "last_status": metrics.last_status,
                "last_seen": metrics.last_seen,
                "latency_ms": round(metrics.last_latency_ms, 1)
                if metrics.last_latency_ms is not None
                else None,
                "average_latency_ms": round(metrics.average_latency_ms, 1)
                if metrics.average_latency_ms is not None
                else None,
                "authenticated": metrics.authenticated,
                "online": health.online,
                "health_status": health.status_code,
                "health_latency_ms": round(health.latency_ms, 1)
                if health.latency_ms is not None
                else None,
                "health_checked_at": health.checked_at,
                "health_error": health.error,
                "state": state,
            }
        return snapshots

    def prometheus_metrics(self) -> str:
        """Export metrics in Prometheus text format."""
        lines = []
        now = time.time()
        
        # System metrics
        lines.append("# HELP warden_uptime_seconds Total uptime of the Warden process")
        lines.append("# TYPE warden_uptime_seconds gauge")
        lines.append(f"warden_uptime_seconds {int(now - self.started_at)}")
        
        # Route metrics
        for host, m in self.metrics.items():
            lines.append(f'# HELP warden_route_requests_total Total requests for {host}')
            lines.append('# TYPE warden_route_requests_total counter')
            lines.append(f'warden_route_requests_total{{host="{host}"}} {m.requests}')
            lines.append(f'# HELP warden_route_errors_total Total errors for {host}')
            lines.append('# TYPE warden_route_errors_total counter')
            lines.append(f'warden_route_errors_total{{host="{host}"}} {m.errors}')
            if m.last_latency_ms is not None:
                lines.append(f'# HELP warden_route_latency_ms Last request latency for {host}')
                lines.append('# TYPE warden_route_latency_ms gauge')
                lines.append(f'warden_route_latency_ms{{host="{host}"}} {m.last_latency_ms}')
            lines.append(f'# HELP warden_route_authenticated_requests_total Total authenticated requests for {host}')
            lines.append('# TYPE warden_route_authenticated_requests_total counter')
            lines.append(f'warden_route_authenticated_requests_total{{host="{host}"}} {m.authenticated}')
        # Role & auth metrics
        lines.append('# HELP warden_auth_success_total Total successful authentication attempts')
        lines.append('# TYPE warden_auth_success_total counter')
        lines.append(f'warden_auth_success_total {self.auth_success}')
        lines.append('# HELP warden_auth_failure_total Total failed authentication attempts')
        lines.append('# TYPE warden_auth_failure_total counter')
        lines.append(f'warden_auth_failure_total {self.auth_failure}')
        lines.append(f'# HELP {OTP_SUCCESS_METRIC} Total successful OTP verifications')
        lines.append(f'# TYPE {OTP_SUCCESS_METRIC} counter')
        lines.append(f'{OTP_SUCCESS_METRIC} {self.otp_success}')
        lines.append(f'# HELP {OTP_FAILURE_METRIC} Total failed OTP verifications')
        lines.append(f'# TYPE {OTP_FAILURE_METRIC} counter')
        lines.append(f'{OTP_FAILURE_METRIC} {self.otp_failure}')
        lines.append('# HELP warden_role_created_total Total roles created')
        lines.append('# TYPE warden_role_created_total counter')
        lines.append(f'warden_role_created_total {self.role_created}')
        lines.append('# HELP warden_role_deleted_total Total roles deleted')
        lines.append('# TYPE warden_role_deleted_total counter')
        lines.append(f'warden_role_deleted_total {self.role_deleted}')
        lines.append('# HELP warden_role_assigned_total Total role assignments')
        lines.append('# TYPE warden_role_assigned_total counter')
        lines.append(f'warden_role_assigned_total {self.role_assigned}')
        lines.append('# HELP warden_role_removed_total Total role removals')
        lines.append('# TYPE warden_role_removed_total counter')
        lines.append(f'warden_role_removed_total {self.role_removed}')
        lines.append(f'# HELP {BACKUP_CODE_USED_METRIC} Total backup code usage')
        lines.append(f'# TYPE {BACKUP_CODE_USED_METRIC} counter')
        lines.append(f'{BACKUP_CODE_USED_METRIC} {self.backup_code_used}')
        lines.append('# HELP warden_rate_limit_allowed_total Total allowed requests by rate limiter')
        lines.append('# TYPE warden_rate_limit_allowed_total counter')
        lines.append(f'warden_rate_limit_allowed_total {self.rate_limit_allowed}')
        lines.append('# HELP warden_rate_limit_blocked_total Total blocked requests by rate limiter')
        lines.append('# TYPE warden_rate_limit_blocked_total counter')
        lines.append(f'warden_rate_limit_blocked_total {self.rate_limit_blocked}')


        return "\n".join(lines) + "\n"

    def snapshot(self, config: WardenConfig) -> dict[str, Any]:
        services = self.route_snapshot(config)
        enabled = [service for service in services.values() if service["state"] != "disabled"]
        online = sum(1 for service in services.values() if service["state"] == "online")
        total_requests = sum(service["requests"] for service in services.values())
        total_errors = sum(service["errors"] for service in services.values())
        return {
            "started_at": self.started_at,
            "uptime_seconds": int(time.time() - self.started_at),
            "services": services,
            "totals": {
                "requests": total_requests,
                "errors": total_errors,
                "services": len(config.routes),
                "enabled": len(enabled),
                "online": online,
            },
            "traffic": [event.as_dict() for event in list(self.recent)[:12]],
        }


class HealthMonitor:
    def __init__(self, stats: Stats, manager: ConfigManager) -> None:
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
                error=exc.__class__.__name,
            )
