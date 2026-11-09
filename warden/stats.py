"""In-memory traffic metrics and upstream health checks."""

from __future__ import annotations

import logging
import time
from collections import deque
from dataclasses import dataclass
from typing import Any

from warden.config import RouteConfig, WardenConfig
from warden.utils import truncate

logger = logging.getLogger("warden.health")


@dataclass(slots=True)
class RouteMetrics:
    """Route metrics per host."""
    requests: int = 0
    errors: int = 0
    last_status: int | None = None
    last_seen: float | None = None
    total_latency_ms: float = 0.0
    last_latency_ms: float | None = None
    authenticated: int = 0

    @property
    def average_latency_ms(self) -> float | None:
        """average_latency_ms."""
        if not self.requests:
            return None
        return self.total_latency_ms / self.requests


@dataclass(slots=True)
class Health:
    """Health check result for a route."""
    online: bool | None = None
    status_code: int | None = None
    latency_ms: float | None = None
    checked_at: float | None = None
    error: str | None = None


@dataclass(slots=True)
class TrafficEvent:
    """Recent traffic event for dashboard."""
    timestamp: float
    host: str
    method: str
    path: str
    status: int
    latency_ms: float
    user: str | None = None
    public: bool = False

    def as_dict(self) -> dict[str, Any]:
        """as_dict."""
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

class MetricsModule:
    """In-memory metrics, health checks, and Prometheus export."""
    def __init__(self) -> None:
        """__init__."""
        self.started_at = time.time()
        self.metrics: dict[str, RouteMetrics] = {}
        self.health: dict[str, Health] = {}
        self.recent: deque[TrafficEvent] = deque(maxlen=60)
        # New auth and access metrics
        self.auth_success = 0
        self.auth_failure = 0
        self.otp_success = 0
        self.otp_failure = 0
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
        """record_request."""
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
        """inc_auth_success."""
        self.auth_success += 1

    def inc_auth_failure(self) -> None:
        """inc_auth_failure."""
        self.auth_failure += 1

    def inc_otp_success(self) -> None:
        """inc_otp_success."""
        self.otp_success += 1

    def inc_otp_failure(self) -> None:
        """inc_otp_failure."""
        self.otp_failure += 1

    def inc_backup_code_used(self) -> None:
        """inc_backup_code_used."""
        self.backup_code_used += 1

    def inc_rate_limit_blocked(self) -> None:
        """inc_rate_limit_blocked."""
        self.rate_limit_blocked += 1

    def inc_rate_limit_allowed(self) -> None:
        """inc_rate_limit_allowed."""
        self.rate_limit_allowed += 1


    def route_snapshot(self, config: WardenConfig) -> dict[str, dict[str, Any]]:
        """route_snapshot."""
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
        def _escape(value: str) -> str:
            """_escape."""
            return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")

        lines = []
        now = time.time()
        
        # System metrics
        lines.append("# HELP warden_uptime_seconds Total uptime of the Warden process")
        lines.append("# TYPE warden_uptime_seconds gauge")
        lines.append(f"warden_uptime_seconds {int(now - self.started_at)}")
        
        # Route metrics
        for host, m in self.metrics.items():
            host_label = _escape(host)
            lines.append(f'# HELP warden_route_requests_total Total requests for {host}')
            lines.append('# TYPE warden_route_requests_total counter')
            lines.append(f'warden_route_requests_total{{host="{host_label}"}} {m.requests}')
            lines.append(f'# HELP warden_route_errors_total Total errors for {host}')
            lines.append('# TYPE warden_route_errors_total counter')
            lines.append(f'warden_route_errors_total{{host="{host_label}"}} {m.errors}')
            if m.last_latency_ms is not None:
                lines.append(f'# HELP warden_route_latency_ms Last request latency for {host}')
                lines.append('# TYPE warden_route_latency_ms gauge')
                lines.append(f'warden_route_latency_ms{{host="{host_label}"}} {m.last_latency_ms}')
            lines.append(f'# HELP warden_route_authenticated_requests_total Total authenticated requests for {host}')
            lines.append('# TYPE warden_route_authenticated_requests_total counter')
            lines.append(f'warden_route_authenticated_requests_total{{host="{host_label}"}} {m.authenticated}')
        # Auth and access metrics
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
        """snapshot."""
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

