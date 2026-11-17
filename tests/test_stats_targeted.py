from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

from warden.config import RouteConfig, WardenConfig
from warden.health_adapter import HealthMonitor
from warden.stats import Health, MetricsModule, RouteMetrics, TrafficEvent


def test_stats_init() -> None:
    s = MetricsModule()
    assert s.metrics == {}
    assert s.health == {}
    assert s.recent is not None
    assert s.started_at > 0

def test_record_request_basic() -> None:
    s = MetricsModule()
    route = RouteConfig(host="app.local", upstream="http://localhost", health_path="/")
    s.record_request(route, method="GET", path="/test", status=200, latency_ms=50.0, user=None)
    assert s.metrics["app.local"].requests == 1
    assert s.metrics["app.local"].last_status == 200
    assert s.metrics["app.local"].total_latency_ms == 50.0
    assert s.recent[0].method == "GET"

def test_record_request_auth_counted() -> None:
    s = MetricsModule()
    route = RouteConfig(host="app.local", upstream="http://localhost", health_path="/", auth=True)
    s.record_request(route, method="GET", path="/", status=200, latency_ms=10.0, user="alice")
    assert s.metrics["app.local"].authenticated == 1

def test_record_request_public_flag() -> None:
    s_auth = MetricsModule()
    route_auth = RouteConfig(host="auth.local", upstream="http://localhost", health_path="/", auth=True)
    s_auth.record_request(route_auth, method="GET", path="/", status=200, latency_ms=1.0, user="bob")
    assert s_auth.recent[0].public is False
    s_pub = MetricsModule()
    route_pub = RouteConfig(host="pub.local", upstream="http://localhost", health_path="/", auth=False)
    s_pub.record_request(route_pub, method="GET", path="/", status=200, latency_ms=1.0, user=None)
    assert s_pub.recent[0].public is True

def test_record_request_error_flag() -> None:
    s = MetricsModule()
    route = RouteConfig(host="err.local", upstream="http://localhost", health_path="/")
    s.record_request(route, method="GET", path="/", status=502, latency_ms=5.0, user=None)
    assert s.metrics["err.local"].errors == 1
    assert s.recent[0].status == 502

def test_record_request_status_zero() -> None:
    s = MetricsModule()
    route = RouteConfig(host="zero.local", upstream="http://localhost", health_path="/")
    s.record_request(route, method="GET", path="/", status=0, latency_ms=2.0, user=None)
    assert s.metrics["zero.local"].errors == 1  # status == 0 counts as error

def test_inc_counters() -> None:
    s = MetricsModule()
    s.inc_auth_success(); s.inc_auth_success()
    assert s.auth_success == 2
    s.inc_auth_failure(); s.inc_otp_success(); s.inc_otp_failure()
    assert s.auth_failure == 1
    assert s.otp_success == 1
    assert s.otp_failure == 1
    s.inc_backup_code_used()
    assert s.backup_code_used == 1
    s.inc_rate_limit_blocked(); s.inc_rate_limit_allowed()
    assert s.rate_limit_blocked == 1
    assert s.rate_limit_allowed == 1

def test_route_snapshot_states() -> None:
    s = MetricsModule()
    config = WardenConfig()
    # Just verify snapshot produces valid dicts for default routes
    snap = s.route_snapshot(config)
    assert isinstance(snap, dict)
    for data in snap.values():
        assert "state" in data
        assert data["state"] in ("disabled", "checking", "online", "offline")

def test_snapshot_totals() -> None:
    s = MetricsModule()
    config = WardenConfig()
    # Snapshot should have totals based on config routes, not external routes
    result = s.snapshot(config)
    assert result["totals"]["services"] == len(config.routes)
    assert "started_at" in result
    assert "uptime_seconds" in result
    assert "traffic" in result
    assert isinstance(result["traffic"], list)

def test_traffic_event_as_dict() -> None:
    e = TrafficEvent(timestamp=1.0, host="h.local", method="GET", path="/", status=200, latency_ms=10.0)
    d = e.as_dict()
    assert d["host"] == "h.local"
    assert d["status"] == 200
    assert "latency_ms" in d
    assert "user" in d

def test_route_metrics_average_latency() -> None:
    m = RouteMetrics()
    assert m.average_latency_ms is None  # no requests
    m.requests = 2
    m.total_latency_ms = 100.0
    assert m.average_latency_ms == 50.0

def test_record_health() -> None:
    s = MetricsModule()
    h = s.health.setdefault("x", Health())
    s.record_health("x", online=True, status_code=200, latency_ms=10.0, error=None)
    assert h.online is True
    assert h.status_code == 200

def test_prometheus_metrics_includes_routes_and_counters() -> None:
    s = MetricsModule()
    route = RouteConfig(host="prom.local", upstream="http://localhost", health_path="/", verify_tls=False)
    s.record_request(route, method="GET", path="/", status=200, latency_ms=30.0, user=None)
    lines = s.prometheus_metrics()
    assert "warden_uptime_seconds" in lines
    assert "warden_route_requests_total{host=\"prom.local\"}" in lines
    assert "warden_auth_success_total" in lines
    assert "warden_rate_limit_allowed_total" in lines
    assert "warden_rate_limit_blocked_total" in lines


def test_prometheus_declares_each_metric_family_once() -> None:
    """HELP/TYPE describe a family: repeating them per sample is invalid."""
    s = MetricsModule()
    for host in ("a.local", "b.local"):
        route = RouteConfig(
            host=host, upstream="http://localhost", health_path="/", verify_tls=False
        )
        s.record_request(route, method="GET", path="/", status=200, latency_ms=1.0, user=None)
    lines = s.prometheus_metrics()
    assert lines.count("# HELP warden_route_requests_total") == 1
    assert lines.count("# TYPE warden_route_requests_total") == 1
    assert lines.count("# HELP warden_route_latency_ms") == 1
    assert lines.count("# TYPE warden_route_latency_ms") == 1

def test_health_monitor_stop() -> None:
    monitor = HealthMonitor(MetricsModule(), MagicMock())
    asyncio.run(monitor.stop())  # should not raise
