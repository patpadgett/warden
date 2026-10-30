from __future__ import annotations
import time
import pytest
from warden.stats import MetricsModule, HealthMonitor, RouteMetrics, Health, TrafficEvent
from warden.config import RouteConfig


def test_route_metrics_average_latency() -> None:
    m = RouteMetrics()
    assert m.average_latency_ms is None
    m.requests = 2
    m.total_latency_ms = 20.0
    assert m.average_latency_ms == 10.0


def test_health_as_none() -> None:
    h = Health()
    assert h.online is None


def test_traffic_event_as_dict() -> None:
    e = TrafficEvent(
        timestamp=time.time(),
        host="test",
        method="GET",
        path="/",
        status=200,
        latency_ms=10.5,
        user="alice",
        public=True,
    )
    d = e.as_dict()
    assert d["host"] == "test"
    assert d["user"] == "alice"
    assert d["public"] is True


def test_stats_init_and_inc() -> None:
    s = MetricsModule()
    s.inc_auth_success()
    assert s.auth_success == 1
    s.inc_auth_failure()
    assert s.auth_failure == 1
    s.inc_otp_success()
    assert s.otp_success == 1
    s.inc_otp_failure()
    assert s.otp_failure == 1
    s.inc_rate_limit_allowed()
    assert s.rate_limit_allowed == 1
    s.inc_rate_limit_blocked()
    assert s.rate_limit_blocked == 1
    s.inc_backup_code_used()
    assert s.backup_code_used == 1


def test_stats_record_request() -> None:
    s = MetricsModule()
    route = RouteConfig(host="test.home", upstream="http://localhost:8000", auth=True)
    s.record_request(route, method="GET", path="/", status=200, latency_ms=5.0, user="alice")
    assert s.metrics["test.home"].requests == 1
    assert s.metrics["test.home"].authenticated == 1


def test_stats_route_snapshot() -> None:
    from warden.config import WardenConfig, RouteConfig
    cfg = WardenConfig()
    cfg.routes = [RouteConfig(host="snap.home", upstream="http://localhost:8000", auth=False)]
    s = MetricsModule()
    s.record_request(cfg.routes[0], method="GET", path="/", status=200, latency_ms=1.0, user=None)
    snap = s.route_snapshot(cfg)
    assert snap["snap.home"]["requests"] == 1
    assert snap["snap.home"]["state"] == "checking"  # no health seen yet -> checking


def test_health_monitor_start_stop() -> None:
    from warden.config import ConfigManager, WardenConfig
    import tempfile, pathlib
    with tempfile.TemporaryDirectory() as td:
        cfg_path = pathlib.Path(td) / "w.yaml"
        cfg_path.write_text("version: 1\nserver:\n  admin_host: localhost\nroutes: []\n")
        manager = ConfigManager.from_file(cfg_path)
        stats = MetricsModule()
        monitor = HealthMonitor(stats, manager)
        assert monitor is not None
