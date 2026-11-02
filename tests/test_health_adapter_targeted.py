from __future__ import annotations

from unittest.mock import MagicMock

from warden.health_adapter import HealthMonitor
from warden.stats import MetricsModule


def test_health_adapter_init() -> None:
    stats = MetricsModule()
    manager = MagicMock()
    adapter = HealthMonitor(stats, manager)
    assert adapter.stats is stats


def test_health_start_stop() -> None:
    stats = MetricsModule()
    manager = MagicMock()
    adapter = HealthMonitor(stats, manager)
    import asyncio
    asyncio.run(adapter.start())
    # Stop after brief interval
    async def stop_after():
        await adapter.stop()
    asyncio.run(stop_after())
    assert adapter._task is None or adapter._task.cancelled()
