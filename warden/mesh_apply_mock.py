"""Mock adapter for mesh apply (test stub)."""
from __future__ import annotations

from typing import Any

from warden.mesh_apply import MeshApplyAdapter


class MockMeshApplyAdapter(MeshApplyAdapter):
    """Stub adapter for tests — skips wg subprocess calls."""

    def __init__(self, intake) -> None:
        super().__init__(intake)
        self.mock_applied = True

    async def apply(self) -> dict[str, Any]:
        result = {
            "ok": True,
            "output": "mock applied",
            "config_path": str(await self.intake.write_config()),
            "interface": self.config.mesh.interface,
            "timestamp": 0,
        }
        self.intake.last_apply = result
        return result

    async def status(self) -> dict[str, Any]:
        return {"available": True, "applied": True, "peers": {}, "detail": "mock status"}

    async def refresh_handshakes(self) -> dict[str, Any]:
        return await self.status()
