from __future__ import annotations
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from warden.mesh_peer import MeshPeerIntake, MeshError
from warden.mesh_apply import MeshApplyAdapter


def test_adapter_init() -> None:
    db = AsyncMock()
    manager = MagicMock()
    manager.config.mesh.enabled = True
    intake = MeshPeerIntake(db, manager)
    adapter = MeshApplyAdapter(intake)
    assert adapter.intake is intake


def test_adapter_apply_requires_wg() -> None:
    db = AsyncMock()
    manager = MagicMock()
    manager.config.mesh.enabled = True
    manager.config.mesh_config_path = "/tmp/wg0.conf"
    manager.config.mesh.interface = "wg0"
    manager.config.mesh.address = "10.44.0.1/24"
    intake = MeshPeerIntake(db, manager)
    adapter = MeshApplyAdapter(intake)
    with patch("shutil.which", return_value=None):
        import asyncio
        with pytest.raises(MeshError, match="WireGuard isn't installed"):
            asyncio.run(adapter.apply())
