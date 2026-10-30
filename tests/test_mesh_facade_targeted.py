from __future__ import annotations
from unittest.mock import AsyncMock, MagicMock
from warden.mesh_peer import MeshPeerIntake
from warden.mesh_apply import MeshApplyAdapter
from warden.mesh import MeshManager


def test_facade_delegates_intake_and_adapter() -> None:
    db = MagicMock()
    manager = MagicMock()
    manager.config.mesh.enabled = True

    mesh = MeshManager(db, manager)
    assert isinstance(mesh.intake, MeshPeerIntake)
    assert isinstance(mesh.adapter, MeshApplyAdapter)

    # Facade routes to adapter/apply
    assert callable(mesh.apply)
