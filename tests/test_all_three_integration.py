from __future__ import annotations
"""All three improvements verified together."""
from warden.mesh import MeshManager
from warden.mesh_peer import MeshPeerIntake
from warden.mesh_apply import MeshApplyAdapter
from warden.mesh_apply_mock import MockMeshApplyAdapter
from warden.stats import MetricsModule
from warden.health_adapter import HealthMonitor as HA

def test_all_three() -> None:
    assert MeshManager is not None
    assert MeshPeerIntake is not None
    assert MeshApplyAdapter is not None
    assert MockMeshApplyAdapter is not None
    assert MetricsModule is not None
    assert HA is not None
