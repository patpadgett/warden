from __future__ import annotations

from warden.config import MeshConfig


def test_mesh_config_validation() -> None:
    cfg = MeshConfig(enabled=False)
    assert cfg.interface == "wg0"
    assert cfg.address == "10.44.0.1/24"
