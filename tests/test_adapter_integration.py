from __future__ import annotations
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from pathlib import Path
from warden.config import ConfigManager, parse_config_text
from warden.db import Database
from warden.mesh_peer import MeshPeerIntake
from warden.mesh_apply_mock import MockMeshApplyAdapter
from tests.conftest import config_dict, dump_yaml


def mesh_config(tmp_path: Path, **mesh):
    values = {
        "enabled": True,
        "interface": "wg0",
        "address": "10.44.0.1/24",
        "listen_port": 51820,
        "endpoint": "vpn.example.com:51820",
        "dns": "10.44.0.1",
        "client_allowed_ips": "10.44.0.0/24, 192.168.1.0/24",
        "config_path": str(tmp_path / "wg0.conf"),
    }
    values.update(mesh)
    import tempfile
    data = config_dict(tmp_path, mesh=values)
    return parse_config_text(dump_yaml(data), base_dir=tmp_path)


async def test_full_adapter_integration(tmp_path: Path) -> None:
    cfg = mesh_config(tmp_path)
    manager = ConfigManager(cfg, None)
    db = Database(tmp_path / "mesh.db")
    await db.init()
    try:
        intake = MeshPeerIntake(db, manager)
        adapter = MockMeshApplyAdapter(intake)

        # Intake: add peer + render
        peer = await intake.add_peer(name="Phone")
        server = await intake.render_server_config()
        assert "[Interface]" in server

        # Adapter: write + apply + status + refresh
        result = await adapter.apply()
        assert result["ok"] is True
        assert adapter.intake.last_apply is result

        status = await adapter.status()
        assert status["available"] is True

        refresh = await adapter.refresh_handshakes()
        assert refresh["available"] is True
        await db.close()
    finally:
        await db.close()
