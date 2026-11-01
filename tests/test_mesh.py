from __future__ import annotations

import stat
from pathlib import Path

import pytest

from warden.config import ConfigManager, parse_config_text
from warden.db import Database
from warden.mesh import MeshManager
from warden.mesh_peer import MeshError, public_from_private

from .conftest import config_dict, dump_yaml


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
    data = config_dict(tmp_path, mesh=values)
    return parse_config_text(dump_yaml(data), base_dir=tmp_path)


@pytest.fixture
async def mesh(tmp_path: Path):
    config = mesh_config(tmp_path)
    manager = ConfigManager(config, None)
    db = Database(tmp_path / "mesh.db")
    await db.init()
    manager_instance = MeshManager(db, manager)
    try:
        yield manager_instance
    finally:
        await db.close()


async def test_hub_key_is_stable(mesh: MeshManager) -> None:
    key = await mesh.ensure_hub_key()
    assert await mesh.ensure_hub_key() == key
    assert await mesh.hub_public_key() == public_from_private(key)


async def test_add_peer_allocates_addresses(mesh: MeshManager) -> None:
    first = await mesh.add_peer(name="Phone")
    assert first.address == "10.44.0.2"
    assert first.endpoint is None
    assert first.keepalive == 25
    second = await mesh.add_peer(name="Laptop", address="10.44.0.9", endpoint="laptop:51820", keepalive=0)
    assert second.address == "10.44.0.9"
    assert second.endpoint == "laptop:51820"
    third = await mesh.add_peer(name="Tablet")
    assert third.address == "10.44.0.3"


async def test_add_peer_validation(mesh: MeshManager) -> None:
    with pytest.raises(MeshError, match="name"):
        await mesh.add_peer(name="")
    with pytest.raises(MeshError, match="name"):
        await mesh.add_peer(name="bad/name")
    with pytest.raises(MeshError, match="Keepalive"):
        await mesh.add_peer(name="Phone", keepalive=70000)
    with pytest.raises(MeshError, match="outside"):
        await mesh.add_peer(name="Phone", address="10.99.0.2")
    with pytest.raises(MeshError, match="reserved"):
        await mesh.add_peer(name="Phone", address="10.44.0.1")
    with pytest.raises(MeshError, match="reserved"):
        await mesh.add_peer(name="Phone", address="10.44.0.255")
    with pytest.raises(MeshError, match="endpoint"):
        await mesh.add_peer(name="Phone", endpoint="noport")
    with pytest.raises(MeshError, match="endpoint"):
        await mesh.add_peer(name="Phone", endpoint="host:99999")
    with pytest.raises(MeshError, match="IPv4"):
        await mesh.add_peer(name="Phone", address="fd00::2")

    await mesh.add_peer(name="Phone", address="10.44.0.2")
    with pytest.raises(MeshError, match="name already exists"):
        await mesh.add_peer(name="phone", address="10.44.0.4")
    with pytest.raises(MeshError, match="already uses"):
        await mesh.add_peer(name="Tablet", address="10.44.0.2")


async def test_add_peer_exhausted_network(tmp_path: Path) -> None:
    config = mesh_config(tmp_path, address="10.44.0.1/30")
    manager = ConfigManager(config, None)
    db = Database(tmp_path / "small.db")
    await db.init()
    try:
        instance = MeshManager(db, manager)
        peer = await instance.add_peer(name="Phone")
        assert peer.address == "10.44.0.2"
        with pytest.raises(MeshError, match="no free addresses"):
            await instance.add_peer(name="Laptop")
    finally:
        await db.close()


async def test_render_server_and_peer_configs(mesh: MeshManager, tmp_path: Path) -> None:
    peer = await mesh.add_peer(name="Phone", endpoint="phone.example:4444", keepalive=30)
    server = await mesh.render_server_config()
    assert "[Interface]" in server
    assert "Address = 10.44.0.1/24" in server
    assert "ListenPort = 51820" in server
    assert "PrivateKey = " in server
    assert "# Phone" in server
    assert f"PublicKey = {peer.public_key}" in server
    assert "AllowedIPs = 10.44.0.2/32" in server
    assert "Endpoint = phone.example:4444" in server
    assert server.endswith("\n")

    config = await mesh.render_peer_config(peer)
    assert f"PrivateKey = {peer.private_key}" in config
    assert "Address = 10.44.0.2/32" in config
    assert "DNS = 10.44.0.1" in config
    assert f"PresharedKey = {peer.preshared_key}" in config
    assert "Endpoint = vpn.example.com:51820" in config
    assert "AllowedIPs = 10.44.0.0/24, 192.168.1.0/24" in config
    assert "PersistentKeepalive = 30" in config

    no_endpoint = mesh_config(tmp_path, endpoint=None, dns=None)
    manager = ConfigManager(no_endpoint, None)
    no_endpoint_instance = MeshManager(mesh.db, manager)
    plain = await no_endpoint_instance.render_peer_config(peer)
    assert "# Set mesh.endpoint" in plain
    assert "DNS = " not in plain


async def test_write_config_private(mesh: MeshManager, tmp_path: Path) -> None:
    await mesh.add_peer(name="Phone")
    path = await mesh.write_config()
    assert path == tmp_path / "wg0.conf"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert "AllowedIPs = 10.44.0.2/32" in path.read_text()


async def test_disabled_mesh(tmp_path: Path) -> None:
    data = config_dict(tmp_path)
    manager = ConfigManager(parse_config_text(dump_yaml(data), base_dir=tmp_path), None)
    db = Database(tmp_path / "disabled.db")
    await db.init()
    try:
        instance = MeshManager(db, manager)
        with pytest.raises(MeshError, match="disabled"):
            await instance.add_peer(name="Phone")
        with pytest.raises(MeshError, match="disabled"):
            await instance.render_server_config()
        with pytest.raises(MeshError, match="disabled"):
            await instance.apply()
        assert await instance.status() == {"available": False, "applied": False, "peers": {}}
    finally:
        await db.close()


async def test_apply_requires_wireguard(mesh: MeshManager, monkeypatch) -> None:
    monkeypatch.setattr("warden.mesh_apply.shutil.which", lambda name: None)
    with pytest.raises(MeshError, match="isn't installed"):
        await mesh.apply()


async def test_apply_brings_interface_up(mesh: MeshManager, monkeypatch) -> None:
    calls: list[tuple[list[str], bytes | None]] = []
    monkeypatch.setattr(
        "warden.mesh_apply.shutil.which",
        lambda name: {"wg": "/usr/bin/wg", "wg-quick": "/usr/bin/wg-quick"}[name],
    )

    async def fake_run(args, *, input_bytes=None, timeout=60):
        calls.append((args, input_bytes))
        if args[1:3] == ["show", "wg0"]:
            return 1, "not running"
        if args[1:3] == ["up", str(mesh.config.mesh_config_path)]:
            return 0, ""
        raise AssertionError(args)

    monkeypatch.setattr(mesh.adapter, "_run", fake_run)
    peer = await mesh.add_peer(name="Phone")
    result = await mesh.apply()
    assert result["ok"] is True
    assert result["interface"] == "wg0"
    assert mesh.last_apply is result
    assert calls[-1][0] == ["/usr/bin/wg-quick", "up", str(mesh.config.mesh_config_path)]
    assert peer.public_key in (await mesh.render_server_config())


async def test_apply_syncs_running_interface(mesh: MeshManager, monkeypatch) -> None:
    calls: list[tuple[list[str], bytes | None]] = []
    monkeypatch.setattr(
        "warden.mesh_apply.shutil.which",
        lambda name: {"wg": "/usr/bin/wg", "wg-quick": "/usr/bin/wg-quick"}[name],
    )

    async def fake_run(args, *, input_bytes=None, timeout=60):
        calls.append((args, input_bytes))
        if args[1:3] == ["show", "wg0"]:
            return 0, "interface: wg0"
        if args[1] == "strip":
            return 0, "[Interface]\nListenPort = 51820"
        if args[1] == "syncconf":
            assert args[2] == "wg0"
            assert args[3] == "/dev/stdin"
            return 0, ""
        raise AssertionError(args)

    monkeypatch.setattr(mesh.adapter, "_run", fake_run)
    await mesh.add_peer(name="Phone")
    result = await mesh.apply()
    assert result["ok"] is True
    assert calls[-1][0] == ["/usr/bin/wg", "syncconf", "wg0", "/dev/stdin"]
    assert calls[-1][1] == b"[Interface]\nListenPort = 51820"


async def test_apply_reports_failure(mesh: MeshManager, monkeypatch) -> None:
    monkeypatch.setattr(
        "warden.mesh_apply.shutil.which",
        lambda name: {"wg": "/usr/bin/wg", "wg-quick": "/usr/bin/wg-quick"}[name],
    )

    async def fake_run(args, *, input_bytes=None, timeout=60):
        if args[1:3] == ["show", "wg0"]:
            return 1, ""
        return 2, "boom"

    monkeypatch.setattr(mesh.adapter, "_run", fake_run)
    await mesh.add_peer(name="Phone")
    with pytest.raises(MeshError, match="boom"):
        await mesh.apply()
    assert mesh.last_apply is not None
    assert mesh.last_apply["ok"] is False


async def test_status_and_handshake_refresh(mesh: MeshManager, monkeypatch) -> None:
    peer = await mesh.add_peer(name="Phone")
    monkeypatch.setattr("warden.mesh_apply.shutil.which", lambda name: "/usr/bin/wg")

    dump = (
        "priv\tpub\t51820\toff\n"
        f"{peer.public_key}\tpsk\t203.0.113.5:4444\t10.44.0.2/32\t"
        "1700000000\t1234\t5678\t25\n"
        "short\tline\n"
    )

    async def fake_run(args, *, input_bytes=None, timeout=60):
        assert args[1:] == ["show", "wg0", "dump"]
        return 0, dump

    monkeypatch.setattr(mesh.adapter, "_run", fake_run)
    status = await mesh.status()
    assert status["available"] is True
    assert status["applied"] is True
    info = status["peers"][peer.public_key]
    assert info.endpoint == "203.0.113.5:4444"
    assert info.last_handshake == 1700000000.0
    assert info.rx_bytes == 1234
    assert info.tx_bytes == 5678
    assert info.keepalive == "25"

    await mesh.refresh_handshakes()
    assert (await mesh.db.get_mesh_peer(peer.id)).last_handshake == 1700000000.0

    # When the interface is live but the peer disappears, clear the stale value.
    monkeypatch.setattr(mesh.adapter, "_run", lambda *a, **k: _return((0, "priv\tpub\t51820\toff\n")))
    await mesh.refresh_handshakes()
    assert (await mesh.db.get_mesh_peer(peer.id)).last_handshake is None


async def _return(value):
    return value
