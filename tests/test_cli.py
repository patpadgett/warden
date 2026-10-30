from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from warden import cli

from .conftest import config_dict, count_rows, seed_user, write_config
from .test_tls import make_certificate


def run(capsys: pytest.CaptureFixture[str], *args: object) -> tuple[int, str, str]:
    code = cli.main([str(arg) for arg in args])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


# ------------------------------------------------------------------------ init
def test_init_writes_valid_config(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    output = tmp_path / "conf" / "warden.yaml"
    code, out, err = run(
        capsys,
        "init",
        "-o",
        output,
        "--admin-host",
        "Warden.Home.LAN",
        "--rp-id",
        "home.lan",
        "--database",
        "/var/lib/warden/warden.db",
        "--port",
        "9080",
    )
    assert code == 0
    assert err == ""
    assert "wrote" in out
    assert "admin host  warden.home.lan" in out
    assert output.exists()
    assert stat.S_IMODE(output.stat().st_mode) == 0o600

    manager = cli.ConfigManager.from_file(output)
    config = manager.config
    assert config.server.admin_host == "warden.home.lan"
    assert config.webauthn.rp_id == "home.lan"
    assert config.server.http_port == 9080
    assert config.server.tls.enabled is False
    assert config.database_path == Path("/var/lib/warden/warden.db")
    assert config.routes == []


def test_init_refuses_to_overwrite_without_force(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "warden.yaml"
    output.write_text("original\n", encoding="utf-8")

    code, _out, err = run(capsys, "init", "-o", output)
    assert code == 1
    assert "already exists" in err
    assert output.read_text(encoding="utf-8") == "original\n"

    code, out, _err = run(capsys, "init", "-o", output, "--force")
    assert code == 0
    assert "wrote" in out
    assert "server:" in output.read_text(encoding="utf-8")


def test_init_rejects_invalid_admin_host(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "warden.yaml"
    code, _out, err = run(capsys, "init", "-o", output, "--admin-host", "https://warden.home.lan")
    assert code == 1
    assert "Invalid configuration" in err
    assert not output.exists()


# ----------------------------------------------------------------------- check
def test_check_json_ok(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = write_config(tmp_path, config_dict(tmp_path))
    code, out, err = run(capsys, "-c", path, "check", "--json")
    assert code == 0
    assert err == ""
    report = json.loads(out)
    assert report["ok"] is True
    assert report["config"] == str(path)
    assert report["admin_host"] == "admin.home.lan"
    assert report["routes"] == 1
    assert report["tls"]["enabled"] is False
    assert report["webauthn_rp_id"] == "home.lan"
    assert report["mesh_enabled"] is False
    assert report["mesh_config"] is None
    assert report["problems"] == []


def test_check_human_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = write_config(tmp_path, config_dict(tmp_path))
    code, out, _err = run(capsys, "-c", path, "check")
    assert code == 0
    assert "configuration is valid" in out
    assert "tls         disabled" in out
    assert "mesh        disabled" in out


def test_check_invalid_config_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "warden.yaml"
    path.write_text(
        "version: 1\nserver:\n  admin_host: 'bad host'\n", encoding="utf-8"
    )
    code, out, err = run(capsys, "-c", path, "check", "--json")
    assert code == 1
    assert err == ""
    report = json.loads(out)
    assert report["ok"] is False
    assert "Invalid configuration" in report["error"]
    assert any("admin_host" in item for item in report["errors"])


def test_check_missing_config_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    missing = tmp_path / "absent.yaml"
    code, out, _err = run(capsys, "-c", missing, "check", "--json")
    assert code == 1
    report = json.loads(out)
    assert report["ok"] is False
    assert "not found" in report["error"].lower()


def test_check_reports_missing_tls_key(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cert_path, _key_path = make_certificate(tmp_path)
    data = config_dict(
        tmp_path,
        tls={
            "enabled": True,
            "certfile": str(cert_path),
            "keyfile": str(tmp_path / "missing-key.pem"),
        },
    )
    path = write_config(tmp_path, data)
    code, out, _err = run(capsys, "-c", path, "check", "--json")
    assert code == 1
    report = json.loads(out)
    assert report["ok"] is False
    assert report["tls"]["ok"] is True
    assert any("private key not found" in problem for problem in report["problems"])


# ----------------------------------------------------------------------- certs
def test_certs_status_disabled(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = write_config(tmp_path, config_dict(tmp_path))
    code, out, _err = run(capsys, "-c", path, "certs", "status")
    assert code == 0
    assert "TLS is disabled" in out

    code, out, _err = run(capsys, "-c", path, "certs", "status", "--json")
    assert code == 0
    status = json.loads(out)
    assert status["enabled"] is False
    assert status["certificate"] is None


def test_certs_status_valid_certificate(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cert_path, key_path = make_certificate(tmp_path, names=("admin.home.lan",))
    data = config_dict(
        tmp_path,
        tls={"enabled": True, "certfile": str(cert_path), "keyfile": str(key_path)},
    )
    path = write_config(tmp_path, data)
    code, out, _err = run(capsys, "-c", path, "certs", "status")
    assert code == 0
    assert f"certificate  {cert_path}" in out
    assert "days left" in out
    assert "admin.home.lan" in out
    assert "renew hook   not configured" in out

    code, out, _err = run(capsys, "-c", path, "certs", "status", "--json")
    assert code == 0
    status = json.loads(out)
    assert status["enabled"] is True
    assert status["configured"] is True
    assert status["ok"] is True
    assert status["certificate"]["days_left"] > 0
    assert status["certificate"]["sans"] == ["admin.home.lan"]


def test_certs_status_expired_certificate(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cert_path, key_path = make_certificate(tmp_path, days=-1, not_before_days=-30)
    data = config_dict(
        tmp_path,
        tls={"enabled": True, "certfile": str(cert_path), "keyfile": str(key_path)},
    )
    path = write_config(tmp_path, data)
    code, out, _err = run(capsys, "-c", path, "certs", "status")
    assert code == 1
    assert "has expired" in out


def test_certs_status_missing_certificate(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    missing = tmp_path / "missing.pem"
    data = config_dict(
        tmp_path,
        tls={
            "enabled": True,
            "certfile": str(missing),
            "keyfile": str(tmp_path / "key.pem"),
        },
    )
    path = write_config(tmp_path, data)
    code, _out, err = run(capsys, "-c", path, "certs", "status")
    assert code == 1
    assert "Could not read certificate" in err


def test_certs_renew_dry_run_and_guards(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cert_path, key_path = make_certificate(tmp_path)
    tls = {
        "enabled": True,
        "certfile": str(cert_path),
        "keyfile": str(key_path),
        "renew_command": "echo renewed",
    }
    path = write_config(tmp_path, config_dict(tmp_path, tls=tls))
    code, out, _err = run(capsys, "-c", path, "certs", "renew", "--dry-run")
    assert code == 0
    assert out.strip() == "echo renewed"

    disabled = write_config(
        tmp_path, config_dict(tmp_path), name="disabled.yaml"
    )
    code, _out, err = run(capsys, "-c", disabled, "certs", "renew", "--dry-run")
    assert code == 1
    assert "TLS is disabled" in err

    no_hook = write_config(
        tmp_path,
        config_dict(
            tmp_path,
            tls={"enabled": True, "certfile": str(cert_path), "keyfile": str(key_path)},
        ),
        name="no-hook.yaml",
    )
    code, _out, err = run(capsys, "-c", no_hook, "certs", "renew", "--dry-run")
    assert code == 1
    assert "renew_command" in err


def test_certs_renew_runs_command(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cert_path, key_path = make_certificate(tmp_path)
    tls = {
        "enabled": True,
        "certfile": str(cert_path),
        "keyfile": str(key_path),
        "renew_command": "echo renewed",
    }
    path = write_config(tmp_path, config_dict(tmp_path, tls=tls))
    code, out, err = run(capsys, "-c", path, "certs", "renew")
    assert code == 0
    assert f"running: {tls['renew_command']}" in out
    assert "renewed" in out
    assert "Restart Warden" in out
    assert err == ""

    failing = write_config(
        tmp_path,
        config_dict(
            tmp_path,
            tls={**tls, "renew_command": "sh -c 'exit 3'"},
        ),
        name="failing.yaml",
    )
    code, out, err = run(capsys, "-c", failing, "certs", "renew")
    assert code == 1
    assert "exited with 3" in err


# ------------------------------------------------------------------------ auth
def test_auth_reset_removes_everything(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write_config(tmp_path, config_dict(tmp_path))
    db_path = tmp_path / "warden.db"
    seed_user(db_path, credential_count=2)
    assert count_rows(db_path, "users") == 1
    assert count_rows(db_path, "credentials") == 2
    assert count_rows(db_path, "sessions") == 1

    code, out, err = run(capsys, "-c", path, "auth", "reset", "--yes")
    assert code == 0
    assert err == ""
    assert "Removed 1 account" in out
    assert "Restart Warden" in out
    assert count_rows(db_path, "users") == 0
    assert count_rows(db_path, "credentials") == 0
    assert count_rows(db_path, "sessions") == 0


def test_auth_reset_requires_confirmation(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write_config(tmp_path, config_dict(tmp_path))
    db_path = tmp_path / "warden.db"
    seed_user(db_path)

    # pytest replaces stdin with a non-tty stream, so Warden refuses to proceed.
    code, _out, err = run(capsys, "-c", path, "auth", "reset")
    assert code == 1
    assert "without --yes" in err
    assert count_rows(db_path, "users") == 1


def test_auth_reset_missing_database(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write_config(tmp_path, config_dict(tmp_path))
    code, _out, err = run(capsys, "-c", path, "auth", "reset", "--yes")
    assert code == 1
    assert "database not found" in err


# ------------------------------------------------------------------------ mesh
def mesh_config(tmp_path: Path, *, enabled: bool = True) -> Path:
    data = config_dict(
        tmp_path,
        mesh={
            "enabled": enabled,
            "interface": "wg0",
            "address": "10.44.0.1/24",
            "listen_port": 51820,
            "endpoint": "vpn.home.lan:51820",
            "dns": "10.44.0.1",
            "client_allowed_ips": "10.44.0.0/24, 192.168.1.0/24",
            "config_path": str(tmp_path / "wg0.conf"),
        },
    )
    return write_config(tmp_path, data)


def test_mesh_peer_lifecycle(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = mesh_config(tmp_path)
    output = tmp_path / "alice.conf"

    code, out, err = run(
        capsys, "-c", path, "mesh", "peer", "add", "alice", "-o", output
    )
    assert code == 0
    assert err == ""
    assert "created alice · 10.44.0.2" in out
    assert "client config written" in out
    assert output.exists()
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    client_config = output.read_text(encoding="utf-8")
    assert "# alice" in client_config
    assert "PrivateKey = " in client_config
    assert "Address = 10.44.0.2/32" in client_config
    assert "DNS = 10.44.0.1" in client_config
    assert "Endpoint = vpn.home.lan:51820" in client_config
    assert "PresharedKey = " in client_config
    assert "AllowedIPs = 10.44.0.0/24, 192.168.1.0/24" in client_config
    assert "PersistentKeepalive = 25" in client_config

    code, out, _err = run(capsys, "-c", path, "mesh", "peers")
    assert code == 0
    assert "alice" in out
    assert "10.44.0.2" in out

    code, out, _err = run(capsys, "-c", path, "mesh", "peer", "config", "ALICE")
    assert code == 0
    assert out == client_config

    code, out, _err = run(capsys, "-c", path, "mesh", "config")
    assert code == 0
    assert "ListenPort = 51820" in out
    assert "# alice" in out
    assert "AllowedIPs = 10.44.0.2/32" in out
    assert "PresharedKey = " in out

    code, out, _err = run(capsys, "-c", path, "mesh", "peer", "remove", "alice", "--yes")
    assert code == 0
    assert "removed alice" in out
    code, out, _err = run(capsys, "-c", path, "mesh", "peers")
    assert code == 0
    assert "No mesh peers" in out

    code, _out, err = run(capsys, "-c", path, "mesh", "peer", "remove", "ghost", "--yes")
    assert code == 1
    assert "no mesh peer" in err


def test_mesh_peer_add_prints_config_without_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = mesh_config(tmp_path)
    code, out, _err = run(capsys, "-c", path, "mesh", "peer", "add", "phone")
    assert code == 0
    assert "created phone · 10.44.0.2" in out
    assert "[Interface]" in out
    assert "[Peer]" in out
    assert "Run 'warden mesh apply'" in out


def test_mesh_apply_fails_without_wireguard(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    path = mesh_config(tmp_path)
    monkeypatch.setattr("warden.mesh_apply.shutil.which", lambda _name: None)
    code, _out, err = run(capsys, "-c", path, "mesh", "apply")
    assert code == 1
    assert "WireGuard isn't installed" in err


def test_mesh_status_when_unavailable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    path = mesh_config(tmp_path)
    run(capsys, "-c", path, "mesh", "peer", "add", "laptop")
    monkeypatch.setattr("warden.mesh_apply.shutil.which", lambda _name: None)
    code, out, _err = run(capsys, "-c", path, "mesh", "status")
    assert code == 0
    assert "interface   wg0" in out
    assert "available   no" in out
    assert "applied     no" in out


def test_mesh_disabled(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = mesh_config(tmp_path, enabled=False)
    code, out, _err = run(capsys, "-c", path, "mesh", "status")
    assert code == 0
    assert "disabled" in out

    code, _out, err = run(capsys, "-c", path, "mesh", "peer", "add", "alice")
    assert code == 1
    assert "disabled" in err
    assert count_rows(tmp_path / "warden.db", "mesh_peers") == 0
