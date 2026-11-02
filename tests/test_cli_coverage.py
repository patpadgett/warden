from __future__ import annotations

from pathlib import Path

from warden.cli import cmd_check, cmd_config_show, cmd_init


def test_config_show(tmp_path: Path) -> None:
    import argparse
    p = tmp_path / "w.yaml"
    p.write_text("version: 1\nserver:\n  admin_host: localhost\nwebauthn:\n  rp_id: localhost\nroutes: []\n")
    args = argparse.Namespace(config=str(p))
    # Should not raise
    cmd_config_show(args)


def test_check_json(tmp_path: Path) -> None:
    import argparse
    p = tmp_path / "w.yaml"
    p.write_text("version: 1\nserver:\n  admin_host: localhost\nroutes: []\n")
    args = argparse.Namespace(config=str(p), json=True)
    # Should not raise (valid config)
    cmd_check(args)


def test_init_force(tmp_path: Path) -> None:
    import argparse
    out = tmp_path / "new.yaml"
    args = argparse.Namespace(output=str(out), admin_host="localhost", rp_id=None, bind="0.0.0.0", port=8080, https_port=8443, database="warden.db", force=True)
    cmd_init(args)
    assert out.exists()
