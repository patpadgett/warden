from __future__ import annotations

import logging
from pathlib import Path

from warden.cli import _configure_logging, cmd_check, cmd_config_show, cmd_init


def test_configure_logging_default() -> None:
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
    _configure_logging("info")
    assert root.level == logging.INFO


def test_configure_logging_rotating_file(tmp_path: Path) -> None:
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
    log_path = tmp_path / "warden.log"
    _configure_logging("debug", log_file=str(log_path), log_rotation="size", log_max_size_mb=1, log_backup_count=2)
    logger = logging.getLogger("warden.test")
    logger.info("hello rotation")
    assert log_path.exists()
    content = log_path.read_text()
    assert "hello rotation" in content


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
