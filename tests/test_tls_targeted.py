from __future__ import annotations

from pathlib import Path

from warden.config import WardenConfig
from warden.tls import (
    ACMEToken,
    certificate_status,
    generate_self_signed_cert,
    read_certificate,
)


def test_generate_self_signed_cert(tmp_path: Path) -> None:
    cert_path = tmp_path / "test.crt"
    key_path = tmp_path / "test.key"
    generate_self_signed_cert(cert_path, key_path, "test.local")
    assert cert_path.exists()
    assert key_path.exists()

def test_read_certificate(tmp_path: Path) -> None:
    cert_path = tmp_path / "test.crt"
    key_path = tmp_path / "test.key"
    generate_self_signed_cert(cert_path, key_path, "test.local")
    info = read_certificate(cert_path)
    assert info.subject == "CN=test.local"
    assert info.days_left > 0

def test_certificate_expired(tmp_path: Path) -> None:
    cert_path = tmp_path / "test.crt"
    key_path = tmp_path / "test.key"
    generate_self_signed_cert(cert_path, key_path, "test.local")
    info = read_certificate(cert_path)
    assert info.expired is False
    assert info.as_dict()["expired"] is False

def test_acme_token_expired() -> None:
    t = ACMEToken("token", 0)
    import time
    time.sleep(0.01)
    assert t.expired is True

def test_certificate_status_disabled() -> None:
    cfg = WardenConfig()
    cfg.server.tls.enabled = False
    status = certificate_status(cfg)
    assert status["enabled"] is False
    assert status["configured"] is False

class FakeConfig:
    server = type("S", (), {"tls": type("T", (), {"enabled": True, "certfile": None, "keyfile": None})()})()
    base_dir = lambda self: Path(".")
