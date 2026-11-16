from __future__ import annotations

import time
from datetime import UTC, datetime
from pathlib import Path

from warden.config import WardenConfig
from warden.tls import (
    ACMEToken,
    CertificateInfo,
    TLSError,
    certificate_status,
    generate_self_signed_cert,
    read_certificate,
)


def test_generate_self_signed_cert_creates_files(tmp_path: Path) -> None:
    cert_path = tmp_path / "test.crt"
    key_path = tmp_path / "test.key"
    generate_self_signed_cert(cert_path, key_path, "test.local")
    assert cert_path.exists()
    assert key_path.exists()
    # valid cert should have days_left > 0
    info = read_certificate(cert_path)
    assert info.days_left > 0
    assert info.subject == "CN=test.local"


def test_generate_self_signed_cert_validity(tmp_path: Path) -> None:
    cert_path = tmp_path / "test.crt"
    key_path = tmp_path / "test.key"
    generate_self_signed_cert(cert_path, key_path, "test.local")
    info = read_certificate(cert_path)
    assert info.not_before is not None
    assert info.not_after is not None


def test_acme_token_lifecycle() -> None:
    t = ACMEToken("my-token", "my-token.thumbprint", 1.0)
    assert t.expired is False
    # token should expire after validity period
    time.sleep(1.1)
    assert t.expired is True


def test_read_certificate_valid(tmp_path: Path) -> None:
    cert_path = tmp_path / "valid.crt"
    key_path = tmp_path / "valid.key"
    generate_self_signed_cert(cert_path, key_path, "example.com")
    info = read_certificate(cert_path)
    assert info.path == cert_path
    assert info.sans == ["example.com"]
    assert info.expired is False


def test_read_certificate_raises_on_missing(tmp_path: Path) -> None:
    nonexistent = tmp_path / "no_such.pem"
    try:
        read_certificate(nonexistent)
        assert False, "Should have raised TLSError"
    except TLSError:
        pass


def test_certificate_status_disabled(tmp_path: Path) -> None:
    cert_path = tmp_path / "test.crt"
    key_path = tmp_path / "test.key"
    generate_self_signed_cert(cert_path, key_path, "test.local")
    cfg = WardenConfig()
    cfg.server.tls.enabled = False
    status = certificate_status(cfg)
    assert status["ok"] is False
    assert status["error"] is None  # disabled -> not an error, just disabled
    assert status["enabled"] is False
    assert status["configured"] is False


def test_certificate_status_missing_files(tmp_path: Path) -> None:
    cert_path = tmp_path / "test.crt"
    key_path = tmp_path / "test.key"
    generate_self_signed_cert(cert_path, key_path, "test.local")
    cfg = WardenConfig()
    cfg.server.tls.enabled = True
    cfg.server.tls.certfile = None
    cfg.server.tls.keyfile = None
    status = certificate_status(cfg)
    assert status["error"] == "No certificate file configured."
    assert status["ok"] is False
    assert status["enabled"] is True
    assert status["configured"] is False


def test_read_certificate_pem_parsing(tmp_path: Path) -> None:
    cert_path = tmp_path / "test.crt"
    key_path = tmp_path / "test.key"
    generate_self_signed_cert(cert_path, key_path, "example.com")
    info = read_certificate(cert_path)
    d = info.as_dict()
    assert "path" in d
    assert "subject" in d
    assert "issuer" in d
    assert "not_before" in d
    assert "not_after" in d
    assert "days_left" in d
    assert "sans" in d
    assert "expired" in d


def test_certificate_info_property() -> None:
    ci = CertificateInfo(
        path=Path("test.pem"),
        subject="CN=test",
        issuer="CN=root",
        not_before=datetime(2020, 1, 1, tzinfo=UTC),
        not_after=datetime(2025, 1, 1, tzinfo=UTC),
        days_left=1825.0,
        sans=[],
    )
    assert ci.expired is False
    assert ci.as_dict()["expired"] is False
    # expired when days_left <= 0
    ci2 = CertificateInfo(
        path=Path("test.pem"),
        subject="CN=test",
        issuer="CN=root",
        not_before=datetime(2020, 1, 1, tzinfo=UTC),
        not_after=datetime(2020, 6, 1, tzinfo=UTC),
        days_left=-181.0,
        sans=[],
    )
    assert ci2.expired is True
    assert ci2.as_dict()["expired"] is True