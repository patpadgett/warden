from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from warden.config import parse_config_text
from warden.tls import (
    TLSError,
    certificate_status,
    read_certificate,
    validate_runtime_files,
)

from .conftest import config_dict, dump_yaml


def make_certificate(
    directory: Path,
    *,
    days: int = 90,
    not_before_days: int = -1,
    names: tuple[str, ...] = ("admin.home.lan",),
) -> tuple[Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, names[0]),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Warden Test"),
        ]
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + timedelta(days=not_before_days))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in names]),
            critical=False,
        )
    )
    certificate = builder.sign(key, hashes.SHA256())
    cert_path = directory / "cert.pem"
    key_path = directory / "key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def tls_config(tmp_path: Path, cert: Path, key: Path, **server):
    data = config_dict(tmp_path, tls={"enabled": True, "certfile": str(cert), "keyfile": str(key)}, **server)
    return parse_config_text(dump_yaml(data), base_dir=tmp_path)


def test_read_certificate(tmp_path: Path) -> None:
    cert_path, _ = make_certificate(tmp_path, names=("admin.home.lan", "*.apps.home.lan"))
    info = read_certificate(cert_path)
    assert "admin.home.lan" in info.subject
    assert "Warden Test" in info.issuer
    assert info.sans == ["admin.home.lan", "*.apps.home.lan"]
    assert 88 < info.days_left <= 90
    assert info.expired is False
    assert info.as_dict()["path"] == str(cert_path)
    assert info.as_dict()["days_left"] == round(info.days_left, 1)


def test_certificate_status_enabled(tmp_path: Path) -> None:
    cert_path, key_path = make_certificate(tmp_path)
    config = tls_config(tmp_path, cert_path, key_path)
    status = certificate_status(config)
    assert status["enabled"] is True
    assert status["configured"] is True
    assert status["ok"] is True
    assert status["error"] is None
    assert status["certificate"]["subject"]
    assert status["renew_command"] is False


def test_certificate_status_disabled_and_broken(tmp_path: Path) -> None:
    data = config_dict(tmp_path)
    config = parse_config_text(dump_yaml(data), base_dir=tmp_path)
    status = certificate_status(config)
    assert status["enabled"] is False
    assert status["certificate"] is None
    assert status["path"] is None

    missing = tmp_path / "missing.pem"
    data = config_dict(
        tmp_path, tls={"enabled": True, "certfile": str(missing), "keyfile": str(missing)}
    )
    config = parse_config_text(dump_yaml(data), base_dir=tmp_path)
    status = certificate_status(config)
    assert status["ok"] is False
    assert "Could not read certificate" in status["error"]

    bad = tmp_path / "bad.pem"
    bad.write_text("not a certificate")
    data = config_dict(
        tmp_path, tls={"enabled": True, "certfile": str(bad), "keyfile": str(bad)}
    )
    config = parse_config_text(dump_yaml(data), base_dir=tmp_path)
    assert "Could not parse" in certificate_status(config)["error"]


def test_expired_certificate(tmp_path: Path) -> None:
    cert_path, key_path = make_certificate(tmp_path, days=-1, not_before_days=-30)
    info = read_certificate(cert_path)
    assert info.expired is True
    config = tls_config(tmp_path, cert_path, key_path)
    status = certificate_status(config)
    assert status["ok"] is False
    assert status["certificate"]["expired"] is True

    with pytest.raises(TLSError):
        read_certificate(tmp_path / "absent.pem")


def test_validate_runtime_files(tmp_path: Path) -> None:
    # Disabled TLS short-circuits even when the paths do not exist.
    data = config_dict(tmp_path)
    config = parse_config_text(dump_yaml(data), base_dir=tmp_path)
    validate_runtime_files(config)

    cert_path, key_path = make_certificate(tmp_path)
    config = tls_config(tmp_path, cert_path, tmp_path / "missing-key.pem")
    with pytest.raises(TLSError, match="private key not found"):
        validate_runtime_files(config)

    config = tls_config(tmp_path, cert_path, key_path)
    validate_runtime_files(config)

    key_path.unlink()
    with pytest.raises(TLSError, match="private key not found"):
        validate_runtime_files(config)
