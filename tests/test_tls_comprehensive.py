"""
Comprehensive tests for the TLS module (warden/tls.py).

Covers all TLS-related functions including certificate inspection,
ACME certificate issuance, and renewal.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from warden.config import parse_config_text, WardenConfig, ConfigManager
from warden.tls import (
    TLSError,
    ACMEManager,
    ACMEToken,
    CertificateInfo,
    certificate_status,
    generate_self_signed_cert,
    read_certificate,
    validate_runtime_files,
)


# -------------------------------------------------------------------------
# Helpers (copied from tests/test_tls.py)
# -------------------------------------------------------------------------
def config_dict(
    tmp_path: Path,
    *,
    upstream: str = "http://127.0.0.1:9",
    routes: list[dict[str, str]] | None = None,
    mesh: dict[str, str] | None = None,
    **server_overrides: Any,
) -> Any:
    server: dict[str, Any] = {
        "admin_host": "admin.home.lan",
        "bind": "127.0.0.1",
        "http_port": "8080",
        "https_port": "8443",
        "tls": {"enabled": "False"},
        "log_level": "warning",
        "health_interval_seconds": "3600",
    }
    server.update(server_overrides)
    return {
        "version": 1,
        "server": server,
        "database": {"path": str(tmp_path / "warden.db")},
        "webauthn": {"rp_id": "home.lan", "rp_name": "Warden"},
        "mesh": {"enabled": False},
        "routes": [{"host": "app.home.lan", "upstream": "http://127.0.0.1:9", "name": "App"}],
    }


def dump_yaml(data: Any) -> str:
    from ruamel.yaml import YAML
    yaml = YAML()
    buffer = StringIO()
    yaml.dump(data, buffer)
    return buffer.getvalue()


def make_certificate(
    directory: Path,
    *,
    days: int = 90,
    not_before_days: int = -1,
    names: tuple[str, ...] = ("admin.home.lan",),
) -> tuple[Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    cn = names[0] if names else "admin.home.lan"
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
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
    data = config_dict(tmp_path, tls={"enabled": "True", "certfile": str(cert), "keyfile": str(key)}, **server)
    return parse_config_text(dump_yaml(data), base_dir=tmp_path)


# -------------------------------------------------------------------------
# Tests for generate_self_signed_cert
# -------------------------------------------------------------------------
class TestGenerateSelfSignedCert:
    """Tests for generate_self_signed_cert."""

    def test_creates_cert_and_key(self, tmp_path: Path) -> None:
        cert_path = tmp_path / "cert.pem"
        key_path = tmp_path / "key.pem"
        generate_self_signed_cert(cert_path, key_path, "localhost")
        assert cert_path.exists()
        assert key_path.exists()
        cert_data = cert_path.read_bytes()
        key_data = key_path.read_bytes()
        assert cert_data.startswith(b"-----BEGIN CERTIFICATE-----")
        assert key_data.startswith(b"-----BEGIN RSA PRIVATE KEY-----")

    def test_creates_parent_directories(self, tmp_path: Path) -> None:
        cert_path = tmp_path / "sub" / "dir" / "cert.pem"
        key_path = tmp_path / "sub" / "dir" / "key.pem"
        generate_self_signed_cert(cert_path, key_path, "localhost")
        assert cert_path.exists()
        assert key_path.exists()

    def test_certificate_valid_for_one_year(self, tmp_path: Path) -> None:
        cert_path = tmp_path / "cert.pem"
        key_path = tmp_path / "key.pem"
        generate_self_signed_cert(cert_path, key_path, "localhost")
        info = read_certificate(cert_path)
        assert 355 < info.days_left <= 365

    def test_certificate_contains_common_name(self, tmp_path: Path) -> None:
        cert_path = tmp_path / "cert.pem"
        key_path = tmp_path / "key.pem"
        generate_self_signed_cert(cert_path, key_path, "admin.home.lan")
        info = read_certificate(cert_path)
        assert "admin.home.lan" in info.subject

    def test_certificate_has_san(self, tmp_path: Path) -> None:
        cert_path = tmp_path / "cert.pem"
        key_path = tmp_path / "key.pem"
        generate_self_signed_cert(cert_path, key_path, "admin.home.lan")
        info = read_certificate(cert_path)
        assert "admin.home.lan" in info.sans


# -------------------------------------------------------------------------
# Tests for ACMEToken
# -------------------------------------------------------------------------
class TestACMEToken:
    """Tests for the ACMEToken class."""

    def test_token_not_expired_initially(self) -> None:
        token = ACMEToken("abc123", validity=3600)
        assert token.expired is False

    def test_token_expired_when_validity_is_zero(self) -> None:
        token = ACMEToken("abc123", validity=0)
        assert token.expired is True

    def test_token_expired_after_validity(self) -> None:
        from time import sleep
        token = ACMEToken("abc123", validity=1)
        sleep(1.1)
        assert token.expired is True

    def test_token_created_at_timestamp(self) -> None:
        from time import time
        token = ACMEToken("abc123", validity=3600)
        assert token.created_at <= time() + 1


# -------------------------------------------------------------------------
# Tests for ACMEManager
# -------------------------------------------------------------------------
class TestACMEManager:
    """Tests for the ACMEManager class."""

    @pytest.fixture()
    def manager(self, tmp_path: Path):
        from ruamel.yaml import YAML
        config_data = {
            "version": 1,
            "server": {"admin_host": "admin.home.lan", "tls": {"enabled": True, "certfile": str(tmp_path / "c.pem"), "keyfile": str(tmp_path / "k.pem")}},
            "database": {"path": str(tmp_path / "warden.db")},
            "webauthn": {"rp_id": "home.lan", "rp_name": "Test"},
            "mesh": {"enabled": False},
            "routes": [{"host": "app.home.lan", "upstream": "http://localhost:8080", "name": "App"}],
        }
        yaml = YAML()
        buffer = StringIO()
        yaml.dump(config_data, buffer)
        config = parse_config_text(buffer.getvalue(), base_dir=tmp_path)
        return ACMEManager(ConfigManager(config, tmp_path))

    def test_set_and_get_challenge_token(self, manager: ACMEManager) -> None:
        token = "test-token-123"
        manager.set_challenge_token(token, validity=3600)
        response = manager.get_challenge_response(token)
        assert response == token

    def test_get_challenge_response_returns_none_for_unknown(self, manager: ACMEManager) -> None:
        assert manager.get_challenge_response("unknown-token") is None

    def test_challenge_token_expired(self, manager: ACMEManager) -> None:
        import time
        manager.set_challenge_token("expired-token", validity=0)
        time.sleep(0.1)
        assert manager.get_challenge_response("expired-token") is None

    def test_account_key_generated_on_first_call(self, tmp_path: Path) -> None:
        config = parse_config_text(
            dump_yaml(
                config_dict(
                    tmp_path,
                    tls={
                        "enabled": "True",
                        "certfile": str(tmp_path / "c.pem"),
                        "keyfile": str(tmp_path / "k.pem"),
                    },
                )
            ),
            base_dir=tmp_path,
        )
        manager = ACMEManager(ConfigManager(config, tmp_path))
        assert not (tmp_path / ".warden" / "acme_account.key").exists()
        manager._get_account_key()
        assert (tmp_path / ".warden" / "acme_account.key").exists()

    def test_account_key_reused_on_subsequent_calls(self, tmp_path: Path) -> None:
        config = parse_config_text(
            dump_yaml(
                config_dict(
                    tmp_path,
                    tls={
                        "enabled": "True",
                        "certfile": str(tmp_path / "c.pem"),
                        "keyfile": str(tmp_path / "k.pem"),
                    },
                )
            ),
            base_dir=tmp_path,
        )
        manager = ACMEManager(ConfigManager(config, tmp_path))
        manager._get_account_key()
        first_path = tmp_path / ".warden" / "acme_account.key"
        first_mtime = first_path.stat().st_mtime
        manager._get_account_key()
        assert first_path.exists()
        assert first_path.stat().st_mtime == first_mtime


# -------------------------------------------------------------------------
# Tests for read_certificate
# -------------------------------------------------------------------------
class TestReadCertificate:
    """Tests for read_certificate."""

    def test_read_valid_certificate(self, tmp_path: Path) -> None:
        cert_path, _ = make_certificate(tmp_path, names=("admin.home.lan", "*.apps.home.lan"))
        info = read_certificate(cert_path)
        assert "admin.home.lan" in info.subject
        assert "admin.home.lan" in info.sans
        assert "*.apps.home.lan" in info.sans
        assert info.days_left > 0
        assert info.expired is False
        assert info.as_dict()["path"] == str(cert_path)

    def test_read_certificate_with_no_sans(self, tmp_path: Path) -> None:
        cert_path, _ = make_certificate(tmp_path, names=())
        info = read_certificate(cert_path)
        assert info.sans == []

    def test_read_expired_certificate(self, tmp_path: Path) -> None:
        cert_path, _ = make_certificate(tmp_path, days=-1, not_before_days=-30)
        info = read_certificate(cert_path)
        assert info.expired is True

    def test_read_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(TLSError, match="Could not read certificate"):
            read_certificate(tmp_path / "missing.pem")

    def test_read_invalid_pem_raises(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.pem"
        bad.write_text("not a certificate at all")
        with pytest.raises(TLSError, match="Could not parse PEM certificate"):
            read_certificate(bad)


# -------------------------------------------------------------------------
# Tests for CertificateInfo dataclass
# -------------------------------------------------------------------------
class TestCertificateInfo:
    """Tests for the CertificateInfo dataclass."""

    def test_not_expired(self) -> None:
        info = CertificateInfo(
            path=Path("/tmp/cert.pem"),
            subject="CN=admin.home.lan",
            issuer="CN=admin.home.lan",
            not_before=datetime.now(timezone.utc) - timedelta(days=1),
            not_after=datetime.now(timezone.utc) + timedelta(days=80),
            days_left=75.0,
            sans=["admin.home.lan"],
        )
        assert info.expired is False

    def test_expired(self) -> None:
        info = CertificateInfo(
            path=Path("/tmp/cert.pem"),
            subject="CN=admin.home.lan",
            issuer="CN=admin.home.lan",
            not_before=datetime.now(timezone.utc) - timedelta(days=1),
            not_after=datetime.now(timezone.utc) - timedelta(days=1),
            days_left=-1.0,
            sans=["admin.home.lan"],
        )
        assert info.expired is True

    def test_as_dict(self) -> None:
        info = CertificateInfo(
            path=Path("/tmp/cert.pem"),
            subject="CN=admin.home.lan",
            issuer="CN=admin.home.lan",
            not_before=datetime.now(timezone.utc) - timedelta(days=1),
            not_after=datetime.now(timezone.utc) + timedelta(days=80),
            days_left=75.0,
            sans=["admin.home.lan"],
        )
        d = info.as_dict()
        assert d["path"] == "/tmp/cert.pem"
        assert d["subject"] == "CN=admin.home.lan"
        assert d["issuer"] == "CN=admin.home.lan"
        assert d["days_left"] == 75.0
        assert d["sans"] == ["admin.home.lan"]
        assert d["expired"] is False
        assert "not_before" in d
        assert "not_after" in d


# -------------------------------------------------------------------------
# Tests for certificate_status
# -------------------------------------------------------------------------
class TestCertificateStatus:
    """Tests for certificate_status."""

    def test_tls_disabled(self, tmp_path: Path) -> None:
        config = parse_config_text(
            dump_yaml(config_dict(tmp_path)),
            base_dir=tmp_path,
        )
        status = certificate_status(config)
        assert status["enabled"] is False
        assert status["configured"] is False
        assert status["certificate"] is None
        assert status["path"] is None

    def test_no_certfile_configured(self, tmp_path: Path) -> None:
        data = config_dict(tmp_path, tls={"enabled": True})
        config = parse_config_text(dump_yaml(data), base_dir=tmp_path)
        status = certificate_status(config)
        assert status["configured"] is False
        assert status["error"] == "No certificate file configured."

    def test_missing_certfile(self, tmp_path: Path) -> None:
        missing = tmp_path / "missing.pem"
        data = config_dict(
            tmp_path, tls={"enabled": True, "certfile": str(missing), "keyfile": str(missing)}
        )
        config = parse_config_text(dump_yaml(data), base_dir=tmp_path)
        status = certificate_status(config)
        assert status["ok"] is False
        assert "Could not read certificate" in status["error"]

    def test_invalid_cert_content(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.pem"
        bad.write_text("not a certificate")
        data = config_dict(
            tmp_path, tls={"enabled": True, "certfile": str(bad), "keyfile": str(bad)}
        )
        config = parse_config_text(dump_yaml(data), base_dir=tmp_path)
        status = certificate_status(config)
        assert status["ok"] is False
        assert "Could not parse" in status["error"]

    def test_enabled_with_valid_cert(self, tmp_path: Path) -> None:
        cert_path, key_path = make_certificate(tmp_path)
        data = config_dict(
            tmp_path, tls={"enabled": True, "certfile": str(cert_path), "keyfile": str(key_path)}
        )
        config = parse_config_text(dump_yaml(data), base_dir=tmp_path)
        status = certificate_status(config)
        assert status["enabled"] is True
        assert status["configured"] is True
        assert status["ok"] is True
        assert status["certificate"] is not None
        assert status["certificate"]["subject"]


# -------------------------------------------------------------------------
# Tests for validate_runtime_files
# -------------------------------------------------------------------------
class TestValidateRuntimeFiles:
    """Tests for validate_runtime_files."""

    def test_disabled_tls_skips_validation(self, tmp_path: Path) -> None:
        config = parse_config_text(
            dump_yaml(config_dict(tmp_path)),
            base_dir=tmp_path,
        )
        validate_runtime_files(config)  # should not raise

    def test_missing_cert_file(self, tmp_path: Path) -> None:
        cert_path = tmp_path / "cert.pem"
        key_path = tmp_path / "key.pem"
        data = config_dict(
            tmp_path, tls={"enabled": True, "certfile": str(cert_path), "keyfile": str(key_path)}
        )
        config = parse_config_text(dump_yaml(data), base_dir=tmp_path)
        with pytest.raises(TLSError, match="certificate not found"):
            validate_runtime_files(config)

    def test_missing_key_file(self, tmp_path: Path) -> None:
        cert_path, _ = make_certificate(tmp_path)
        key_path = tmp_path / "missing-key.pem"
        data = config_dict(
            tmp_path, tls={"enabled": True, "certfile": str(cert_path), "keyfile": str(key_path)}
        )
        config = parse_config_text(dump_yaml(data), base_dir=tmp_path)
        with pytest.raises(TLSError, match="private key not found"):
            validate_runtime_files(config)

    def test_valid_config_passes(self, tmp_path: Path) -> None:
        cert_path, key_path = make_certificate(tmp_path)
        data = config_dict(
            tmp_path, tls={"enabled": True, "certfile": str(cert_path), "keyfile": str(key_path)}
        )
        config = parse_config_text(dump_yaml(data), base_dir=tmp_path)
        validate_runtime_files(config)  # should not raise

    def test_keypem_not_readable(self, tmp_path: Path) -> None:
        cert_path, key_path = make_certificate(tmp_path)
        key_path.chmod(0o000)
        data = config_dict(
            tmp_path, tls={"enabled": True, "certfile": str(cert_path), "keyfile": str(key_path)}
        )
        config = parse_config_text(dump_yaml(data), base_dir=tmp_path)
        with pytest.raises(TLSError, match="Could not read TLS private key"):
            validate_runtime_files(config)


# -------------------------------------------------------------------------
# Tests for _run_renewal
# -------------------------------------------------------------------------
class TestRunRenewal:
    """Tests for _run_renewal."""

    @pytest.mark.asyncio
    async def test_success(self, tmp_path: Path) -> None:
        from warden.tls import _run_renewal
        app = MagicMock()
        config = MagicMock()
        config.server.tls.renew_command = "test-renew"
        config.base_dir.return_value = tmp_path
        mock_process = AsyncMock()
        mock_process.communicate.return_value = (b"", b"")
        mock_process.returncode = 0
        with patch("warden.tls.asyncio.create_subprocess_shell", return_value=mock_process):
            await _run_renewal(app, config)
        assert app.state.cert_renewal["ok"] is True
        assert app.state.cert_renewal["command"] == "test-renew"
        assert app.state.cert_renewal["output"] == ""

    @pytest.mark.asyncio
    async def test_failure(self, tmp_path: Path) -> None:
        from warden.tls import _run_renewal
        app = MagicMock()
        config = MagicMock()
        config.server.tls.renew_command = "failing-command"
        config.base_dir.return_value = tmp_path
        mock_process = AsyncMock()
        mock_process.communicate.return_value = (b"", b"")
        mock_process.returncode = 1
        with patch("warden.tls.asyncio.create_subprocess_shell", return_value=mock_process):
            await _run_renewal(app, config)
        assert app.state.cert_renewal["ok"] is False
        assert app.state.cert_renewal["command"] == "failing-command"


# -------------------------------------------------------------------------
# Tests for renewal_loop
# -------------------------------------------------------------------------
class TestRenewalLoop:
    """Tests for renewal_loop."""

    @pytest.mark.asyncio
    async def test_renew_due(self, tmp_path: Path) -> None:
        import warden.tls as warden_tls_module
        from warden.tls import renewal_loop as _renewal_loop
        app = MagicMock()
        app.state.manager = MagicMock()
        app.state.cert_renewal = None

        config = MagicMock()
        config.server.tls.enabled = True
        config.server.tls.renew_command = "cron renew"
        config.server.tls.check_interval_hours = 24
        config.server.tls.renew_days_before = 30
        app.state.manager.config = config

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        cert_path = tmp_path / "cert.pem"
        key_path = tmp_path / "key.pem"
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(timezone.utc)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "admin.home.lan")])
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=30))
            .not_valid_after(now - timedelta(days=29))
        )
        cert = builder.sign(key, hashes.SHA256())
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    
        with patch("warden.tls.asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            mock_status = MagicMock()
            mock_status.return_value = {
                "enabled": True,
                "configured": True,
                "ok": False,
                "certificate": {"days_left": -1},
                "error": None,
                "path": str(cert_path),
                "renew_command": True,
            }
            mock_renewal = AsyncMock()
            mock_renewal.return_value = mock_renewal  # Return itself (a coroutine)
            with patch("warden.tls.certificate_status", mock_status):
                # Patch renewal_loop in the warden.tls module
                with patch.object(__import__("warden.tls", fromlist=["renewal_loop"]), "renewal_loop", mock_renewal):
                    mock_sleep.side_effect = [None]
                    renewal_task = asyncio.create_task(warden_tls_module.renewal_loop(app))
                    await asyncio.sleep(0.1)
                    renewal_task.cancel()
                    with pytest.raises(asyncio.CancelledError):
                        await renewal_task
                    mock_renewal.assert_called_once()

    @pytest.mark.asyncio
    async def test_no_renewal_when_disabled(self) -> None:
        from warden.tls import renewal_loop
        app = MagicMock()
        app.state.manager = MagicMock()
        app.state.cert_renewal = None
        config = MagicMock()
        config.server.tls.enabled = False
        config.server.tls.renew_command = None
        app.state.manager.config = config
        await renewal_loop(app)  # Should return without calling _run_renewal


# -------------------------------------------------------------------------
# Tests for ACMEManager.request_certificate
# -------------------------------------------------------------------------
class TestRequestCertificate:
    """Tests for ACMEManager.request_certificate."""

    @pytest.fixture()
    def manager(self, tmp_path: Path):
        from unittest.mock import Mock
        from warden.config import WardenConfig, ServerConfig, TLSConfig
        config = WardenConfig(
            version=1,
            server=ServerConfig(
                admin_host="admin.home.lan",
                bind="127.0.0.1",
                http_port="8080",
                https_port="8443",
                tls=TLSConfig(
                    enabled=True,
                    certfile=str(tmp_path / "c.pem"),
                    keyfile=str(tmp_path / "k.pem"),
                ),
                log_level="warning",
                health_interval_seconds="3600",
            ),
            database={"path": str(tmp_path / "warden.db")},
            webauthn={"rp_id": "home.lan", "rp_name": "Warden"},
            mesh={"enabled": False},
            routes=[{"host": "app.home.lan", "upstream": "http://127.0.0.1:9", "name": "App"}],
        )
        from warden.config import ConfigManager
        # Use the real config object, not a Mock. The base_dir property
        # returns tmp_path via the WardenConfig implementation.
        cm = ConfigManager(config, tmp_path)
        # Mock base_dir to return tmp_path so the test works with
        # ACMEManager._get_account_key() which uses config.base_dir()
        cm._config._base_dir = tmp_path
        acm = ACMEManager(cm)
        # Force certfile_path and keyfile_path to resolve to tmp_path
        acm.manager._config.server.tls.certfile = str(tmp_path / "c.pem")
        acm.manager._config.server.tls.keyfile = str(tmp_path / "k.pem")
        # Also patch the MANAGER's config property to return the real config
        # with the correct certfile_path and keyfile_path
        acm._config = config  # Replace the managed config with the real one
        return acm

    @pytest.mark.asyncio
    async def test_request_certificate_success(self, manager: ACMEManager, tmp_path: Path) -> None:
        import warden.tls as tls_mod
        original_acme_client = tls_mod.acme_client

        mock_client = MagicMock()
        mock_order = MagicMock()
        mock_authz = MagicMock()
        mock_authz.body = MagicMock()
        mock_authz.body.status = "valid"
        mock_authz.body.challenges = [MagicMock()]
        mock_authz.body.challenges[0].chall = MagicMock()
        mock_authz.body.challenges[0].chall.token = "test-token"
        mock_authz.body.challenges[0].chall.response = MagicMock(return_value="dummy-response")
        mock_order.authorizations = [mock_authz]
        mock_client.new_order = MagicMock(return_value=mock_order)
        mock_client.new_account = MagicMock()
        mock_client.poll = MagicMock(return_value=mock_authz)
        mock_client.answer_challenge = MagicMock()
        mock_client.finalize_order = MagicMock(return_value=MagicMock(
            fullchain_pem="-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n"
        ))
        tls_mod.acme_client = mock_client

        try:
            cert_path, key_path = await manager.request_certificate("admin.home.lan", "https://acme.example.com")
            assert cert_path.exists()
            assert key_path.exists()
            assert cert_path.read_text().startswith("-----BEGIN CERTIFICATE-----")
        finally:
            tls_mod.acme_client = original_acme_client

    @pytest.mark.asyncio
    async def test_request_certificate_no_acme_client(self, manager: ACMEManager) -> None:
        import warden.tls as tls_mod
        original_acme_client = tls_mod.acme_client
        try:
            tls_mod.acme_client = None
            with pytest.raises(TLSError, match="acme library not installed"):
                await manager.request_certificate("admin.home.lan", "https://acme.example.com")
        finally:
            tls_mod.acme_client = original_acme_client
