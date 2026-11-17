"""TLS certificate inspection and optional certbot renewal hook.

This module defines utilities for reading X.509 certificates, checking their
validity, and automatically renewing them via an ACME client (Let's Encrypt or
compatible). It also provides the :class:`ACMEManager` class for handling ACME
challenges and the :func:`renewal_loop` coroutine for periodic renewal.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from pathlib import Path

try:
    from acme import challenges, errors, jose, messages
    from acme import client as acme_client
except ImportError:
    acme_client = None
    messages = None
    challenges = None
    jose = None
    errors = None

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from warden.config import ConfigManager, WardenConfig

logger = logging.getLogger("warden.tls")

def generate_self_signed_cert(cert_path: Path, key_path: Path, common_name: str) -> None:
    """Generate a self‑signed TLS certificate for development use.

    The certificate is valid for one year and includes the *common_name* as a
    Subject Alternative Name. The private key is an unencrypted RSA 2048‑bit
    key written in PEM format.
    """
    from datetime import datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    # Private key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # Subject and issuer are the same for a self‑signed cert
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False
        )
        .sign(private_key, hashes.SHA256())
    )
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    os.chmod(key_path, 0o600)


class TLSError(Exception):
    """Error raised for TLS‑related operations, such as missing files or validation failures."""


#: Longest a single HTTP-01 authorization may stay pending before giving up.
ACME_AUTHZ_TIMEOUT = 300.0


def _wait_for_authorization(
    net: Any,
    authz: Any,
    domain: str,
    *,
    timeout: float = ACME_AUTHZ_TIMEOUT,
    interval: float = 2.0,
) -> None:
    """Poll *authz* until the CA marks it valid.

    Raises ``TLSError`` when the CA rejects the challenge, or when it stays
    pending past *timeout*. Without a deadline one stuck order would pin the
    ACME worker thread and silently stop every later renewal.
    """
    deadline = time.monotonic() + timeout
    while True:
        # ``ClientV2.poll`` returns (AuthorizationResource, Response).
        updated, _response = net.poll(authz)
        # acme 5.x reports the status as a ``Status`` enum member rather than
        # a str, so a comparison against the bare literal never matches and the
        # waiter sleeps past a challenge the CA already accepted.
        status = updated.body.status
        if status == messages.STATUS_VALID:
            return
        if status == messages.STATUS_INVALID:
            raise TLSError(f"HTTP‑01 challenge validation failed for {domain}")
        if time.monotonic() >= deadline:
            raise TLSError(
                f"Timed out after {timeout:.0f}s waiting for {domain} authorization"
            )
        time.sleep(interval)


class ACMEToken:
    """Short-lived token for an ACME HTTP-01 challenge.

    ``token`` is the path segment the CA requests and ``response`` is the body
    it must receive there: the key authorization (``token.thumbprint``), not the
    bare token.
    """
    def __init__(self, token: str, response: str, validity: float = 3600):
        """__init__."""
        self.token = token
        self.response = response
        self.validity = validity
        self.created_at = time.time()

    @property
    def expired(self) -> bool:
        """expired."""
        return time.time() > self.created_at + self.validity


class ACMEManager:
    """Handles automated certificate issuance via ACME (Let's Encrypt/ZeroSSL)."""

    def __init__(self, manager: ConfigManager) -> None:
        """__init__."""
        self.manager = manager
        self._tokens: dict[str, ACMEToken] = {}
        self._account_key: Path | None = None

    def get_challenge_response(self, token: str) -> str | None:
        """Return the key authorization the CA expects, or ``None`` if unknown/expired."""
        t = self._tokens.get(token)
        if t is None:
            return None
        if t.expired:
            # Drop it so the store cannot grow one entry per renewal forever.
            self._tokens.pop(token, None)
            return None
        return t.response

    def set_challenge_token(self, token: str, response: str, validity: float = 3600) -> None:
        """Publish *response* (the key authorization) for the HTTP-01 *token*.

        Expired entries are dropped here rather than only on lookup: the CA
        fetches each token once, so nothing ever asks for a stale one again and
        the store would otherwise keep every renewal's key authorizations until
        the process restarts.
        """
        for stale in [key for key, item in self._tokens.items() if item.expired]:
            del self._tokens[stale]
        self._tokens[token] = ACMEToken(token, response, validity)

    def _get_account_key(self) -> Path:
        """_get_account_key."""
        config = self.manager.config
        path = config.base_dir() / ".warden" / "acme_account.key"
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            with open(path, "wb") as f:
                f.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                ))
            os.chmod(path, 0o600)
        return path

    async def request_certificate(self, domain: str, acme_url: str) -> tuple[Path, Path]:
        """Obtain a certificate for *domain* using the ACME provider at *acme_url*.

        The flow is:
        1️⃣ Load or create an account key (stored under ``.warden/acme_account.key``).
        2️⃣ Register a new ACME account (or reuse an existing one).
        3️⃣ Generate a CSR and create a new order for it (the order identifiers
           are read from the CSR).
        4️⃣ For each authorization, fulfill the HTTP‑01 challenge by storing the
           token via :meth:`set_challenge_token`. The ``ProxyEngine`` will serve the
           ``/.well-known/acme-challenge/<token>`` response.
        5️⃣ Wait until the challenge is marked *valid* by the CA.
        6️⃣ Finalize the order and download the certificate chain.
        7️⃣ Write the certificate and the private key to the paths defined in the
           configuration (``server.tls.certfile`` / ``server.tls.keyfile``).
        """
        if acme_client is None:
            raise TLSError("acme library not installed")
        # The ACME library is synchronous; we run it in a thread so the FastAPI
        # event loop stays responsive.
        return await asyncio.to_thread(self._run_acme_flow, domain, acme_url)

    def _run_acme_flow(self, domain: str, acme_url: str) -> tuple[Path, Path]:
        # Load/create the account private key.
        """_run_acme_flow."""
        account_key_path = self._get_account_key()
        with open(account_key_path, "rb") as f:
            account_key = jose.JWKRSA.load(f.read())

        # acme keeps transport (``ClientNetwork``) and protocol (``ClientV2``)
        # apart; the account key signs both.
        net = acme_client.ClientNetwork(key=account_key)
        # The directory has to be fetched explicitly: ``ClientV2`` only stores
        # the resource it is handed and never follows a URL itself.
        directory = messages.Directory.from_json(net.get(acme_url).json())
        client = acme_client.ClientV2(directory=directory, net=net)

        # Register a new account (terms‑of‑service must be agreed to).
        try:
            client.new_account(
                messages.NewRegistration.from_data(
                    email=None, terms_of_service_agreed=True
                )
            )
        except errors.ConflictError as exc:
            # The account key is reused across renewals, and a CA that already
            # knows it answers with the account URL instead of registering
            # again. Binding it makes later requests sign with its kid rather
            # than a bare JWK, which ACME only allows for ``newAccount``.
            logger.debug("ACME account already exists: %s", exc.location)
            net.account = messages.RegistrationResource(
                uri=exc.location, body=messages.Registration()
            )

        # The CSR decides which names the order covers, so it comes first.
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False,
        ).sign(private_key, hashes.SHA256())

        order = client.new_order(csr.public_bytes(serialization.Encoding.PEM))

        # Fulfil each HTTP‑01 challenge.
        for authz in order.authorizations:
            # Find the HTTP‑01 challenge.
            http_challenge = None
            for chall in authz.body.challenges:
                if isinstance(chall.chall, challenges.HTTP01):
                    http_challenge = chall
                    break
            if http_challenge is None:
                raise TLSError(f"No HTTP‑01 challenge found for {domain}")

            # ``HTTP01.token`` is the decoded payload; the CA fetches the
            # base64url encoding of it, which is what ``encode`` returns and
            # what the request path carries. Keying the store by the raw token
            # leaves nothing to match, so every challenge comes back 404.
            token = http_challenge.chall.encode("token")
            # The CA fetches /<token> and requires the key authorization there.
            key_authorization = str(http_challenge.chall.key_authorization(account_key))
            self.set_challenge_token(token, key_authorization)

            # Tell the CA we are ready for validation.
            response = http_challenge.chall.response(account_key)
            client.answer_challenge(http_challenge, response)

            # Poll the authorization until it is ``valid``.
            _wait_for_authorization(client, authz, domain)

        # Finalise the order and wait for the certificate.
        # ``finalize_order`` compares the deadline with a naive local
        # ``datetime.now()``, so an aware value raises TypeError.
        finalized = client.finalize_order(
            order, deadline=datetime.now() + timedelta(seconds=ACME_AUTHZ_TIMEOUT)
        )

        # The certificate chain is returned as PEM.
        cert_pem = finalized.fullchain_pem

        # Write cert and key to the configured locations.
        config = self.manager.config
        cert_path = config.certfile_path
        key_path = config.keyfile_path
        if not cert_path or not key_path:
            raise TLSError("TLS certfile/keyfile not configured in warden.yaml")
        cert_path.parent.mkdir(parents=True, exist_ok=True)
        key_path.parent.mkdir(parents=True, exist_ok=True)
        cert_path.write_text(cert_pem)
        key_path.write_text(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode("utf-8")
        )
        os.chmod(key_path, 0o600)
        logger.info("Obtained ACME certificate for %s", domain)
        return cert_path, key_path

@dataclass(slots=True)
class CertificateInfo:
    """CertificateInfo."""
    path: Path
    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    days_left: float
    sans: list[str]

    @property
    def expired(self) -> bool:
        """expired."""
        return self.days_left <= 0

    def as_dict(self) -> dict[str, Any]:
        """as_dict."""
        return {
            "path": str(self.path),
            "subject": self.subject,
            "issuer": self.issuer,
            "not_before": self.not_before.timestamp(),
            "not_after": self.not_after.timestamp(),
            "days_left": round(self.days_left, 1),
            "sans": self.sans,
            "expired": self.expired,
        }


def read_certificate(path: str | Path) -> CertificateInfo:
    """read_certificate."""
    cert_path = Path(path)
    try:
        raw = cert_path.read_bytes()
    except OSError as exc:
        raise TLSError(f"Could not read certificate {cert_path}: {exc}") from exc
    try:
        certificate = x509.load_pem_x509_certificate(raw)
    except ValueError as exc:
        raise TLSError(f"Could not parse PEM certificate {cert_path}.") from exc
    try:
        not_after = certificate.not_valid_after_utc
        not_before = certificate.not_valid_before_utc
    except AttributeError:
        not_after = certificate.not_valid_after.replace(tzinfo=UTC)
        not_before = certificate.not_valid_before.replace(tzinfo=UTC)
    sans: list[str] = []
    try:
        extension = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = extension.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        # No SubjectAlternativeName extension, continue without SANs
        pass
    now = datetime.now(UTC)
    days_left = (not_after - now).total_seconds() / 86400
    return CertificateInfo(
        path=cert_path,
        subject=certificate.subject.rfc4514_string(),
        issuer=certificate.issuer.rfc4514_string(),
        not_before=not_before,
        not_after=not_after,
        days_left=days_left,
        sans=sans,
    )


def certificate_status(config: WardenConfig) -> dict[str, Any]:
    """certificate_status."""
    tls = config.server.tls
    status: dict[str, Any] = {
        "enabled": tls.enabled,
        "configured": bool(tls.certfile and tls.keyfile),
        "ok": False,
        "error": None,
        "path": str(config.certfile_path) if config.certfile_path else None,
        "renew_command": bool(tls.renew_command),
        "certificate": None,
    }
    if not tls.enabled:
        return status
    if not config.certfile_path:
        status["error"] = "No certificate file configured."
        return status
    try:
        info = read_certificate(config.certfile_path)
    except TLSError as exc:
        status["error"] = str(exc)
        return status
    status["ok"] = not info.expired
    status["certificate"] = info.as_dict()
    return status


def _public_key_bytes(key: Any) -> bytes:
    """Return a public key as DER, so two keys can be compared across types."""
    return key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def validate_runtime_files(config: WardenConfig) -> None:
    """Fail fast when TLS files are missing, unreadable, or inconsistent.

    A readable but unusable key (garbage, passphrase-protected, or the key from
    another certificate) used to pass this check and only fail during the TLS
    handshake, which for a reverse proxy means every site behind it is down.
    """
    if not config.server.tls.enabled:
        return
    certfile = config.certfile_path
    keyfile = config.keyfile_path
    if not certfile or not keyfile:
        raise TLSError("TLS is enabled but certfile/keyfile are not configured.")
    if not certfile.exists():
        raise TLSError(f"TLS certificate not found: {certfile}")
    if not keyfile.exists():
        raise TLSError(f"TLS private key not found: {keyfile}")
    read_certificate(certfile)
    try:
        key_bytes = keyfile.read_bytes()
    except OSError as exc:
        raise TLSError(f"Could not read TLS private key {keyfile}: {exc}") from exc
    try:
        private_key = serialization.load_pem_private_key(key_bytes, password=None)
    except TypeError as exc:
        # ``cryptography`` raises TypeError when a passphrase is required.
        raise TLSError(
            f"TLS private key {keyfile} is passphrase-protected; Warden cannot "
            "load it unattended. Use an unencrypted key for the listener."
        ) from exc
    except ValueError as exc:
        raise TLSError(f"Could not parse TLS private key {keyfile}.") from exc
    certificate = x509.load_pem_x509_certificate(certfile.read_bytes())
    if _public_key_bytes(certificate.public_key()) != _public_key_bytes(
        private_key.public_key()
    ):
        raise TLSError(
            f"TLS private key {keyfile} does not match the certificate {certfile}."
        )


async def renewal_loop(app: Any) -> None:
    """Periodically inspect the cert and run the configured renewal command."""
    manager: ConfigManager = app.state.manager
    app.state.cert_renewal = None
    await asyncio.sleep(15)
    while True:
        config = manager.config
        tls = config.server.tls
        if not (tls.enabled and (tls.renew_command or tls.acme_directory)):
            return
        try:
            status = certificate_status(config)
            info = status.get("certificate")
            due = info is None or float(info.get("days_left", 999)) <= tls.renew_days_before
            if due:
                await _run_renewal(app, config)
        except Exception:
            logger.exception("Certificate renewal check failed")
        interval = max(1, tls.check_interval_hours) * 3600
        await asyncio.sleep(interval)


async def _run_renewal(app: Any, config: WardenConfig) -> None:
    """Renew in-process via ACME when configured, otherwise run ``renew_command``."""
    tls = config.server.tls
    started = time.time()
    if tls.acme_directory:
        domain = tls.acme_domain or config.server.admin_host
        logger.info("Certificate renewal due; requesting %s from %s", domain, tls.acme_directory)
        try:
            cert_path, _key_path = await app.state.acme_manager.request_certificate(
                domain, tls.acme_directory
            )
        except Exception as exc:  # noqa: BLE001
            app.state.cert_renewal = {
                "ok": False,
                "command": None,
                "acme_directory": tls.acme_directory,
                "output": str(exc),
                "timestamp": started,
                "restart_required": False,
            }
            logger.warning("ACME certificate request failed: %s", exc)
            return
        app.state.cert_renewal = {
            "ok": True,
            "command": None,
            "acme_directory": tls.acme_directory,
            "output": str(cert_path),
            "timestamp": started,
            "restart_required": True,
        }
        logger.info(
            "Obtained a certificate for %s at %s. Restart Warden to serve it.",
            domain,
            cert_path,
        )
        return
    command = tls.renew_command
    if not command:
        return
    logger.info("Certificate renewal due; running configured renewal command")
    try:
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=str(config.base_dir()),
        )
        try:
            output, _ = await asyncio.wait_for(process.communicate(), timeout=600)
        except TimeoutError:
            process.kill()
            await process.wait()
            raise TLSError("Renewal command timed out after 10 minutes.")
        text = output.decode("utf-8", "replace").strip()
        result = {
            "ok": process.returncode == 0,
            "command": command,
            "output": text[-4000:],
            "timestamp": started,
            "restart_required": process.returncode == 0,
        }
        app.state.cert_renewal = result
        if process.returncode == 0:
            logger.info("Certificate renewal command succeeded. Restart Warden to serve the new certificate.")
        else:
            logger.warning("Certificate renewal command failed with exit code %s", process.returncode)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:  # noqa: BLE001
        app.state.cert_renewal = {
            "ok": False,
            "command": command,
            "output": str(exc),
            "timestamp": started,
            "restart_required": False,
        }
        logger.warning("Certificate renewal failed: %s", exc)
