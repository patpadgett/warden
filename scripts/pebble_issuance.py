#!/usr/bin/env python3
"""End-to-end ACME issuance check against a local Pebble CA.

This runs the real issuance path with nothing mocked, so it covers what the unit
tests cannot: the key authorization Pebble actually fetches over HTTP-01, the
order it finalizes, and the certificate chain Warden writes to disk.

The script:

1. finds a Pebble binary (``--pebble``, ``$PEBBLE_BIN``, or the download cache)
   and fetches the pinned release on first use;
2. generates a throwaway CA for Pebble's own HTTPS directory, plus the
   short-lived self-signed placeholder ``warden serve`` needs to boot;
   ``warden certs bootstrap`` writes a one-year certificate and
   ``renew_days_before`` caps at 90, so its placeholder would never come due
   inside a two-minute check;
3. starts Pebble and ``warden serve`` on free ports with a scratch config;
4. waits for the renewal loop, then asserts the certificate is issued by
   Pebble, the chain carries the intermediate, the CA fetched the challenge
   (a 200 in the access log), and Warden logged its restart notice;
5. stops both processes, keeping the scratch directory for inspection when a
   check fails.

Usage::

    python scripts/pebble_issuance.py              # download once, run, clean up
    python scripts/pebble_issuance.py --keep       # keep the scratch directory
    python scripts/pebble_issuance.py --pebble ./pebble

The first run needs network access for the binary download, and every run needs
four free loopback ports. Run it from a checkout with the project's virtualenv
interpreter; see ROADMAP.md §2 for why this exists.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import platform
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

REPO = Path(__file__).resolve().parents[1]
PEBBLE_VERSION = "v2.10.3"
CHALLENGE_RE = re.compile(r'acme-challenge/\S+ HTTP/1\.1" 200')
RESTART_RE = re.compile(r"Restart Warden to serve it\.")
PROBE_LINE = "-" * 68


class PebbleCheckError(RuntimeError):
    """A step of the check failed; the message says which."""


@dataclass(frozen=True, slots=True)
class Ports:
    """Loopback ports for one run: Pebble's two listeners and Warden's two."""

    pebble_directory: int
    pebble_management: int
    warden_http: int
    warden_https: int


def log(message: str) -> None:
    """Print a progress line, flushed so a long run reports as it goes."""
    print(message, flush=True)


def free_port() -> int:
    """Reserve and release a loopback port, returning the number."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _target_asset() -> str:
    """Return the Pebble release asset for this platform, or raise."""
    system = platform.system().lower()
    machine = platform.machine().lower()
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(machine)
    if system not in {"linux", "darwin"} or arch is None:
        raise PebbleCheckError(
            f"no Pebble binary is published for {system}/{machine}; pass --pebble PATH"
        )
    return f"pebble-{system}-{arch}.tar.gz"


def _download_pebble(cache_dir: Path) -> Path:
    """Download and extract the pinned Pebble release into *cache_dir*."""
    asset = _target_asset()
    url = (
        f"https://github.com/letsencrypt/pebble/releases/download/{PEBBLE_VERSION}/{asset}"
    )
    cache_dir.mkdir(parents=True, exist_ok=True)
    archive = cache_dir / asset
    if not archive.exists():
        log(f"downloading {url}")
        try:
            with urllib.request.urlopen(url, timeout=60) as response:
                archive.write_bytes(response.read())
        except (urllib.error.URLError, OSError) as exc:
            raise PebbleCheckError(f"could not download Pebble: {exc}") from exc
    extract_dir = cache_dir / PEBBLE_VERSION
    if not extract_dir.exists():
        with tarfile.open(archive) as tar:
            try:
                tar.extractall(extract_dir, filter="data")
            except TypeError:  # Python < 3.11.4 has no extraction filter
                tar.extractall(extract_dir)
    binary = next((path for path in extract_dir.rglob("pebble") if path.is_file()), None)
    if binary is None:
        raise PebbleCheckError(f"no pebble binary inside {archive}")
    binary.chmod(0o755)
    return binary


def find_pebble(explicit: str | None, cache_dir: Path) -> Path:
    """Resolve the Pebble binary from a flag, the environment, or the cache."""
    candidate = explicit or os.environ.get("PEBBLE_BIN")
    if candidate:
        binary = Path(candidate).expanduser().resolve()
        if not binary.is_file():
            raise PebbleCheckError(f"PEBBLE_BIN/--pebble is not a file: {binary}")
        return binary
    cached = sorted(path for path in cache_dir.rglob("pebble") if path.is_file())
    if cached:
        return cached[0]
    return _download_pebble(cache_dir)


def _write_private_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    """Write *key* as an unencrypted PEM readable only by the owner."""
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)


def generate_directory_ca(tls_dir: Path) -> tuple[Path, Path, Path]:
    """Create a throwaway CA and a server certificate for Pebble's HTTPS port.

    Pebble serves its ACME directory over TLS, and the ``acme`` client verifies
    that connection with the bundle in ``$REQUESTS_CA_BUNDLE``. Generating the
    pair here keeps the run self-contained; nothing from Pebble's own test
    fixtures is needed.
    """
    tls_dir.mkdir(parents=True, exist_ok=True)
    now = datetime.now(UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Pebble Local CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )

    ca_pem = tls_dir / "pebble-ca.pem"
    cert_pem = tls_dir / "pebble-cert.pem"
    key_pem = tls_dir / "pebble-key.pem"
    ca_pem.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    cert_pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    _write_private_key(key_pem, key)
    return ca_pem, cert_pem, key_pem


def generate_placeholder_cert(tls_dir: Path, common_name: str) -> tuple[Path, Path]:
    """Write the self-signed certificate Warden must find before it can boot.

    It expires tomorrow on purpose: the renewal loop only requests a
    certificate once ``days_left`` is at or below ``renew_days_before`` (capped
    at 90 days), so a long-lived placeholder would never trigger issuance.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = tls_dir / "cert.pem"
    key_pem = tls_dir / "key.pem"
    cert_pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    _write_private_key(key_pem, key)
    return cert_pem, key_pem


def write_pebble_config(work_dir: Path, ports: Ports, cert_pem: Path, key_pem: Path) -> Path:
    """Write the Pebble config for this run and return its path."""
    config = {
        "pebble": {
            "listenAddress": f"127.0.0.1:{ports.pebble_directory}",
            "managementListenAddress": f"127.0.0.1:{ports.pebble_management}",
            "certificate": str(cert_pem),
            "privateKey": str(key_pem),
            # The port Pebble's validation authority dials for HTTP-01: Warden's
            # plain-HTTP companion.
            "httpPort": ports.warden_http,
            "tlsPort": ports.warden_https,
            "ocspResponderURL": "",
            "externalAccountBindingRequired": False,
            "domainBlocklist": ["blocked-domain.example"],
            "retryAfter": {"authz": 3, "order": 5},
            "keyAlgorithm": "ecdsa",
            "profiles": {
                "default": {
                    "description": "The profile you know and love",
                    "validityPeriod": 7776000,
                }
            },
        }
    }
    path = work_dir / "pebble-config.json"
    path.write_text(json.dumps(config, indent=2))
    return path


def write_warden_config(work_dir: Path, ports: Ports) -> Path:
    """Write the scratch ``warden.yaml`` this run serves with."""
    cert = work_dir / "tls" / "cert.pem"
    key = work_dir / "tls" / "key.pem"
    path = work_dir / "warden.yaml"
    path.write_text(
        f"""\
version: 1
server:
  admin_host: localhost
  bind: 127.0.0.1
  http_port: {ports.warden_http}
  https_port: {ports.warden_https}
  log_level: info
  health_interval_seconds: 3600
  tls:
    enabled: true
    certfile: {cert}
    keyfile: {key}
    acme_directory: https://localhost:{ports.pebble_directory}/dir
    acme_domain: localhost
    renew_days_before: 90
    check_interval_hours: 1
database:
  path: {work_dir / "warden.db"}
webauthn:
  rp_id: localhost
  rp_name: Warden Pebble
mesh:
  enabled: false
routes: []
"""
    )
    return path


def wait_for_directory(url: str, ca_pem: Path, process: subprocess.Popen, timeout: float) -> None:
    """Wait until Pebble answers its directory over TLS, or fail."""
    context = ssl.create_default_context(cafile=str(ca_pem))
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise PebbleCheckError("Pebble exited before its directory came up")
        try:
            with urllib.request.urlopen(url, timeout=2, context=context) as response:
                if response.status == 200:
                    return
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(0.2)
    raise PebbleCheckError(f"Pebble directory did not answer within {timeout:.0f}s")


def read_issuer(cert_path: Path) -> str | None:
    """Return the issuer of *cert_path*, or ``None`` while it is unreadable."""
    sys.path.insert(0, str(REPO))
    try:
        from warden.tls import TLSError, read_certificate

        return read_certificate(cert_path).issuer
    except (OSError, ImportError, TLSError):
        return None


def log_tail(path: Path, lines: int = 30) -> str:
    """Return the last *lines* of a log file, or a note that it is missing."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return f"<no {path.name}>"
    return "\n".join(text[-lines:])


def stop(process: subprocess.Popen | None, name: str) -> None:
    """Terminate *process* politely, then forcibly, and report a stuck exit."""
    if process is None or process.poll() is not None:
        return
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        log(f"{name} ignored SIGTERM; killing it")
        process.kill()
        process.wait(timeout=10)


def run_check(args: argparse.Namespace) -> int:
    """Run the whole check and return a process exit code."""
    work_dir: Path = args.work_dir
    if work_dir.exists():
        shutil.rmtree(work_dir)
    (work_dir / "tls").mkdir(parents=True)

    binary = find_pebble(args.pebble, args.cache_dir)
    log(f"pebble   {binary}")

    ports = Ports(free_port(), free_port(), free_port(), free_port())
    ca_pem, cert_pem, key_pem = generate_directory_ca(work_dir / "tls")
    pebble_config = write_pebble_config(work_dir, ports, cert_pem, key_pem)
    config = write_warden_config(work_dir, ports)

    warden_log = work_dir / "warden.log"
    pebble_log = work_dir / "pebble.log"
    cert_path = work_dir / "tls" / "cert.pem"

    pebble_process: subprocess.Popen | None = None
    warden_process: subprocess.Popen | None = None
    pebble_out = None
    warden_out = None
    failed = True
    try:
        generate_placeholder_cert(work_dir / "tls", "localhost")
        log(f"placeholder {cert_path.relative_to(REPO)} (expires tomorrow)")

        pebble_out = pebble_log.open("w")
        pebble_process = subprocess.Popen(
            [str(binary), "-config", str(pebble_config)],
            cwd=str(work_dir),
            env={**os.environ, "PEBBLE_VA_NOSLEEP": "1", "PYTHONUNBUFFERED": "1"},
            stdout=pebble_out,
            stderr=subprocess.STDOUT,
        )
        directory_url = f"https://localhost:{ports.pebble_directory}/dir"
        wait_for_directory(directory_url, ca_pem, pebble_process, timeout=30)
        log(f"pebble   {directory_url} up on port {ports.pebble_directory}")

        warden_env = {
            "PYTHONUNBUFFERED": "1",
            # The acme client verifies Pebble's directory certificate against
            # this bundle; without it the handshake fails as untrusted.
            "REQUESTS_CA_BUNDLE": str(ca_pem),
        }
        warden_out = warden_log.open("w")
        warden_process = subprocess.Popen(
            [sys.executable, "-m", "warden", "-c", str(config), "serve"],
            cwd=str(REPO),
            env={**os.environ, **warden_env},
            stdout=warden_out,
            stderr=subprocess.STDOUT,
        )
        log(f"warden   http {ports.warden_http} / https {ports.warden_https}")

        started = time.monotonic()
        issuer = None
        while time.monotonic() - started < args.timeout:
            if warden_process.poll() is not None:
                raise PebbleCheckError("warden exited before issuing a certificate")
            issuer = read_issuer(cert_path)
            if issuer and "Pebble" in issuer:
                break
            issuer = None
            time.sleep(2)
        elapsed = time.monotonic() - started

        results: list[tuple[str, bool, str]] = []
        if issuer is None:
            results.append(("issuer", False, "no Pebble-issued certificate before timeout"))
            chain_pem = ""
        else:
            results.append(("issuer", True, issuer))
            chain_pem = cert_path.read_text(encoding="utf-8", errors="replace")
        chain_length = chain_pem.count("BEGIN CERTIFICATE")
        results.append(("chain", chain_length >= 2, f"{chain_length} certificate(s)"))

        warden_text = warden_log.read_text(encoding="utf-8", errors="replace")
        fetched = CHALLENGE_RE.findall(warden_text)
        results.append(
            ("http-01", bool(fetched), f"{len(fetched)} challenge fetch(es) answered 200")
        )
        results.append(
            ("restart", bool(RESTART_RE.search(warden_text)), "restart notice logged")
        )

        failed = not all(ok for _name, ok, _detail in results)
        log("")
        log(f"=== Pebble issuance  (ports {ports.pebble_directory}/{ports.warden_http})")
        for name, ok, detail in results:
            log(f"  {'PASS' if ok else 'FAIL'}  {name:<8} {detail}")
        log(f"  issued in {elapsed:.1f}s")
        if failed:
            log(PROBE_LINE)
            log("--- warden.log")
            log(log_tail(warden_log))
            log("--- pebble.log")
            log(log_tail(pebble_log))
    except PebbleCheckError as exc:
        failed = True
        log(f"FAIL {exc}")
        log(PROBE_LINE)
        log("--- warden.log")
        log(log_tail(warden_log))
        log("--- pebble.log")
        log(log_tail(pebble_log))
    finally:
        stop(warden_process, "warden")
        stop(pebble_process, "Pebble")
        for handle in (warden_out, pebble_out):
            if handle is not None:
                handle.close()
        if failed or args.keep:
            log(f"scratch directory kept: {work_dir}")
        else:
            shutil.rmtree(work_dir, ignore_errors=True)
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    """Parse arguments and run the check."""
    parser = argparse.ArgumentParser(
        description="Run real ACME issuance against a local Pebble CA.",
    )
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=REPO / "tmp" / "pebble-check",
        help="scratch directory for this run (default: tmp/pebble-check)",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=REPO / "tmp" / "pebble-cache",
        help="where the downloaded Pebble release is cached (default: tmp/pebble-cache)",
    )
    parser.add_argument(
        "--pebble",
        default=None,
        help="path to a Pebble binary (default: $PEBBLE_BIN, then the cache)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=120.0,
        help="seconds to wait for issuance after Warden starts (default: 120)",
    )
    parser.add_argument(
        "--keep",
        action="store_true",
        help="keep the scratch directory even when every check passes",
    )
    args = parser.parse_args(argv)
    try:
        return run_check(args)
    except PebbleCheckError as exc:
        log(f"FAIL {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
