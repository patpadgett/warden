"""Command line interface for Warden."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import logging.handlers
import os
import re
import signal
import sqlite3
import sys
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import uvicorn
from starlette.responses import PlainTextResponse, Response

from warden import __version__
from warden.config import ConfigError, ConfigManager, WardenConfig, parse_config_text
from warden.db import Database, DatabaseError
from warden.main import create_app
from warden.mesh import MeshManager
from warden.mesh_peer import MeshError
from warden.tls import (
    TLSError,
    certificate_status,
    generate_self_signed_cert,
    validate_runtime_files,
)
from warden.utils import apply_security_headers, get_host

logger = logging.getLogger("warden.cli")
_ACME_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")

DEFAULT_CONFIG = "warden.yaml"

INIT_TEMPLATE = """\
# Warden configuration
# See README.md for every option. Hosts must resolve to this machine.

version: 1

server:
  admin_host: {admin_host}
  bind: {bind}
  http_port: {http_port}
  https_port: {https_port}
  session_ttl_hours: 168
  # Forward the signed-in username to protected upstreams as X-Warden-User.
  forward_user_header: X-Warden-User
  # tls:
  #   enabled: true
  #   certfile: /etc/letsencrypt/live/{cert_host}/fullchain.pem
  #   keyfile: /etc/letsencrypt/live/{cert_host}/privkey.pem
  #   acme_webroot: /var/www/warden-acme
  #   renew_command: certbot renew --quiet
  #   renew_days_before: 30

database:
  path: {database}

webauthn:
  rp_id: {rp_id}
  rp_name: Warden
  # Set require_user_verification to true to force a PIN/biometric check.
  require_user_verification: false
  # Add another origin only if you deliberately sign in from a second host.
  allowed_origins: []

mesh:
  enabled: false
  interface: wg0
  address: 10.44.0.1/24
  listen_port: 51820
  # endpoint: vpn.example.com:51820
  # config_path: /etc/wireguard/wg0.conf

# Every route is a hostname Warden answers for. Remove the brackets to add one.
routes: []
# routes:
#   - host: app.{rp_id}
#     upstream: http://192.168.1.20:3000
#     name: App
#     auth: true
#     websocket: true
#     health_path: /
"""


# --------------------------------------------------------------------- helpers
def _config_path(args: argparse.Namespace) -> Path:
    """Resolve the configuration file path.

    Checks ``args.config``, the ``WARDEN_CONFIG`` environment variable, and falls back
    to ``DEFAULT_CONFIG``. Returns an absolute ``Path``.
    """
    raw = getattr(args, "config", None) or os.environ.get("WARDEN_CONFIG") or DEFAULT_CONFIG
    return Path(raw).expanduser().resolve()


def _load_manager(args: argparse.Namespace) -> ConfigManager:
    """Load a ``ConfigManager`` from the resolved configuration file.

    Calls :func:`_config_path` and then ``ConfigManager.from_file``.
    """
    return ConfigManager.from_file(_config_path(args))


def _configure_logging(level: str, log_file: str | None = None, log_rotation: str = "size", log_max_size_mb: int = 10, log_backup_count: int = 5) -> None:
    """Configure the root logger based on a textual log level.

    Accepts standard ``logging`` level names (e.g., ``INFO``, ``DEBUG``). If the
    level is unrecognised, defaults to ``INFO``.

    When ``log_file`` is provided, logs are also written to that file with
    rotation enabled.
    """
    numeric = getattr(logging, str(level).upper(), logging.INFO)
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if log_file:
        max_bytes = max(1024 * 1024, log_max_size_mb * 1024 * 1024)
        if log_rotation == "time":
            file_handler = logging.handlers.TimedRotatingFileHandler(
                log_file,
                when="midnight",
                backupCount=log_backup_count,
            )
        else:
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=max_bytes,
                backupCount=log_backup_count,
            )
        file_handler.setFormatter(logging.Formatter("%(asctime)s  %(levelname)-7s %(name)s · %(message)s"))
        handlers.append(file_handler)
    logging.basicConfig(
        level=numeric,
        format="%(asctime)s  %(levelname)-7s %(name)s · %(message)s",
        datefmt="%H:%M:%S",
        handlers=handlers,
    )


def _print_error(message: str) -> None:
    """Print an error message to ``stderr`` prefixed with ``warden:``.

    Used for user‑visible errors before exiting.
    """
    print(f"warden: {message}", file=sys.stderr)


def _human_time(timestamp: float | None) -> str:
    """Format a timestamp (seconds since epoch) as a human‑readable date/time string.

    Returns ``"never"`` if ``timestamp`` is falsy.
    """
    if not timestamp:
        return "never"
    return datetime.fromtimestamp(float(timestamp)).strftime("%Y-%m-%d %H:%M")


def _human_bytes(value: float) -> str:
    """Human‑readable byte size with appropriate unit (B, KB, …).

    Mirrors the implementation from ``warden.utils.humanize_bytes`` but used for CLI output.
    """
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


async def _confirm(question: str, assume_yes: bool) -> bool:
    """Prompt the user for confirmation.

    * If ``assume_yes`` is true, automatically returns ``True``.
    * In a non‑interactive environment (no TTY), prints an error and returns ``False``.
    * Otherwise reads input from stdin and returns ``True`` for ``y``/``yes``.
    """
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        _print_error("refusing to continue without --yes in a non-interactive shell")
        return False
    answer = await asyncio.to_thread(input, f"{question} [y/N] ")
    return answer.strip().lower() in {"y", "yes"}


# ----------------------------------------------------------------------- serve
class HttpsRedirectApp:
    """Serve ACME challenges on plain HTTP and send everything else to HTTPS."""

    def __init__(self, manager: ConfigManager, acme_manager: Any | None = None) -> None:
        """__init__."""
        self.manager = manager
        self.acme_manager = acme_manager

    def _acme_file(self, path: str) -> Path | None:
        """_acme_file."""
        root = self.manager.config.acme_webroot_path
        if root is None or not path.startswith("/.well-known/acme-challenge/"):
            return None
        token = path.rsplit("/", 1)[-1]
        if not _ACME_TOKEN_RE.match(token):
            return None
        try:
            resolved_root = root.resolve()
            target = (resolved_root / token).resolve()
        except OSError:
            return None
        if resolved_root not in target.parents:
            return None
        return target

    def _location(self, scope: dict[str, Any]) -> str | None:
        """Build the HTTPS target, or ``None`` for a host Warden does not serve.

        The plain-HTTP listener answers any ``Host`` header, so echoing that
        header into ``Location`` turns an exposed HTTP port into an open
        redirect. Only the admin host and hosts with a configured route are
        redirected; anything else is rejected.
        """
        config = self.manager.config
        host = get_host(scope)
        if host != config.server.admin_host and config.match_route(host) is None:
            return None
        path = scope.get("raw_path") or scope.get("path", "/")
        if isinstance(path, bytes):
            path = path.decode("latin-1")
        if not path.startswith("/"):
            path = "/" + path
        query = scope.get("query_string", b"").decode("latin-1")
        public = config.server.public_url
        if public:
            parts = urlsplit(public)
            port = parts.port or 443
            port_suffix = "" if port == 443 else f":{port}"
            location = f"https://{host}{port_suffix}{path}"
        else:
            port = config.server.https_port
            port_suffix = "" if port == 443 else f":{port}"
            location = f"https://{host}{port_suffix}{path}"
        if query:
            location += f"?{query}"
        return location

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        """__call__."""
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        if scope["type"] != "http":
            return
        path = scope.get("path", "/")
        target = self._acme_file(path)
        if target is not None:
            try:
                content = target.read_text(encoding="utf-8").strip()
            except OSError:
                response: Response = PlainTextResponse("Not found", status_code=404)
            else:
                response = PlainTextResponse(content)
        elif path.startswith("/.well-known/acme-challenge/"):
            token = path.rsplit("/", 1)[-1]
            content = None
            if self.acme_manager is not None and _ACME_TOKEN_RE.match(token):
                content = self.acme_manager.get_challenge_response(token)
            if content is None:
                response = PlainTextResponse("Not found", status_code=404)
            else:
                response = PlainTextResponse(content)
        else:
            location = self._location(scope)
            if location is None:
                response = PlainTextResponse("Unknown host", status_code=404)
            else:
                response = Response(status_code=308)
                response.headers["Location"] = location
                response.headers["Cache-Control"] = "no-store"
        apply_security_headers(response)
        await response(scope, receive, send)


def _uvicorn_config(
    app: Any,
    *,
    host: str,
    port: int,
    config: WardenConfig,
    access_log: bool,
    lifespan: str = "auto",
    use_tls: bool = True,
) -> uvicorn.Config:
    """_uvicorn_config."""
    tls = config.server.tls
    ssl_kwargs: dict[str, Any] = {}
    if tls.enabled and use_tls:
        ssl_kwargs["ssl_certfile"] = str(config.certfile_path)
        ssl_kwargs["ssl_keyfile"] = str(config.keyfile_path)
    return uvicorn.Config(
        app,
        host=host,
        port=port,
        log_level=config.server.log_level,
        access_log=access_log,
        lifespan=lifespan,
        proxy_headers=config.server.trust_proxy_headers,
        forwarded_allow_ips="*" if config.server.trust_proxy_headers else None,
        server_header=False,
        timeout_graceful_shutdown=10,
        **ssl_kwargs,
    )


async def _run_single(app: Any, config: WardenConfig, host: str, port: int, access_log: bool) -> None:
    """_run_single."""
    server = uvicorn.Server(_uvicorn_config(app, host=host, port=port, config=config, access_log=access_log))
    await server.serve()


async def _run_dual(app: Any, config: WardenConfig, host: str, access_log: bool) -> None:
    """_run_dual."""
    https_server = uvicorn.Server(
        _uvicorn_config(
            app,
            host=host,
            port=config.server.https_port,
            config=config,
            access_log=access_log,
        )
    )
    redirect = HttpsRedirectApp(
        app.state.manager, getattr(app.state, "acme_manager", None)
    )
    http_server = uvicorn.Server(
        _uvicorn_config(
            redirect,
            host=host,
            port=config.server.http_port,
            config=config,
            access_log=access_log,
            lifespan="off",
            use_tls=False,
        )
    )
    # The TLS listener owns the lifespan and signal handling; the plain HTTP
    # listener is a small companion that only serves ACME and redirects.
    https_server.capture_signals = contextlib.nullcontext
    http_server.capture_signals = contextlib.nullcontext

    loop = asyncio.get_running_loop()

    def stop(*_: Any) -> None:
        """stop."""
        https_server.should_exit = True
        http_server.should_exit = True

    installed: list[int] = []
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop)
            installed.append(sig)
        except (NotImplementedError, RuntimeError):
            pass
    tasks = [
        asyncio.create_task(https_server.serve(), name="warden-https"),
        asyncio.create_task(http_server.serve(), name="warden-http"),
    ]
    try:
        _done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        https_server.should_exit = True
        http_server.should_exit = True
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for task, result in zip(tasks, results):
            if isinstance(result, BaseException) and not isinstance(result, asyncio.CancelledError):
                raise result
    finally:
        for sig in installed:
            with contextlib.suppress(NotImplementedError, RuntimeError):
                loop.remove_signal_handler(sig)


def cmd_serve(args: argparse.Namespace) -> int:
    """Run the proxy server."""
    try:
        manager = _load_manager(args)
    except ConfigError as exc:
        _print_error(exc.pretty())
        return 1
    config = manager.config
    # Dev TLS mode: generate a temporary self‑signed certificate if requested.
    if getattr(args, "dev_tls", False):
        # Use a deterministic location under --tls-dir for dev files.
        dev_dir = Path(args.tls_dir).expanduser()
        dev_dir.mkdir(parents=True, exist_ok=True)
        try:
            # The directory holds a private key; keep other users out of it.
            os.chmod(dev_dir, 0o700)
        except OSError:
            pass
        cert_path = dev_dir / "cert.pem"
        key_path = dev_dir / "key.pem"
        if not cert_path.is_file() or not key_path.is_file():
            # Generate a self-signed cert using the admin host as the CN.
            from warden.tls import generate_self_signed_cert

            generate_self_signed_cert(cert_path, key_path, common_name=config.server.admin_host)
        # Enable TLS in the runtime configuration without persisting to file.
        config.server.tls.enabled = True
        config.server.tls.certfile = str(cert_path)
        config.server.tls.keyfile = str(key_path)
    try:
        validate_runtime_files(config)
    except TLSError as exc:
        _print_error(str(exc))
        return 1
    _configure_logging(
        config.server.log_level,
        log_file=config.server.log_file,
        log_rotation=config.server.log_rotation,
        log_max_size_mb=config.server.log_max_size_mb,
        log_backup_count=config.server.log_backup_count,
    )
    host = args.host or config.server.bind
    app = create_app(manager.path, config=config)
    try:
        if config.server.tls.enabled:
            port = args.https_port or config.server.https_port
            # Keep the manager's live config coherent with a CLI override.
            config.server.https_port = port
            if args.port:
                config.server.http_port = args.port
            with _serve_manager(manager):
                asyncio.run(_run_dual(app, config, host, not args.no_access_log))
        else:
            port = args.port or config.server.http_port
            config.server.http_port = port
            with _serve_manager(manager):
                asyncio.run(_run_single(app, config, host, port, not args.no_access_log))
    except KeyboardInterrupt:
        return 130
    except OSError as exc:
        _print_error(f"could not start the listener: {exc}")
        return 1
    return 0


@contextlib.contextmanager
def _serve_manager(manager: ConfigManager):
    # Reserved for future serve-time resource coordination. Keeping the path
    # explicit makes the config file visible in error messages.
    """_serve_manager."""
    assert manager.path is not None
    yield manager


# ------------------------------------------------------------------------ init
def cmd_init(args: argparse.Namespace) -> int:
    """Write starter warden.yaml."""
    output = Path(args.output).expanduser().resolve()
    if output.exists() and not args.force:
        _print_error(f"{output} already exists (use --force to overwrite)")
        return 1
    admin_host = args.admin_host.strip().lower()
    rp_id = (args.rp_id or admin_host).strip().lower()
    database = args.database
    cert_host = rp_id
    text = INIT_TEMPLATE.format(
        admin_host=admin_host,
        rp_id=rp_id,
        bind=args.bind,
        http_port=args.port,
        https_port=args.https_port,
        database=database,
        cert_host=cert_host,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        parse_config_text(text, base_dir=output.parent, source=str(output))
    except ConfigError as exc:
        _print_error(exc.pretty())
        return 1
    temp = output.with_name(f".{output.name}.tmp")
    try:
        temp.write_text(text, encoding="utf-8")
        os.chmod(temp, 0o600)
        os.replace(temp, output)
        manager = ConfigManager.from_file(output)
    except (OSError, ConfigError) as exc:
        temp.unlink(missing_ok=True)
        _print_error(str(exc))
        return 1
    print(f"wrote {output}")
    print(f"admin host  {manager.config.server.admin_host}")
    print(f"webauthn    {manager.config.webauthn.rp_id}")
    print(f"database    {manager.config.database_path}")
    print()
    print("Next:")
    print(f"  1. Point {manager.config.server.admin_host} at this machine.")
    print("  2. Start Warden with: warden serve")
    print("  3. Open the dashboard and claim it with the printed setup code.")
    return 0


# ----------------------------------------------------------------------- check
def _sqlite_problems(path: Path) -> list[str]:
    """Return problems opening *path* as a SQLite database, read-only.

    ``warden check`` validated the YAML and TLS files but never opened the
    database, so a corrupt or non-database file still printed "valid" — which
    is exactly when an operator runs it.
    """

    if not path.exists():
        # A missing database is normal: startup creates it.
        return []
    try:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            connection.execute("PRAGMA schema_version").fetchone()
            result = connection.execute("PRAGMA quick_check").fetchone()
        finally:
            connection.close()
    except sqlite3.Error as exc:
        return [f"Database {path} is not a usable SQLite file: {exc}"]
    if result and result[0] != "ok":
        return [f"Database {path} failed SQLite's integrity check: {result[0]}"]
    return []


def cmd_check(args: argparse.Namespace) -> int:
    """Validate config and paths."""
    try:
        manager = _load_manager(args)
    except ConfigError as exc:
        if args.json:
            print(json.dumps({"ok": False, "error": exc.message, "errors": exc.errors}, indent=2))
        else:
            _print_error(exc.pretty())
        return 1
    config = manager.config
    tls = certificate_status(config)
    problems: list[str] = []
    try:
        validate_runtime_files(config)
    except TLSError as exc:
        problems.append(str(exc))
    db_path = config.database_path if config.database.type != "postgres" else None
    if db_path is not None:
        problems.extend(_sqlite_problems(Path(db_path)))
    db_display = (
        config.database.url if config.database.type == "postgres" else str(db_path)
    )
    mesh_path = config.mesh_config_path
    report = {
        "ok": not problems,
        "version": __version__,
        "config": str(manager.path),
        "admin_host": config.server.admin_host,
        "database": db_display,
        "database_type": config.database.type,
        "routes": len(config.routes),
        "tls": tls,
        "webauthn_rp_id": config.webauthn.rp_id,
        "cookie_domain": config.server.cookie_domain,
        "mesh_enabled": config.mesh.enabled,
        "mesh_config": str(mesh_path) if mesh_path else None,
        "problems": problems,
    }
    if args.json:
        print(json.dumps(report, indent=2, default=str))
        return 0 if report["ok"] else 1
    print(f"Warden {__version__}")
    print(f"  config      {manager.path}")
    print(f"  admin       {config.server.admin_host}")
    print(f"  database    {db_display}")
    print(f"  routes      {len(config.routes)}")
    print(f"  rp id       {config.webauthn.rp_id}")
    print(f"  cookie      {config.server.cookie_domain or 'host-only'}")
    if tls["enabled"]:
        if tls.get("certificate"):
            info = tls["certificate"]
            print(
                f"  tls         valid · {int(info['days_left'])} days left · "
                f"expires {_human_time(info['not_after'])}"
            )
        else:
            print(f"  tls         enabled, but {tls.get('error') or 'unreadable'}")
    else:
        print("  tls         disabled (plain HTTP)")
    if config.mesh.enabled:
        print(f"  mesh        {config.mesh.interface} · {config.mesh.address}")
    else:
        print("  mesh        disabled")
    if problems:
        print()
        for problem in problems:
            print(f"  ✗ {problem}")
        return 1
    print()
    print("  ✓ configuration is valid")
    return 0


# ----------------------------------------------------------------------- certs
def cmd_certs(args: argparse.Namespace) -> int:
    """Inspect or renew TLS."""
    try:
        manager = _load_manager(args)
    except ConfigError as exc:
        _print_error(exc.pretty())
        return 1
    config = manager.config
    if args.action == "status":
        status = certificate_status(config)
        if args.json:
            print(json.dumps(status, indent=2, default=str))
            return 0
        if not status["enabled"]:
            print("TLS is disabled in warden.yaml.")
            return 0
        if not status["configured"]:
            print("TLS is enabled but certfile/keyfile are missing.")
            return 1
        if not status["certificate"]:
            _print_error(status.get("error") or "could not read certificate")
            return 1
        info = status["certificate"]
        print(f"certificate  {info['path']}")
        print(f"subject      {info['subject']}")
        print(f"issuer       {info['issuer']}")
        print(f"valid from   {_human_time(info['not_before'])}")
        print(f"valid until  {_human_time(info['not_after'])}")
        print(f"days left    {info['days_left']}")
        print(f"sans         {', '.join(info['sans']) or '—'}")
        print(f"renew hook   {'configured' if status['renew_command'] else 'not configured'}")
        if info["expired"]:
            print()
            print("The certificate has expired. Renew it and restart Warden.")
            return 1
        return 0

    if args.action == "bootstrap":
        # A self-signed placeholder only exists so the process can boot: TLS
        # startup refuses to run without a readable certificate, and HTTP-01
        # validation happens over plain HTTP, so the CA never sees this one.
        tls = config.server.tls
        if not tls.enabled:
            _print_error("TLS is disabled in warden.yaml")
            return 1
        cert_path = config.certfile_path
        key_path = config.keyfile_path
        if cert_path is None or key_path is None:
            _print_error("TLS is enabled but certfile/keyfile are not configured.")
            return 1
        existing = [path for path in (cert_path, key_path) if path.exists()]
        if existing and not args.force:
            _print_error(f"{existing[0]} already exists; pass --force to replace it")
            return 1
        name = tls.acme_domain or config.server.admin_host
        generate_self_signed_cert(cert_path, key_path, common_name=name)
        print(f"certificate  {cert_path}")
        print(f"key          {key_path}")
        print(f"subject      CN={name} (self-signed placeholder)")
        print()
        print(
            "Browsers will not trust this certificate. It lets Warden start and "
            "serve the HTTP-01 challenge while ACME issues the real one; the CA "
            "still has to reach Warden's plain HTTP port."
        )
        return 0

    # renew
    tls = config.server.tls
    if not tls.enabled:
        _print_error("TLS is disabled in warden.yaml")
        return 1
    if not tls.renew_command:
        _print_error("no tls.renew_command is configured")
        return 1
    if args.dry_run:
        print(tls.renew_command)
        return 0
    return asyncio.run(_renew_now(manager, tls.renew_command))


async def _renew_now(manager: ConfigManager, command: str) -> int:
    """_renew_now."""
    print(f"running: {command}")
    try:
        process = await asyncio.create_subprocess_shell(
            command,
            cwd=str(manager.config.base_dir()),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
    except OSError as exc:
        _print_error(f"could not run renewal command: {exc}")
        return 1
    try:
        output, _ = await asyncio.wait_for(process.communicate(), timeout=600)
    except TimeoutError:
        process.kill()
        await process.wait()
        _print_error("renewal command timed out after 10 minutes")
        return 1
    text = output.decode("utf-8", "replace").strip()
    if text:
        print(text)
    if process.returncode != 0:
        _print_error(f"renewal command exited with {process.returncode}")
        return 1
    print()
    print("Renewal command finished. Restart Warden to load the new certificate.")
    return 0


# ------------------------------------------------------------------------ database
def _open_database(config: WardenConfig) -> Database:
    """Open the configured database backend (SQLite or PostgreSQL)."""
    if config.database.type == "postgres":
        try:
            from warden.db_postgres import PostgresDatabase
        except ImportError as exc:  # pragma: no cover - depends on optional extra
            raise DatabaseError(
                "PostgreSQL support requires the optional dependencies. "
                "Install Warden with: pip install 'warden-mesh[postgres]'"
            ) from exc
        url = config.database.url or "postgresql+asyncpg://localhost/warden"
        return PostgresDatabase(url)
    return Database(config.database_path)


# ------------------------------------------------------------------------ backup
def cmd_backup(args: argparse.Namespace) -> int:
    """Back up the SQLite database to a timestamped file."""
    try:
        manager = _load_manager(args)
    except ConfigError as exc:
        _print_error(exc.pretty())
        return 1
    if manager.config.database.type == "postgres":
        _print_error(
            "warden backup only supports SQLite. Use pg_dump against "
            "database.url for PostgreSQL backups."
        )
        return 1
    db_path = manager.config.database_path
    if not db_path.exists():
        _print_error(f"database not found: {db_path}")
        return 1
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_path = db_path.with_name(f"{db_path.name}.backup-{timestamp}")
    try:
        src = sqlite3.connect(str(db_path))
        dst = sqlite3.connect(str(backup_path))
        try:
            src.backup(dst)
        finally:
            dst.close()
            src.close()
        os.chmod(backup_path, 0o600)
    except (OSError, sqlite3.Error) as exc:
        _print_error(f"could not write backup {backup_path}: {exc}")
        return 1
    print(f"backup written to {backup_path}")
    return 0


# ------------------------------------------------------------------------ auth
def cmd_auth_reset(args: argparse.Namespace) -> int:
    """Reset admin account."""
    try:
        manager = _load_manager(args)
    except ConfigError as exc:
        _print_error(exc.pretty())
        return 1
    target = (
        manager.config.database.url
        if manager.config.database.type == "postgres"
        else str(manager.config.database_path)
    )
    if manager.config.database.type != "postgres" and not manager.config.database_path.exists():
        _print_error(f"database not found: {manager.config.database_path}")
        return 1
    if not asyncio.run(
        _confirm(
            f"Delete every user, passkey, and session from {target}? This cannot be undone.",
            args.yes,
        )
    ):
        return 1
    return asyncio.run(_reset_auth(manager.config))


async def _reset_auth(config: WardenConfig) -> int:
    """_reset_auth."""
    try:
        db = _open_database(config)
    except DatabaseError as exc:
        _print_error(str(exc))
        return 1
    try:
        await db.init()
        users = await db.user_count()
        await db.reset_auth()
        await db.vacuum()
        print(f"Removed {users} account{'s' if users != 1 else ''}, their passkeys, and all sessions.")
        print("Restart Warden to generate a fresh first-run setup code.")
        return 0
    except (DatabaseError, OSError, sqlite3.Error) as exc:
        _print_error(str(exc))
        return 1
    finally:
        await db.close()


# ------------------------------------------------------------------------ mesh
def _mesh_manager(args: argparse.Namespace) -> tuple[ConfigManager, Database, MeshManager]:
    """_mesh_manager."""
    manager = _load_manager(args)
    if not manager.config.mesh.enabled and args.mesh_action != "status":
        raise MeshError("WireGuard mesh is disabled in warden.yaml.")
    db = _open_database(manager.config)
    return manager, db, MeshManager(db, manager)


def cmd_mesh(args: argparse.Namespace) -> int:
    """Run mesh commands."""
    try:
        manager, db, mesh = _mesh_manager(args)
    except (ConfigError, MeshError) as exc:
        _print_error(str(exc))
        return 1

    async def _run() -> int:
        try:
            return await _mesh_command(args, manager, db, mesh)
        finally:
            # Always close the connection. An aiosqlite worker thread left
            # alive keeps the interpreter from exiting after an error, so a
            # failure here would hang the CLI instead of returning non-zero.
            await db.close()

    try:
        return asyncio.run(_run())
    except (MeshError, DatabaseError, sqlite3.Error) as exc:
        _print_error(str(exc))
        return 1


async def _mesh_command(
    args: argparse.Namespace,
    manager: ConfigManager,
    db: Database,
    mesh: MeshManager,
) -> int:
    """_mesh_command."""
    await db.init()
    try:
        return await _run_mesh(args, manager, db, mesh)
    finally:
        await db.close()


async def _run_mesh(
    args: argparse.Namespace,
    manager: ConfigManager,
    db: Database,
    mesh: MeshManager,
) -> int:
    """_run_mesh."""
    action = args.mesh_action
    if action == "status":
        if not manager.config.mesh.enabled:
            print("WireGuard mesh is disabled.")
            return 0
        status = await mesh.refresh_handshakes()
        print(f"interface   {manager.config.mesh.interface}")
        print(f"available   {'yes' if status.get('available') else 'no'}")
        print(f"applied     {'yes' if status.get('applied') else 'no'}")
        if status.get("detail"):
            print(f"detail      {status['detail']}")
        peers = await db.list_mesh_peers()
        if peers:
            print()
            for peer in peers:
                info = status.get("peers", {}).get(peer.public_key)
                handshake = _human_time(info.last_handshake if info else peer.last_handshake)
                print(f"  {peer.name:<22} {peer.address:<14} {handshake}")
        return 0

    if action == "config":
        print(await mesh.render_server_config(), end="")
        return 0

    if action == "apply":
        result = await mesh.apply()
        print(f"interface   {result.get('interface')}")
        print(f"config      {result.get('config_path')}")
        if result.get("output"):
            print(result["output"])
        print("applied.")
        return 0

    if action == "peers":
        peers = await db.list_mesh_peers()
        if not peers:
            print("No mesh peers.")
            return 0
        for peer in peers:
            print(f"{peer.name:<22} {peer.address:<14} {peer.public_key[:20]}…")
        return 0

    if action == "peer-add":
        peer = await mesh.add_peer(
            name=args.name,
            address=args.address,
            endpoint=args.endpoint,
            keepalive=args.keepalive,
        )
        print(f"created {peer.name} · {peer.address}")
        config = await mesh.render_peer_config(peer)
        if args.output:
            path = Path(args.output).expanduser().resolve()
            path.write_text(config, encoding="utf-8")
            os.chmod(path, 0o600)
            print(f"client config written to {path}")
        else:
            print()
            print(config)
        print("Run 'warden mesh apply' to put the peer on the interface.")
        return 0

    if action in {"peer-config", "peer-remove"}:
        peers = await db.list_mesh_peers()
        peer = next((item for item in peers if item.name.lower() == args.name.lower()), None)
        if peer is None:
            _print_error(f"no mesh peer named {args.name!r}")
            return 1
        if action == "peer-config":
            print(await mesh.render_peer_config(peer), end="")
            return 0
        if not await _confirm(f"Remove mesh peer {peer.name} ({peer.address})?", args.yes):
            return 1
        await db.delete_mesh_peer(peer.id)
        print(f"removed {peer.name}. Run 'warden mesh apply' to update the interface.")
        return 0

    _print_error(f"unknown mesh action: {action}")
    return 1


# ---------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    """Build argument parser."""
    parser = argparse.ArgumentParser(
        prog="warden",
        description="A quiet door for a loud homelab: passkey-protected reverse proxy.",
    )
    parser.add_argument("--version", action="version", version=f"warden {__version__}")
    parser.add_argument(
        "-c",
        "--config",
        default=None,
        help="path to warden.yaml (default: $WARDEN_CONFIG or ./warden.yaml)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="run the reverse proxy and dashboard")
    serve.add_argument("--host", default=None, help="bind address override")
    serve.add_argument("--port", type=int, default=None, help="HTTP port override")
    serve.add_argument("--https-port", type=int, default=None, help="HTTPS port override")
    serve.add_argument("--dev-tls", action="store_true", help="Generate a temporary self‑signed certificate and enable TLS for local development")
    serve.add_argument(
        "--tls-dir",
        default=".warden/dev-tls",
        help="directory for --dev-tls cert/key (default: .warden/dev-tls)",
    )
    serve.add_argument("--no-access-log", action="store_true", help="disable uvicorn access log")
    serve.set_defaults(func=cmd_serve)

    init = sub.add_parser("init", help="write a starter warden.yaml")
    init.add_argument("-o", "--output", default=DEFAULT_CONFIG, help="output path")
    init.add_argument("--admin-host", default="localhost", help="dashboard hostname")
    init.add_argument("--rp-id", default=None, help="WebAuthn RP ID (default: admin host)")
    init.add_argument("--bind", default="0.0.0.0", help="listen address")
    init.add_argument("--port", type=int, default=8080, help="HTTP port")
    init.add_argument("--https-port", type=int, default=8443, help="HTTPS port")
    init.add_argument("--database", default="warden.db", help="SQLite path")
    init.add_argument("--force", action="store_true", help="overwrite an existing file")
    init.set_defaults(func=cmd_init)

    check = sub.add_parser("check", help="validate config and runtime files")
    check.add_argument("--json", action="store_true", help="machine-readable output")
    check.set_defaults(func=cmd_check)

    config_cmd = sub.add_parser("config", help="show effective configuration")
    config_cmd.add_argument("show", nargs="?", default="show", choices=["show"], help="print config (default)")
    config_cmd.set_defaults(func=cmd_config_show)

    certs = sub.add_parser("certs", help="inspect, renew, or bootstrap the TLS certificate")
    certs.add_argument("action", choices=["status", "renew", "bootstrap"])
    certs.add_argument("--json", action="store_true", help="JSON output for status")
    certs.add_argument("--dry-run", action="store_true", help="print the renewal command only")
    certs.add_argument(
        "--force", action="store_true", help="replace an existing certificate (bootstrap)"
    )
    certs.set_defaults(func=cmd_certs)

    backup = sub.add_parser("backup", help="back up the SQLite database")
    backup.set_defaults(func=cmd_backup)

    auth = sub.add_parser("auth", help="account recovery")
    auth_sub = auth.add_subparsers(dest="auth_action", required=True)
    reset = auth_sub.add_parser("reset", help="delete the account, passkeys, and sessions")
    reset.add_argument("--yes", action="store_true", help="skip confirmation")
    reset.set_defaults(func=cmd_auth_reset)

    mesh = sub.add_parser("mesh", help="manage WireGuard peers and config")
    mesh_sub = mesh.add_subparsers(dest="mesh_action", required=True)
    mesh_status = mesh_sub.add_parser("status", help="show the interface and peers")
    mesh_status.set_defaults(func=cmd_mesh)
    mesh_config = mesh_sub.add_parser("config", help="print the hub WireGuard config")
    mesh_config.set_defaults(func=cmd_mesh)
    mesh_apply = mesh_sub.add_parser("apply", help="write and apply the hub config")
    mesh_apply.set_defaults(func=cmd_mesh)
    mesh_peers = mesh_sub.add_parser("peers", help="list enrolled peers")
    mesh_peers.set_defaults(func=cmd_mesh)

    peer = mesh_sub.add_parser("peer", help="manage one peer")
    peer_sub = peer.add_subparsers(dest="peer_action", required=True)
    peer_add = peer_sub.add_parser("add", help="create a peer and print its config")
    peer_add.add_argument("name")
    peer_add.add_argument("--address", default=None)
    peer_add.add_argument("--endpoint", default=None)
    peer_add.add_argument("--keepalive", type=int, default=25)
    peer_add.add_argument("-o", "--output", help="write the client config to this path")
    peer_add.set_defaults(func=cmd_mesh, mesh_action="peer-add")

    peer_config = peer_sub.add_parser("config", help="print a peer's client config")
    peer_config.add_argument("name")
    peer_config.set_defaults(func=cmd_mesh, mesh_action="peer-config")

    peer_remove = peer_sub.add_parser("remove", help="delete a peer")
    peer_remove.add_argument("name")
    peer_remove.add_argument("--yes", action="store_true")
    peer_remove.set_defaults(func=cmd_mesh, mesh_action="peer-remove")
    return parser


def cmd_config_show(args: argparse.Namespace) -> int:
    """Print the effective configuration file."""
    print(_load_manager(args).read_text())
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except ConfigError as exc:
        _print_error(exc.pretty())
        return 1
    except (TLSError, MeshError, DatabaseError, OSError, sqlite3.Error) as exc:
        _print_error(str(exc))
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
