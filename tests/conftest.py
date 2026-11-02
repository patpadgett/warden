from __future__ import annotations

import asyncio
import io
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from ruamel.yaml import YAML
from starlette.testclient import TestClient

from warden.auth.sessions import hash_token
from warden.config import ConfigManager, parse_config_text
from warden.db import Database
from warden.main import create_app
from warden.utils import SESSION_COOKIE


def config_dict(
    tmp_path: Path,
    *,
    upstream: str = "http://127.0.0.1:9",
    routes: list[dict[str, Any]] | None = None,
    mesh: dict[str, Any] | None = None,
    **server_overrides: Any,
) -> dict[str, Any]:
    server: dict[str, Any] = {
        "admin_host": "admin.home.lan",
        "bind": "127.0.0.1",
        "http_port": 8080,
        "https_port": 8443,
        "tls": {"enabled": False},
        "log_level": "warning",
        "health_interval_seconds": 3600,
    }
    server.update(server_overrides)
    return {
        "version": 1,
        "server": server,
        "database": {"path": str(tmp_path / "warden.db")},
        "webauthn": {"rp_id": "home.lan", "rp_name": "Warden Test"},
        "mesh": mesh if mesh is not None else {"enabled": False},
        "routes": routes
        if routes is not None
        else [{"host": "app.home.lan", "upstream": upstream, "name": "App"}],
    }


def dump_yaml(data: dict[str, Any]) -> str:
    yaml = YAML()
    yaml.indent(mapping=2, sequence=4, offset=2)
    buffer = io.StringIO()
    yaml.dump(data, buffer)
    return buffer.getvalue()


def write_config(tmp_path: Path, data: dict[str, Any], *, name: str = "warden.yaml") -> Path:
    text = dump_yaml(data)
    parse_config_text(text, base_dir=tmp_path, source=name)
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture
def config_file(tmp_path: Path) -> Path:
    return write_config(tmp_path, config_dict(tmp_path))


@pytest.fixture
def manager(config_file: Path) -> ConfigManager:
    return ConfigManager.from_file(config_file)


def seed_user(
    db_path: Path,
    *,
    token: str = "test-session-token",
    username: str = "pat",
    credential_count: int = 1,
    audit: bool = True,
) -> tuple[int, str]:
    """Create a user, passkeys, and a session before the app starts."""

    async def _seed() -> int:
        db = Database(db_path)
        await db.init()
        try:
            user, _credential = await db.create_user_with_credential(
                username=username,
                display_name=username.title(),
                webauthn_user_id=b"u" * 16,
                credential_id=b"c" * 32,
                public_key=b"p" * 64,
                sign_count=1,
                transports=["internal"],
                credential_name="Test passkey",
                aaguid=None,
                fmt="none",
                user_verified=True,
                backup_eligible=False,
                backup_state=False,
            )
            for index in range(1, credential_count):
                await db.add_credential(
                    user_id=user.id,
                    credential_id=bytes([index]) * 32,
                    public_key=bytes([index]) * 64,
                    sign_count=1,
                    transports=["internal"],
                    name=f"Spare {index}",
                    aaguid=None,
                    fmt="none",
                    user_verified=True,
                    backup_eligible=False,
                    backup_state=False,
                )
            await db.create_session(hash_token(token), user.id, time.time() + 3600)
            if audit:
                await db.audit(
                    "login_succeeded",
                    user_id=user.id,
                    username=user.username,
                    ip="127.0.0.1",
                    user_agent="pytest",
                    detail="Test sign-in",
                )
            return user.id
        finally:
            await db.close()

    user_id = asyncio.run(_seed())
    return user_id, token


def set_session_cookie(client: Any, token: str, host: str = "admin.home.lan") -> None:
    client.cookies.set(SESSION_COOKIE, token, domain=host)


def session_header(token: str, extra: str = "") -> dict[str, str]:
    value = f"{SESSION_COOKIE}={token}"
    if extra:
        value += f"; {extra}"
    return {"cookie": value}


class UpstreamHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        if self.path.startswith("/redirect"):
            body = b"redirecting"
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/landing?x=1")
            self.send_header("Set-Cookie", "session=abc; Path=/; HttpOnly")
            self.send_header("Set-Cookie", "warden_session=spoof; Path=/")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/slow"):
            time.sleep(0.4)
        if self.path.startswith("/fail"):
            self.send_response(500)
            self.send_header("Content-Length", "4")
            self.end_headers()
            self.wfile.write(b"fail")
            return
        payload = (
            f"path={self.path}\n"
            f"host={self.headers.get('host')}\n"
            f"xff={self.headers.get('x-forwarded-for')}\n"
            f"xfp={self.headers.get('x-forwarded-proto')}\n"
            f"user={self.headers.get('x-warden-user')}\n"
            f"cookie={self.headers.get('cookie')}\n"
            f"route={self.headers.get('x-route')}\n"
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self) -> None:
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length)
        payload = f"body={body.decode('utf-8', 'replace')}\n".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args: Any) -> None:
        pass


@pytest.fixture
def upstream_server() -> tuple[ThreadingHTTPServer, str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), UpstreamHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()


def admin_headers(token: str = "test-session-token", **extra: str) -> dict[str, str]:
    headers = {
        "host": "admin.home.lan",
        "cookie": f"{SESSION_COOKIE}={token}",
    }
    headers.update({key.lower(): value for key, value in extra.items()})
    return headers


def host_headers(host: str, token: str | None = None, **extra: str) -> dict[str, str]:
    headers = {"host": host}
    if token:
        headers["cookie"] = f"{SESSION_COOKIE}={token}"
    headers.update({key.lower(): value for key, value in extra.items()})
    return headers


@pytest.fixture
def app_and_path(tmp_path: Path, upstream_server: tuple[ThreadingHTTPServer, str]):
    import socket

    _server, upstream = upstream_server
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        dead_port = probe.getsockname()[1]
    data = config_dict(
        tmp_path,
        routes=[
            {
                "host": "app.home.lan",
                "upstream": upstream,
                "name": "App",
                "public_paths": ["/public", "/public/*", "/assets/*"],
                "headers": {"X-Route": "yes"},
            },
            {"host": "public.home.lan", "upstream": upstream, "auth": False, "name": "Public"},
            {"host": "disabled.home.lan", "upstream": upstream, "enabled": False},
            {
                "host": "preserve.home.lan",
                "upstream": upstream,
                "auth": False,
                "preserve_host": True,
            },
            {"host": "*.apps.home.lan", "upstream": upstream, "auth": False, "name": "Wild"},
            {"host": "dead.home.lan", "upstream": f"http://127.0.0.1:{dead_port}", "auth": False},
        ],
    )
    path = write_config(tmp_path, data)
    seed_user(tmp_path / "warden.db", credential_count=2)
    app = create_app(path)
    return app, path


@pytest.fixture
def client(app_and_path):
    app, _path = app_and_path
    with TestClient(app, base_url="http://admin.home.lan") as test_client:
        yield test_client


@pytest.fixture
def unclaimed_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("WARDEN_SETUP_TOKEN", "TEST-SETUP-CODE-1234")
    path = write_config(tmp_path, config_dict(tmp_path))
    app = create_app(path)
    with TestClient(app) as test_client:
        yield test_client


def count_rows(db_path: Path, table: str) -> int:
    import sqlite3

    with sqlite3.connect(db_path) as connection:
        row = connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
    return int(row[0]) if row else 0


def add_session(db_path: Path, token: str, user_id: int = 1, *, ttl: float = 3600) -> None:
    import sqlite3

    now = time.time()
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "INSERT INTO sessions "
            "(token_hash, user_id, created_at, expires_at, last_seen_at, ip, user_agent) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (hash_token(token), user_id, now, now + ttl, now, "127.0.0.1", "pytest"),
        )
