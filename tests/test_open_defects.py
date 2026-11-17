"""Regression tests for edge defects on the startup and check paths."""

from __future__ import annotations

import asyncio
import sqlite3
from unittest.mock import AsyncMock

from warden.cli import HttpsRedirectApp, _sqlite_problems
from warden.config import ConfigManager

from .conftest import config_dict, write_config


def _redirect_app(tmp_path) -> HttpsRedirectApp:
    path = write_config(tmp_path, config_dict(tmp_path))
    return HttpsRedirectApp(ConfigManager.from_file(path))


def _request(app: HttpsRedirectApp, host: str) -> dict:
    messages: list[dict] = []

    async def send(message: dict) -> None:
        messages.append(message)

    scope = {
        "type": "http",
        "method": "GET",
        "scheme": "http",
        "path": "/dashboard",
        "raw_path": b"/dashboard",
        "query_string": b"",
        "headers": [(b"host", host.encode("latin-1"))],
        "server": ("127.0.0.1", 8080),
        "client": ("203.0.113.9", 50000),
    }
    asyncio.run(app(scope, AsyncMock(), send))
    return next(message for message in messages if message["type"] == "http.response.start")


def test_https_redirect_rejects_an_unconfigured_host(tmp_path) -> None:
    """The HTTP listener echoed any Host header into Location (open redirect)."""
    start = _request(_redirect_app(tmp_path), "evil.example")
    assert start["status"] == 404
    assert not any(name.lower() == b"location" for name, _ in start["headers"])


def test_https_redirect_keeps_the_configured_admin_host(tmp_path) -> None:
    app = _redirect_app(tmp_path)
    start = _request(app, app.manager.config.server.admin_host)
    assert start["status"] == 308
    headers = dict(start["headers"])
    assert headers[b"location"].startswith(b"https://")


def test_check_reports_a_corrupt_database(tmp_path) -> None:
    path = tmp_path / "warden.db"
    path.write_text("this is not a database", encoding="utf-8")
    problems = _sqlite_problems(path)
    assert problems
    assert "not a usable SQLite file" in problems[0]


def test_check_accepts_a_real_database(tmp_path) -> None:
    path = tmp_path / "warden.db"
    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE sample (id INTEGER)")
        connection.commit()
    finally:
        connection.close()
    assert _sqlite_problems(path) == []


def test_check_accepts_a_missing_database(tmp_path) -> None:
    # Startup creates the database, so its absence is not a problem.
    assert _sqlite_problems(tmp_path / "absent.db") == []
