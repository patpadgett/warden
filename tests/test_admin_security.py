from __future__ import annotations

import hashlib
import sqlite3
import time
from unittest.mock import patch

import pytest

from warden.auth.sessions import hash_token
from warden.db import Database


@pytest.mark.asyncio
async def test_non_admin_denied_on_admin_host(app_and_path, client) -> None:
    """A non-admin user authenticated on the admin host must be denied."""
    _app, cfg_path = app_and_path
    db_path = cfg_path.with_name("warden.db")

    db = Database(db_path)
    await db.init()
    try:
        user = await db.create_user(
            username="mallory",
            display_name="Mallory",
            webauthn_user_id=b"m" * 16,
            is_admin=False,
        )
    finally:
        db.close()

    token = "mallory-token"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO sessions "
        "(token_hash, user_id, created_at, expires_at, last_seen_at, ip, user_agent)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            hash_token(token),
            user.id,
            time.time(),
            time.time() + 3600,
            time.time(),
            "127.0.0.1",
            "pytest",
        ),
    )
    conn.commit()
    conn.close()

    response = client.get(
        "/_warden/api/status",
        headers={"host": "admin.home.lan", "cookie": f"warden_session={token}"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Admin access required."


@pytest.mark.asyncio
async def test_create_invite_api(app_and_path, client) -> None:
    """An admin on the admin host can mint a first-login invite token."""
    app, cfg_path = app_and_path
    db = app.state.db

    # Non-admin user to invite.
    non_admin = await db.create_user("invitee", "Invitee", b"n" * 16, is_admin=False)
    # Admin user to mint the invite.
    admin = await db.create_user("administrator", "Administrator", b"a" * 16, is_admin=True)

    # Admin signs in.
    token = "admin-token"
    conn = sqlite3.connect(cfg_path.with_name("warden.db"))
    conn.execute(
        "INSERT INTO sessions (token_hash, user_id, created_at, expires_at, last_seen_at, ip, user_agent)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (hash_token(token), admin.id, time.time(), time.time() + 3600, time.time(), "127.0.0.1", "pytest"),
    )
    conn.commit()
    conn.close()

    def api(payload=None, **extra):
        return client.post(
            "/_warden/api/invites",
            headers={
                "host": "admin.home.lan",
                "cookie": f"warden_session={token}",
                "x-warden-request": "1",
            },
            json=payload,
            **extra,
        )

    response = api(payload={"user_id": non_admin.id, "expires_in": 3600})
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["token"]
    assert body["expires_in"] == 3600

    # The invite token must be usable via the invite flow.
    stored = await db.get_invite(body["token"])
    assert stored is not None
    assert int(stored["used"]) == 0

    # The admin account cannot receive an invite.
    forbidden = api(payload={"user_id": admin.id})
    assert forbidden.status_code == 400
    assert "cannot receive" in forbidden.json()["detail"]

    # A non-existent user cannot receive an invite.
    missing = api(payload={"user_id": 999999})
    assert missing.status_code == 400
    assert "does not exist" in missing.json()["detail"]


@pytest.mark.asyncio
async def test_create_invite_sends_email(app_and_path, client):
    """When email is enabled and the user has an address, the invite is emailed."""
    app, cfg_path = app_and_path
    db = app.state.db

    user = await db.create_user(
        "invitee-email", "Invitee Email", b"n" * 16, is_admin=False
    )
    admin = await db.create_user(
        "admin-email", "Admin Email", b"a" * 16, is_admin=True
    )

    token = "admin-email-token"
    conn = sqlite3.connect(cfg_path.with_name("warden.db"))
    conn.execute(
        "INSERT INTO sessions (token_hash, user_id, created_at, expires_at, last_seen_at, ip, user_agent)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (hash_token(token), admin.id, time.time(), time.time() + 3600, time.time(), "127.0.0.1", "pytest"),
    )
    conn.commit()
    conn.close()

    # Enable email and set the user's address.
    app.state.config.email.enabled = True
    app.state.config.email.host = "smtp.example.com"
    app.state.config.email.port = 25
    app.state.config.email.from_address = "warden@example.com"
    conn = sqlite3.connect(cfg_path.with_name("warden.db"))
    conn.execute("UPDATE users SET email = ? WHERE id = ?", ("invitee@example.com", user.id))
    conn.commit()
    conn.close()

    with patch("warden.admin.routes.send_email") as mock_send:
        response = client.post(
            "/_warden/api/invites",
            headers={
                "host": "admin.home.lan",
                "cookie": f"warden_session={token}",
                "x-warden-request": "1",
            },
            json={"user_id": user.id, "expires_in": 3600},
        )

    assert response.status_code == 200
    mock_send.assert_called_once()
    call_kwargs = mock_send.call_args[1]
    assert call_kwargs["to"] == "invitee@example.com"
    assert "Your first-login invite" in call_kwargs["subject"]
    assert response.json()["token"] in call_kwargs["body"]


@pytest.mark.asyncio
async def test_create_invite_email_failure_is_non_blocking(app_and_path, client):
    """SMTP failures must not block invite creation."""
    app, cfg_path = app_and_path
    db = app.state.db

    user = await db.create_user(
        "invitee-email-fail", "Invitee Fail", b"n" * 16, is_admin=False
    )
    admin = await db.create_user(
        "admin-email-fail", "Admin Fail", b"a" * 16, is_admin=True
    )

    token = "admin-email-fail-token"
    conn = sqlite3.connect(cfg_path.with_name("warden.db"))
    conn.execute(
        "INSERT INTO sessions (token_hash, user_id, created_at, expires_at, last_seen_at, ip, user_agent)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (hash_token(token), admin.id, time.time(), time.time() + 3600, time.time(), "127.0.0.1", "pytest"),
    )
    conn.commit()
    conn.close()

    app.state.config.email.enabled = True
    app.state.config.email.host = "smtp.example.com"
    app.state.config.email.port = 25
    app.state.config.email.from_address = "warden@example.com"
    conn = sqlite3.connect(cfg_path.with_name("warden.db"))
    conn.execute("UPDATE users SET email = ? WHERE id = ?", ("invitee@example.com", user.id))
    conn.commit()
    conn.close()

    with patch("warden.admin.routes.send_email", side_effect=RuntimeError("SMTP down")):
        response = client.post(
            "/_warden/api/invites",
            headers={
                "host": "admin.home.lan",
                "cookie": f"warden_session={token}",
                "x-warden-request": "1",
            },
            json={"user_id": user.id, "expires_in": 3600},
        )

    assert response.status_code == 200
    assert response.json()["ok"] is True
