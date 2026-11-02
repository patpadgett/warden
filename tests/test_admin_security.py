from __future__ import annotations

import sqlite3
import time

import pytest
from warden.auth.sessions import hash_token
from warden.db import Database


@pytest.mark.asyncio
async def test_non_admin_denied_on_admin_host(app_and_path, client) -> None:
    """A non-admin user authenticated on the admin host must be denied."""
    app, cfg_path = app_and_path
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
