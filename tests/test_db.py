from __future__ import annotations

import time
from pathlib import Path

import pytest

from warden.auth.sessions import hash_token
from warden.db import AlreadyExistsError, Database, DatabaseError


@pytest.fixture
async def db(tmp_path: Path):
    database = Database(tmp_path / "warden.db")
    await database.init()
    try:
        yield database
    finally:
        await database.close()


async def make_user(db: Database, username: str = "pat"):
    return await db.create_user_with_credential(
        username=username,
        display_name=username.title(),
        webauthn_user_id=b"u" * 16,
        credential_id=b"c" * 32,
        public_key=b"p" * 64,
        sign_count=1,
        transports=["internal", "hybrid"],
        credential_name="Laptop",
        aaguid=None,
        fmt="none",
        user_verified=True,
        backup_eligible=False,
        backup_state=False,
    )


async def test_user_and_credential_lifecycle(db: Database) -> None:
    user, credential = await make_user(db)
    assert user.username == "pat"
    assert user.is_admin is True
    assert credential.name == "Laptop"
    assert credential.transports == ["internal", "hybrid"]
    assert (await db.user_count()) == 1
    assert await db.get_user_by_username("PAT") is not None
    assert await db.get_user_by_webauthn_id(b"u" * 16) is not None
    assert (await db.list_users())[0].id == user.id
    assert (await db.list_credentials(user.id))[0].id == credential.id
    assert (await db.count_credentials(user.id)) == 1

    with pytest.raises(AlreadyExistsError):
        await db.create_user("PAT", "Other", b"z" * 16)
    with pytest.raises(AlreadyExistsError):
        await db.add_credential(
            user_id=user.id,
            credential_id=b"c" * 32,
            public_key=b"q",
            sign_count=0,
            transports=[],
            name="Duplicate",
            aaguid=None,
            fmt=None,
            user_verified=False,
            backup_eligible=False,
            backup_state=False,
        )

    assert await db.rename_credential(user.id, credential.id, "Desktop") is True
    assert await db.rename_credential(user.id + 99, credential.id, "Nope") is False
    assert (await db.get_credential(credential.id)).name == "Desktop"

    await db.update_credential_use(credential.id, 9, now=123.0)
    updated = await db.get_credential(credential.id)
    assert updated is not None
    assert updated.sign_count == 9
    assert updated.last_used_at == 123.0

    assert await db.delete_credential(user.id + 99, credential.id) is False
    assert await db.delete_credential(user.id, credential.id) is True
    assert await db.list_credentials() == []


async def test_setup_mode_is_atomic_and_clears_setup_code(db: Database) -> None:
    await db.set_setting("setup_code_hash", "hash")
    await db.set_setting("setup_code_expires_at", "123")

    user, _ = await db.create_user_with_credential(
        username="first",
        display_name="First",
        webauthn_user_id=b"f" * 16,
        credential_id=b"f" * 32,
        public_key=b"f" * 64,
        sign_count=0,
        transports=[],
        credential_name="First",
        aaguid=None,
        fmt="none",
        user_verified=False,
        backup_eligible=False,
        backup_state=False,
        setup_mode=True,
    )
    assert user.username == "first"
    assert await db.get_setting("setup_code_hash") is None
    assert await db.get_setting("setup_code_expires_at") is None

    with pytest.raises(AlreadyExistsError):
        await db.create_user_with_credential(
            username="second",
            display_name="Second",
            webauthn_user_id=b"s" * 16,
            credential_id=b"s" * 32,
            public_key=b"s" * 64,
            sign_count=0,
            transports=[],
            credential_name="Second",
            aaguid=None,
            fmt="none",
            user_verified=False,
            backup_eligible=False,
            backup_state=False,
            setup_mode=True,
        )
    assert await db.user_count() == 1


async def test_sessions_expiry_touch_and_revocation(db: Database) -> None:
    user, _ = await make_user(db)
    token_hash = hash_token("token-one")
    now = time.time()
    session_id = await db.create_session(
        token_hash, user.id, now + 3600, ip="127.0.0.1", user_agent="pytest", now=now - 400
    )
    session = await db.get_session(token_hash, now=now)
    assert session is not None
    assert session.id == session_id
    assert session.user.username == "pat"
    # Touching after five minutes updates last_seen_at.
    assert session.last_seen_at == now
    assert await db.get_session(hash_token("missing")) is None

    second = await db.create_session(hash_token("token-two"), user.id, now + 3600)
    assert len(await db.list_sessions(user.id)) == 2
    assert await db.revoke_other_sessions(user.id, token_hash) == 1
    assert len(await db.list_sessions(user.id)) == 1
    assert await db.revoke_session(user.id, second) is False
    assert await db.revoke_session(user.id, session_id) is True
    assert await db.list_sessions(user.id) == []

    expired = await db.create_session(hash_token("expired"), user.id, now - 10)
    assert await db.get_session(hash_token("expired"), now=now) is None
    assert await db.revoke_session(user.id, expired) is False


async def test_challenges_are_single_use_and_expire(db: Database) -> None:
    now = time.time()
    await db.create_challenge("abc", "register", {"flow": "setup"}, 60, now=now)
    consumed = await db.consume_challenge("abc", "register", now=now + 1)
    assert consumed is not None
    assert consumed.payload == {"flow": "setup"}
    assert await db.consume_challenge("abc", "register", now=now + 2) is None

    await db.create_challenge("def", "register", {}, 60, now=now)
    assert await db.consume_challenge("def", "authenticate", now=now + 1) is None
    # A wrong-kind consume removes the row so it cannot be retried.
    assert await db.consume_challenge("def", "register", now=now + 1) is None

    await db.create_challenge("old", "register", {}, 5, now=now - 10)
    assert await db.consume_challenge("old", "register", now=now) is None
    await db.create_challenge("live", "register", {}, 60, now=now)
    await db.create_challenge("dead", "register", {}, 5, now=now - 10)
    assert await db.delete_expired_challenges() >= 1


async def test_settings_audit_and_reset(db: Database) -> None:
    await db.set_setting("theme", "dark")
    assert await db.get_setting("theme") == "dark"
    await db.set_setting("theme", "light")
    assert await db.get_setting("theme") == "light"
    await db.delete_setting("theme")
    assert await db.get_setting("theme") is None

    now = time.time()
    await db.audit("login_succeeded", username="pat", detail="ok", now=now - 5)
    await db.audit("login_failed", detail={"reason": "bad"}, now=now)
    assert await db.count_audit() == 2
    assert await db.count_audit(event="login_succeeded") == 1
    assert await db.count_audit(since=now - 1) == 1
    events = await db.list_audit(1)
    assert len(events) == 1
    assert events[0].event == "login_failed"
    assert events[0].detail == '{"reason": "bad"}'

    user, _ = await make_user(db)
    await db.create_session(hash_token("s"), user.id, now + 100)
    await db.reset_auth()
    assert await db.user_count() == 0
    assert await db.list_credentials() == []


async def test_mesh_peer_persistence(db: Database) -> None:
    peer = await db.add_mesh_peer(
        name="Phone",
        public_key="pub",
        private_key="priv",
        preshared_key="psk",
        address="10.44.0.2",
        endpoint="vpn.example:51820",
    )
    assert peer.keepalive == 25
    assert peer.enabled is True
    assert (await db.get_mesh_peer(peer.id)).name == "Phone"
    assert [item.id for item in await db.list_mesh_peers()] == [peer.id]
    await db.set_mesh_handshake(peer.id, 456.0)
    assert (await db.get_mesh_peer(peer.id)).last_handshake == 456.0
    await db.set_mesh_handshake(peer.id, None)
    assert (await db.get_mesh_peer(peer.id)).last_handshake is None

    with pytest.raises(AlreadyExistsError):
        await db.add_mesh_peer(
            name="PHONE",
            public_key="pub2",
            private_key="priv2",
            preshared_key="psk2",
            address="10.44.0.3",
            endpoint=None,
        )
    assert await db.delete_mesh_peer(peer.id) is True
    assert await db.delete_mesh_peer(peer.id) is False


async def test_database_init_is_idempotent(tmp_path: Path) -> None:
    database = Database(tmp_path / "nested" / "warden.db")
    await database.init()
    await database.init()
    assert (tmp_path / "nested" / "warden.db").exists()
    assert oct((tmp_path / "nested" / "warden.db").stat().st_mode & 0o777) == "0o600"
    await database.close()
    await database.close()

    uninitialized = Database(tmp_path / "other.db")
    with pytest.raises(DatabaseError):
        uninitialized._require_conn()
