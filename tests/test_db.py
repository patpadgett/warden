from __future__ import annotations

import asyncio
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


async def test_get_challenge_peeks_without_consuming(db: Database) -> None:
    now = time.time()
    await db.create_challenge("peek", "login_otp", {"user_id": 1}, 300, now=now)

    first = await db.get_challenge("peek", "login_otp", now=now + 1)
    assert first is not None
    assert first.payload == {"user_id": 1}
    # A second look still finds it: only consume_challenge spends the row.
    assert await db.get_challenge("peek", "login_otp", now=now + 2) is not None
    assert await db.consume_challenge("peek", "login_otp", now=now + 3) is not None
    assert await db.get_challenge("peek", "login_otp", now=now + 4) is None

    # Expired and wrong-kind challenges are never returned.
    await db.create_challenge("stale", "login_otp", {}, 5, now=now - 10)
    assert await db.get_challenge("stale", "login_otp", now=now) is None
    assert await db.get_challenge("stale", "register", now=now) is None


async def test_pending_otp_secret_never_blocks_the_active_one(db: Database) -> None:
    """An abandoned re-enrolment must not lock out the current authenticator."""
    import base64
    import hashlib
    import hmac
    import struct

    def code_for(secret: str) -> str:
        key = base64.b32decode(secret)
        digest = hmac.new(key, struct.pack(">Q", int(time.time() // 30)), hashlib.sha1).digest()
        start = digest[-1] & 0x0F
        token = struct.unpack(">I", digest[start : start + 4])[0] & 0x7FFFFFFF
        return f"{token % 1_000_000:06d}"

    user, _ = await make_user(db)
    await db.set_otp_secret(user.id, "JBSWY3DPEHPK3PXP")
    await db.set_pending_otp_secret(user.id, "GEZDGNBVGY3TQOJQ")

    # The already-working secret still signs in while a new one is pending.
    assert await db.verify_otp(user.id, code_for("JBSWY3DPEHPK3PXP")) is True
    assert await db.get_otp_secret(user.id) == "JBSWY3DPEHPK3PXP"
    assert await db.get_pending_otp_secret(user.id) == "GEZDGNBVGY3TQOJQ"

    # The pending one promotes itself once it verifies.
    assert await db.verify_otp(user.id, code_for("GEZDGNBVGY3TQOJQ")) is True
    assert await db.get_otp_secret(user.id) == "GEZDGNBVGY3TQOJQ"
    assert await db.get_pending_otp_secret(user.id) is None

    await db.clear_otp_secret(user.id)
    assert await db.get_otp_secret(user.id) is None
    assert await db.verify_otp(user.id, code_for("GEZDGNBVGY3TQOJQ")) is False


async def test_totp_codes_cannot_be_replayed(db: Database) -> None:
    """The verification that accepts a code spends its time-step."""
    import base64
    import hashlib
    import hmac
    import struct

    def code_at(secret: str, at: float) -> str:
        key = base64.b32decode(secret)
        digest = hmac.new(key, struct.pack(">Q", int(at // 30)), hashlib.sha1).digest()
        start = digest[-1] & 0x0F
        token = struct.unpack(">I", digest[start : start + 4])[0] & 0x7FFFFFFF
        return f"{token % 1_000_000:06d}"

    user, _ = await make_user(db)
    secret = "JBSWY3DPEHPK3PXP"
    await db.set_otp_secret(user.id, secret)
    now = 1_700_000_000.0

    assert await db.verify_otp(user.id, code_at(secret, now), at=now) is True
    # The same code, and an older step still inside the drift window, are spent.
    assert await db.verify_otp(user.id, code_at(secret, now), at=now) is False
    assert await db.verify_otp(user.id, code_at(secret, now - 30), at=now) is False
    # The next step still works, so a legitimate user is not locked out.
    assert await db.verify_otp(user.id, code_at(secret, now + 30), at=now + 30) is True

    # Promoting a pending secret also spends the code that proved it.
    await db.clear_otp_secret(user.id)
    replacement = "GEZDGNBVGY3TQOJQ"
    await db.set_pending_otp_secret(user.id, replacement)
    assert await db.verify_otp(user.id, code_at(replacement, now), at=now) is True
    assert await db.get_otp_secret(user.id) == replacement
    assert await db.verify_otp(user.id, code_at(replacement, now), at=now) is False


async def test_delete_credential_can_keep_the_last_key(db: Database) -> None:
    user, credential = await make_user(db)

    assert await db.delete_credential(user.id, credential.id, keep_last=True) is False
    assert len(await db.list_credentials(user.id)) == 1

    await db.add_credential(
        user_id=user.id,
        credential_id=b"s" * 32,
        public_key=b"q" * 64,
        sign_count=1,
        transports=["internal"],
        name="Spare",
        aaguid=None,
        fmt="none",
        user_verified=True,
        backup_eligible=False,
        backup_state=False,
    )
    assert await db.delete_credential(user.id, credential.id, keep_last=True) is True

    spare = (await db.list_credentials(user.id))[0]
    assert await db.delete_credential(user.id, spare.id, keep_last=True) is False
    assert await db.delete_credential(user.id, spare.id) is True


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


async def test_vacuum(db: Database) -> None:
    # Insert data then vacuum; operation should not raise.
    await db.set_setting("theme", "dark")
    await db.vacuum()
    assert await db.get_setting("theme") == "dark"


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


async def test_init_failure_closes_connection_and_leaves_no_thread(tmp_path: Path) -> None:
    """A corrupt database must not leave an open connection behind.

    ``PRAGMA journal_mode = WAL`` is the first statement that touches the file,
    so it is where a non-database file fails. If the connection is not closed
    there, aiosqlite's worker thread stays alive and the process never exits —
    the CLI hangs instead of returning non-zero.
    """
    import sqlite3
    import threading

    corrupt = tmp_path / "corrupt.db"
    corrupt.write_text("this is not a sqlite database\n", encoding="utf-8")

    before = {t.ident for t in threading.enumerate()}
    database = Database(corrupt)
    with pytest.raises(sqlite3.DatabaseError):
        await database.init()

    assert database._conn is None
    # Give a would-be worker thread a moment to appear, then assert none did.
    await asyncio.sleep(0.05)
    leaked = [t for t in threading.enumerate() if t.ident not in before and not t.daemon]
    assert leaked == []


async def test_invite_lifecycle(db: Database) -> None:
    """create_invite, get_invite, and mark_invite_used round-trip."""
    user = await db.create_user("invite-db", "Invite DB", b"i" * 16, is_admin=False)
    token = "DB-INVITE-TOKEN"
    invite_id = await db.create_invite(user.id, token, time.time() + 3600)

    stored = await db.get_invite(token)
    assert stored is not None
    assert int(stored["user_id"]) == user.id
    assert int(stored["used"]) == 0
    assert float(stored["expires_at"]) > time.time()

    ok = await db.mark_invite_used(invite_id)
    assert ok is True

    used = await db.get_invite(token)
    assert used is not None
    assert int(used["used"]) == 1


async def test_get_invite_missing_token(db: Database) -> None:
    """get_invite returns None for an unknown token."""
    result = await db.get_invite("NONEXISTENT-TOKEN")
    assert result is None


async def test_mark_invite_used_missing(db: Database) -> None:
    """mark_invite_used returns False for a non-existent invite."""
    ok = await db.mark_invite_used(999999)
    assert ok is False
