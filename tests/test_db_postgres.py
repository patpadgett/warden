"""Tests for the PostgreSQL adapter module.

Covers the :class:`PostgresDatabase` mesh-peer operations (the portion
originally implemented) plus the full database interface -- users, credentials,
sessions, challenges, settings, audit, backup codes and OTP secrets -- using a
mocked SQLAlchemy async engine/session. No live PostgreSQL instance is
required.
"""

from __future__ import annotations

from typing import Self
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from warden.db import DatabaseError, MeshPeer
from warden.db_postgres import PostgresDatabase

NOW = 1_700_000_000.0

# Mesh peer row (used by the mesh test class only).
MOCK_ROW = {
    "id": 1,
    "name": "Phone",
    "public_key": "pub",
    "private_key": "priv",
    "preshared_key": "psk",
    "address": "10.0.0.1",
    "endpoint": None,
    "keepalive": 25,
    "enabled": True,
    "created_at": NOW,
    "last_handshake": None,
}

# Peer fields expected by add_mesh_peer (id is auto-generated).
PEER_BODY = {
    "name": MOCK_ROW["name"],
    "public_key": MOCK_ROW["public_key"],
    "private_key": MOCK_ROW["private_key"],
    "preshared_key": MOCK_ROW["preshared_key"],
    "address": MOCK_ROW["address"],
    "endpoint": MOCK_ROW["endpoint"],
    "keepalive": MOCK_ROW["keepalive"],
}


class _Row:
    """Row object that is both subscriptable and exposes a ``_mapping`` attribute."""

    def __init__(self, **kw) -> None:
        self._mapping = kw

    def __getitem__(self, key):
        return self._mapping[key]

    def __contains__(self, key) -> bool:
        return key in self._mapping


def _row(**kw) -> _Row:
    """Return a row object whose ``_mapping`` attribute is *kw*."""
    return _Row(**kw)


class _Result:
    """Minimal SQLAlchemy ``Result`` stand-in."""

    def __init__(self, scalar=None, fetchone=None, fetchall=None, rowcount=0, _mapping=None):
        self._mapping = _mapping
        self.scalar = MagicMock(return_value=scalar)
        self.fetchone = MagicMock(return_value=fetchone)
        self.fetchall = MagicMock(return_value=fetchall or [])
        self.rowcount = rowcount


class _BeginContext:
    """Async context manager returned by ``session.begin()``."""

    def __init__(self, session: _MockSession) -> None:
        self.session = session

    async def __aenter__(self) -> _MockSession:
        return self.session

    async def __aexit__(self, *exc) -> None:
        return None


class _MockSession:
    """Async context manager plus executor mock for PostgresDatabase tests."""

    def __init__(self) -> None:
        self.execute = AsyncMock()
        self.commit = AsyncMock()

    def begin(self) -> _BeginContext:
        return _BeginContext(self)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc) -> None:
        return None


# ---------------------------------------------------------------------------
# Init / schema
# ---------------------------------------------------------------------------
class TestPostgresDatabaseInit:
    def test_engine_and_session_factory_are_created(self) -> None:

        mock_engine = AsyncMock()
        mock_session_factory = MagicMock(return_value=AsyncMock())
        with patch("warden.db_postgres.create_async_engine", return_value=mock_engine), \
                patch("warden.db_postgres.sessionmaker", return_value=mock_session_factory):
            db = PostgresDatabase("postgresql+asyncpg://localhost/warden")
        assert db.engine is mock_engine
        assert callable(db.session_factory)

    async def test_init_creates_tables(self) -> None:
        mock_engine = AsyncMock()
        mock_conn = AsyncMock()
        mock_conn.run_sync.return_value = None
        # Result for the SELECT used to read the current schema version.
        select_result = MagicMock()
        select_result.fetchone.return_value = (0,)
        # Results for the INSERT used to record the version.
        insert_result = MagicMock()
        # Mock the conn.execute() calls for the schema migration part.
        mock_conn.execute.side_effect = [
            select_result,  # SELECT schema version
            # v1: users, settings, audit
            MagicMock(), MagicMock(), MagicMock(),
            insert_result,  # v1 insert version
            MagicMock(),  # v2: mesh_peers
            insert_result,  # v2 insert version
            # v3: 10 statements (credentials, idx_credentials_user, sessions,
            # idx_sessions_user, idx_sessions_expiry, challenges,
            # idx_challenges_expiry, backup_codes, idx_backup_codes_user,
            # otp_secrets)
            MagicMock(), MagicMock(), MagicMock(), MagicMock(), MagicMock(),
            MagicMock(), MagicMock(), MagicMock(), MagicMock(), MagicMock(),
            insert_result,  # v3 insert version
            # v4: invites table
            MagicMock(),  # CREATE TABLE invites
            MagicMock(),  # CREATE INDEX idx_invites_user
            MagicMock(),  # CREATE INDEX idx_invites_token
            MagicMock(),  # CREATE INDEX idx_invites_used
            insert_result,  # v4 insert version
            # v5: add users.email
            MagicMock(),  # ALTER TABLE users ADD COLUMN email
            insert_result,  # v5 insert version
            # v6: ACL groups (acl_groups, unique name index, acl_members,
            # member index, seed the default Users group)
            MagicMock(), MagicMock(), MagicMock(), MagicMock(), MagicMock(),
            insert_result,  # v6 insert version
            # v7: OTP enrolment columns + backfill
            MagicMock(), MagicMock(), MagicMock(), MagicMock(),
            insert_result,  # v7 insert version
            # v8: TOTP replay counter
            MagicMock(),
            insert_result,  # v8 insert version
        ]
        # Build a proper async context manager for the engine.begin() call.
        mock_cm = AsyncMock()
        mock_cm.__aenter__.return_value = mock_conn
        mock_cm.__aexit__.return_value = None
        # mock_engine.begin is a plain callable that returns the context manager
        # directly (not a coroutine), matching how real async engines behave.
        mock_engine.begin = MagicMock(return_value=mock_cm)
        # Mock asyncpg.connect for _ensure_database_exists.
        mock_pg_conn = AsyncMock()
        mock_pg_conn.fetchval.return_value = None  # DB doesn't exist yet
        with patch("warden.db_postgres.asyncpg.connect", return_value=mock_pg_conn), \
                patch("warden.db_postgres.create_async_engine", return_value=mock_engine), \
                patch("warden.db_postgres.sessionmaker", return_value=AsyncMock()):
            db = PostgresDatabase("postgresql+asyncpg://localhost/warden")
            await db.init()
        mock_engine.begin.assert_called_once()
        mock_conn.run_sync.assert_called_once()

    async def test_close_disposes_engine(self) -> None:
        mock_engine = AsyncMock()
        with patch("warden.db_postgres.create_async_engine", return_value=mock_engine):
            db = PostgresDatabase("postgresql+asyncpg://localhost/warden")
            await db.close()
        mock_engine.dispose.assert_called_once()


# ---------------------------------------------------------------------------
# Mesh peers (the portion originally implemented)
# ---------------------------------------------------------------------------
class TestPostgresDatabaseMeshPeers:
    async def _make_db(self, session=None, execute_side_effect=None):
        engine = AsyncMock()
        if session is None:
            session = _MockSession()
        if execute_side_effect is not None:
            session.execute.side_effect = execute_side_effect
        factory = MagicMock(return_value=session)
        with patch("warden.db_postgres.create_async_engine", return_value=engine), \
                patch("warden.db_postgres.sessionmaker", return_value=factory):
            db = PostgresDatabase("postgresql+asyncpg://localhost/warden")
        return db, session

    async def test_list_mesh_peers(self) -> None:
        session, result = _MockSession(), MagicMock()
        result.fetchall.return_value = [_row(**MOCK_ROW)]
        session.execute.return_value = result
        db, _ = await self._make_db(session=session)
        peers = await db.list_mesh_peers()
        assert peers == [MeshPeer(**MOCK_ROW)]
        session.execute.assert_called_once()

    async def test_add_mesh_peer(self) -> None:
        session = _MockSession()
        insert_result, select_result = MagicMock(), MagicMock()
        session.execute.side_effect = [insert_result, select_result]
        select_result.fetchone.return_value = _row(**MOCK_ROW)
        db, _ = await self._make_db(session=session)
        peer = await db.add_mesh_peer(**PEER_BODY)
        assert peer == MeshPeer(**MOCK_ROW)
        assert peer.id == 1
        assert session.commit.called

    async def test_add_mesh_peer_row_disappeared_raises(self) -> None:
        session = _MockSession()
        select_result = MagicMock()
        session.execute.side_effect = [AsyncMock(), select_result]
        select_result.fetchone.return_value = None
        db, _ = await self._make_db(session=session)
        with pytest.raises(DatabaseError, match="disappeared"):
            await db.add_mesh_peer(**PEER_BODY)

    async def test_get_mesh_peer_found(self) -> None:
        session, result = _MockSession(), MagicMock()
        result.fetchone.return_value = _row(**MOCK_ROW)
        session.execute.return_value = result
        db, _ = await self._make_db(session=session)
        peer = await db.get_mesh_peer(1)
        assert peer == MeshPeer(**MOCK_ROW)
        session.execute.assert_called_once()

    async def test_get_mesh_peer_not_found(self) -> None:
        session, result = _MockSession(), MagicMock()
        result.fetchone.return_value = None
        session.execute.return_value = result
        db, _ = await self._make_db(session=session)
        peer = await db.get_mesh_peer(99)
        assert peer is None

    async def test_delete_mesh_peer(self) -> None:
        session = _MockSession()
        session.execute.return_value.rowcount = 1
        db, _ = await self._make_db(session=session)
        removed = await db.delete_mesh_peer(1)
        assert removed is True
        session.commit.assert_called_once()

    async def test_delete_mesh_peer_not_found(self) -> None:
        session = _MockSession()
        session.execute.return_value.rowcount = 0
        db, _ = await self._make_db(session=session)
        removed = await db.delete_mesh_peer(1)
        assert removed is False

    async def test_set_mesh_handshake(self) -> None:
        session = _MockSession()
        session.execute.return_value.rowcount = 1
        db, _ = await self._make_db(session=session)
        updated = await db.set_mesh_handshake(1, 456.0)
        assert updated is True
        session.commit.assert_called_once()

    async def test_set_mesh_handshake_no_rows(self) -> None:
        session = _MockSession()
        session.execute.return_value.rowcount = 0
        db, _ = await self._make_db(session=session)
        updated = await db.set_mesh_handshake(1, None)
        assert updated is False


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------
class TestPostgresDatabaseUsers:
    async def _make_db(self, session=None, execute_side_effect=None):
        engine = AsyncMock()
        if session is None:
            session = _MockSession()
        if execute_side_effect is not None:
            session.execute.side_effect = execute_side_effect
        factory = MagicMock(return_value=session)
        with patch("warden.db_postgres.create_async_engine", return_value=engine), \
                patch("warden.db_postgres.sessionmaker", return_value=factory):
            db = PostgresDatabase("postgresql+asyncpg://localhost/warden")
        return db, session

    async def test_user_count(self) -> None:
        session = _MockSession()
        session.execute.return_value = _Result(scalar=3)
        db, _ = await self._make_db(session=session)
        assert await db.user_count() == 3

    async def test_create_user(self) -> None:
        created = NOW
        row = _row(id=1, username="alice", display_name="Alice", webauthn_user_id=b"\x01",
                   is_admin=True, created_at=created, recovery_token=None)
        result = _Result(scalar=1, fetchone=row)
        # The default ACL group lookup returns no row, so no membership is
        # inserted; then the created user is read back.
        group_result = _Result(scalar=None)
        session = _MockSession()
        session.execute.side_effect = [result, group_result, result]
        db, _ = await self._make_db(session=session)
        user = await db.create_user("alice", "Alice", b"\x01", now=NOW)
        assert user.username == "alice"
        assert user.id == 1

    async def test_get_user(self) -> None:
        session, result = _MockSession(), MagicMock()
        result.fetchone.return_value = _row(
            id=1, username="admin", display_name="Admin", webauthn_user_id=b"w1",
            is_admin=True, created_at=NOW, recovery_token=None,
        )
        session.execute.return_value = result
        db, _ = await self._make_db(session=session)
        user = await db.get_user(1)
        assert user is not None
        assert user.id == 1
        session.execute.assert_called_once()

    async def test_get_user_by_username(self) -> None:
        session, result = _MockSession(), MagicMock()
        result.fetchone.return_value = _row(
            id=1, username="Phone", display_name="Phone", webauthn_user_id=b"w1",
            is_admin=True, created_at=NOW, recovery_token=None,
        )
        session.execute.return_value = result
        db, _ = await self._make_db(session=session)
        user = await db.get_user_by_username("Phone")
        assert user is not None
        assert user.username == "Phone"
        session.execute.assert_called_once()

    async def test_list_users(self) -> None:
        session, result = _MockSession(), MagicMock()
        result.fetchall.return_value = [
            _row(id=1, username="Phone", display_name="Phone", webauthn_user_id=b"w1",
                 is_admin=True, created_at=NOW, recovery_token=None),
        ]
        session.execute.return_value = result
        db, _ = await self._make_db(session=session)
        users = await db.list_users()
        assert len(users) == 1
        assert users[0].username == "Phone"
        session.execute.assert_called_once()

    async def test_get_user_by_webauthn_id(self) -> None:
        session, result = _MockSession(), MagicMock()
        result.fetchone.return_value = _row(
            id=1, username="Phone", display_name="Phone", webauthn_user_id=b"\x01",
            is_admin=True, created_at=NOW, recovery_token=None,
        )
        session.execute.return_value = result
        db, _ = await self._make_db(session=session)
        user = await db.get_user_by_webauthn_id(b"\x01")
        assert user is not None
        session.execute.assert_called_once()

    async def test_delete_user(self) -> None:
        session = _MockSession()
        session.execute.return_value.rowcount = 1
        db, _ = await self._make_db(session=session)
        removed = await db.delete_user(1)
        assert removed is True
        session.commit.assert_called_once()

    async def test_update_user_admin(self) -> None:
        session = _MockSession()
        session.execute.return_value.rowcount = 1
        db, _ = await self._make_db(session=session)
        updated = await db.update_user_admin(1, False)
        assert updated is True
        session.commit.assert_called_once()

    async def test_update_user_display_name(self) -> None:
        session = _MockSession()
        session.execute.return_value.rowcount = 1
        db, _ = await self._make_db(session=session)
        updated = await db.update_user_display_name(1, "New Nick")
        assert updated is True
        session.execute.assert_called_once()
        session.commit.assert_called_once()

    async def test_update_user_email(self) -> None:
        session = _MockSession()
        session.execute.return_value.rowcount = 1
        db, _ = await self._make_db(session=session)
        updated = await db.update_user_email(1, "pat@example.com")
        assert updated is True
        session.execute.assert_called_once()
        session.commit.assert_called_once()

    # ---------------------------------------------------------------- invites
    async def test_create_invite(self) -> None:
        session = _MockSession()
        session.execute.return_value = _Result(scalar=7)
        db, _ = await self._make_db(session=session)
        invite_id = await db.create_invite(1, "invite-token", NOW + 3600, now=NOW)
        assert invite_id == 7
        session.commit.assert_called_once()
        statement = session.execute.call_args[0][0]
        params = statement.compile().params
        assert params["user_id"] == 1
        assert params["expires_at"] == NOW + 3600
        assert params["used"] == 0
        assert params["token_hash"] != "invite-token"
        assert len(params["token_hash"]) == 64

    async def test_get_invite_found(self) -> None:
        row = _row(
            id=7, user_id=1, token_hash="h", expires_at=NOW + 3600,
            used=0, created_at=NOW,
        )
        session, result = _MockSession(), MagicMock()
        result.fetchone.return_value = row
        session.execute.return_value = result
        db, _ = await self._make_db(session=session)
        invite = await db.get_invite("invite-token")
        assert invite is not None
        assert invite["id"] == 7
        assert invite["user_id"] == 1
        assert invite["used"] == 0

    async def test_get_invite_not_found(self) -> None:
        session, result = _MockSession(), MagicMock()
        result.fetchone.return_value = None
        session.execute.return_value = result
        db, _ = await self._make_db(session=session)
        assert await db.get_invite("missing") is None

    async def test_mark_invite_used(self) -> None:
        session = _MockSession()
        session.execute.return_value.rowcount = 1
        db, _ = await self._make_db(session=session)
        assert await db.mark_invite_used(7) is True
        session.commit.assert_called_once()

    async def test_mark_invite_used_not_found(self) -> None:
        session = _MockSession()
        session.execute.return_value.rowcount = 0
        db, _ = await self._make_db(session=session)
        assert await db.mark_invite_used(99) is False


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------
class TestPostgresDatabaseCredentials:
    async def _make_db(self, session=None, execute_side_effect=None):
        engine = AsyncMock()
        if session is None:
            session = _MockSession()
        if execute_side_effect is not None:
            session.execute.side_effect = execute_side_effect
        factory = MagicMock(return_value=session)
        with patch("warden.db_postgres.create_async_engine", return_value=engine), \
                patch("warden.db_postgres.sessionmaker", return_value=factory):
            db = PostgresDatabase("postgresql+asyncpg://localhost/warden")
        return db, session

    async def test_add_credential(self) -> None:
        cred_row = _row(
            id=1, user_id=1, credential_id=b"cid", public_key=b"pub",
            sign_count=5, transports='["hybrid"]', name="Test", aaguid=None,
            fmt="FIDO_2", user_verified=True, backup_eligible=False,
            backup_state=False, created_at=NOW, last_used_at=None,
        )
        result1 = _Result(scalar=1)
        result2 = _Result(fetchone=cred_row)
        session = _MockSession()
        session.execute.side_effect = [result1, result2]
        db, _ = await self._make_db(session=session)
        cred = await db.add_credential(
            user_id=1, credential_id=b"cid", public_key=b"pub", sign_count=5,
            transports=["hybrid"], name="Test", aaguid=None, fmt="FIDO_2",
            user_verified=True, backup_eligible=False, backup_state=False, now=NOW,
        )
        assert cred is not None
        assert cred.id == 1
        assert cred.sign_count == 5

    async def test_get_credential(self) -> None:
        session, result = _MockSession(), MagicMock()
        result.fetchone.return_value = _row(
            id=1, user_id=1, credential_id=b"c1", public_key=b"p1",
            sign_count=25, transports='["hybrid"]', name="Test", aaguid=None,
            fmt="FIDO_2", user_verified=True, backup_eligible=False,
            backup_state=False, created_at=NOW, last_used_at=None,
        )
        session.execute.return_value = result
        db, _ = await self._make_db(session=session)
        credential = await db.get_credential(1)
        assert credential is not None
        assert credential.sign_count == 25

    async def test_get_credential_by_id(self) -> None:
        session, result = _MockSession(), MagicMock()
        result.fetchone.return_value = _row(
            id=1, user_id=1, credential_id=b"cid", public_key=b"pub",
            sign_count=25, transports='["hybrid"]', name="Test", aaguid=None,
            fmt="FIDO_2", user_verified=True, backup_eligible=False,
            backup_state=False, created_at=NOW, last_used_at=None,
        )
        session.execute.return_value = result
        db, _ = await self._make_db(session=session)
        credential = await db.get_credential_by_id(b"cid")
        assert credential is not None

    async def test_list_credentials(self) -> None:
        session, result = _MockSession(), MagicMock()
        result.fetchall.return_value = [
            _row(
                id=1, user_id=1, credential_id=b"c1", public_key=b"p1",
                sign_count=25, transports='["hybrid"]', name="Test", aaguid=None,
                fmt="FIDO_2", user_verified=True, backup_eligible=False,
                backup_state=False, created_at=NOW, last_used_at=None,
            )
        ]
        session.execute.return_value = result
        db, _ = await self._make_db(session=session)
        creds = await db.list_credentials(user_id=1)
        assert len(creds) == 1

    async def test_count_credentials(self) -> None:
        session = _MockSession()
        session.execute.return_value = _Result(scalar=2)
        db, _ = await self._make_db(session=session)
        assert await db.count_credentials(1) == 2

    async def test_update_credential_use(self) -> None:
        session = _MockSession()
        session.execute.return_value.rowcount = 1
        db, _ = await self._make_db(session=session)
        await db.update_credential_use(1, 10, now=NOW)
        session.commit.assert_called_once()

    async def test_rename_credential(self) -> None:
        session = _MockSession()
        session.execute.return_value.rowcount = 1
        db, _ = await self._make_db(session=session)
        renamed = await db.rename_credential(1, 1, "New name")
        assert renamed is True

    async def test_delete_credential(self) -> None:
        session = _MockSession()
        session.execute.return_value.rowcount = 1
        db, _ = await self._make_db(session=session)
        removed = await db.delete_credential(1, 1)
        assert removed is True
        session.commit.assert_called_once()


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------
class TestPostgresDatabaseSessions:
    async def _make_db(self, session=None, execute_side_effect=None):
        engine = AsyncMock()
        if session is None:
            session = _MockSession()
        if execute_side_effect is not None:
            session.execute.side_effect = execute_side_effect
        factory = MagicMock(return_value=session)
        with patch("warden.db_postgres.create_async_engine", return_value=engine), \
                patch("warden.db_postgres.sessionmaker", return_value=factory):
            db = PostgresDatabase("postgresql+asyncpg://localhost/warden")
        return db, session

    async def test_create_session(self) -> None:
        session = _MockSession()
        session.execute.return_value = _Result(scalar=1)
        db, _ = await self._make_db(session=session)
        token_hash = "abc123"
        user_id = 1
        expires_at = NOW + 3600
        created_id = await db.create_session(
            token_hash, user_id, expires_at, ip="1.2.3.4", user_agent="test", now=NOW
        )
        assert created_id == 1
        assert session.commit.called

    async def test_get_session(self) -> None:
        session, result = _MockSession(), MagicMock()
        result.fetchone.return_value = _row(
            id=1, token_hash="abc123", user_id=1, created_at=NOW,
            expires_at=NOW + 3600, last_seen_at=NOW, ip="1.2.3.4",
            user_agent="test",
            u_id=1, u_username="admin", u_display_name="Admin",
            u_webauthn_user_id=b"w1", u_is_admin=1, u_created_at=NOW,
            u_recovery_token=None,
        )
        session.execute.return_value = result
        db, _ = await self._make_db(session=session)
        got = await db.get_session("abc123", now=NOW)
        assert got is not None
        assert got.token_hash == "abc123"

    async def test_list_sessions(self) -> None:
        session, result = _MockSession(), MagicMock()
        result.fetchall.return_value = [
            _row(
                id=1, token_hash="a", user_id=1, created_at=NOW,
                expires_at=NOW + 3600, last_seen_at=NOW, ip="1.2.3.4",
                user_agent="test",
                u_id=1, u_username="admin", u_display_name="Admin",
                u_webauthn_user_id=b"w1", u_is_admin=1, u_created_at=NOW,
                u_recovery_token=None,
            )
        ]
        session.execute.return_value = result
        db, _ = await self._make_db(session=session)
        sessions = await db.list_sessions(user_id=1)
        assert len(sessions) == 1

    async def test_revoke_session(self) -> None:
        session = _MockSession()
        session.execute.return_value.rowcount = 1
        db, _ = await self._make_db(session=session)
        removed = await db.revoke_session(user_id=1, session_id=1)
        assert removed is True
        session.commit.assert_called_once()

    async def test_revoke_session_by_hash(self) -> None:
        session = _MockSession()
        db, _ = await self._make_db(session=session)
        await db.revoke_session_by_hash("tok")
        session.execute.assert_called_once()

    async def test_revoke_other_sessions(self) -> None:
        session = _MockSession()
        session.execute.return_value.rowcount = 2
        db, _ = await self._make_db(session=session)
        removed = await db.revoke_other_sessions(user_id=1, keep_token_hash="keep")
        assert removed == 2

    async def test_delete_expired_sessions(self) -> None:
        session = _MockSession()
        session.execute.return_value.rowcount = 3
        db, _ = await self._make_db(session=session)
        removed = await db.delete_expired_sessions()
        assert removed == 3
        session.commit.assert_called_once()


# ---------------------------------------------------------------------------
# Challenges
# ---------------------------------------------------------------------------
class TestPostgresDatabaseChallenges:
    async def _make_db(self, session=None, execute_side_effect=None):
        engine = AsyncMock()
        if session is None:
            session = _MockSession()
        if execute_side_effect is not None:
            session.execute.side_effect = execute_side_effect
        factory = MagicMock(return_value=session)
        with patch("warden.db_postgres.create_async_engine", return_value=engine), \
                patch("warden.db_postgres.sessionmaker", return_value=factory):
            db = PostgresDatabase("postgresql+asyncpg://localhost/warden")
        return db, session

    async def test_create_challenge(self) -> None:
        session = _MockSession()
        session.execute.return_value = _Result(scalar=1, fetchone=_row(id="ch1", kind="register", payload='{"foo":"bar"}', created_at=NOW, expires_at=NOW + 300))
        db, _ = await self._make_db(session=session)
        challenge = await db.create_challenge(
            "ch1", "register", {"foo": "bar"}, 300, now=NOW
        )
        assert challenge.id == "ch1"
        assert challenge.kind == "register"

    async def test_consume_challenge(self) -> None:
        session, result = _MockSession(), MagicMock()
        result.fetchone.return_value = _row(
            id="ch1", kind="register", payload='{"foo":"bar"}',
            created_at=NOW, expires_at=NOW + 300,
        )
        session.execute.return_value = result
        db, _ = await self._make_db(session=session)
        challenge = await db.consume_challenge("ch1", "register", now=NOW)
        assert challenge is not None
        assert challenge.id == "ch1"

    async def test_delete_expired_challenges(self) -> None:
        session = _MockSession()
        session.execute.return_value.rowcount = 2
        db, _ = await self._make_db(session=session)
        removed = await db.delete_expired_challenges()
        assert removed == 2
        session.commit.assert_called_once()


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
class TestPostgresDatabaseSettings:
    async def _make_db(self, session=None, execute_side_effect=None):
        engine = AsyncMock()
        if session is None:
            session = _MockSession()
        if execute_side_effect is not None:
            session.execute.side_effect = execute_side_effect
        factory = MagicMock(return_value=session)
        with patch("warden.db_postgres.create_async_engine", return_value=engine), \
                patch("warden.db_postgres.sessionmaker", return_value=factory):
            db = PostgresDatabase("postgresql+asyncpg://localhost/warden")
        return db, session

    async def test_get_setting(self) -> None:
        session, result = _MockSession(), MagicMock()
        result.fetchone.return_value = _row(key="setup", value="hash123")
        session.execute.return_value = result
        db, _ = await self._make_db(session=session)
        value = await db.get_setting("setup")
        assert value == "hash123"

    async def test_set_setting(self) -> None:
        session = _MockSession()
        db, _ = await self._make_db(session=session)
        await db.set_setting("setup", "hash123")
        session.commit.assert_called_once()

    async def test_delete_setting(self) -> None:
        session = _MockSession()
        db, _ = await self._make_db(session=session)
        await db.delete_setting("setup")
        session.commit.assert_called_once()


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------
class TestPostgresDatabaseAudit:
    async def _make_db(self, session=None, execute_side_effect=None):
        engine = AsyncMock()
        if session is None:
            session = _MockSession()
        if execute_side_effect is not None:
            session.execute.side_effect = execute_side_effect
        factory = MagicMock(return_value=session)
        with patch("warden.db_postgres.create_async_engine", return_value=engine), \
                patch("warden.db_postgres.sessionmaker", return_value=factory):
            db = PostgresDatabase("postgresql+asyncpg://localhost/warden")
        return db, session

    async def test_audit(self) -> None:
        session = _MockSession()
        db, _ = await self._make_db(session=session)
        await db.audit("login", user_id=1, username="admin",
                        detail={"ip": "1.2.3.4"})
        session.commit.assert_called_once()

    async def test_list_audit(self) -> None:
        session, result = _MockSession(), MagicMock()
        result.fetchall.return_value = [
            _row(
                id=1, created_at=NOW, event="login", user_id=1,
                username="admin", ip="1.2.3.4", user_agent="test",
                detail='{"ip":"1.2.3.4"}',
            )
        ]
        session.execute.return_value = result
        db, _ = await self._make_db(session=session)
        events = await db.list_audit(limit=10)
        assert len(events) == 1

    async def test_count_audit(self) -> None:
        session = _MockSession()
        session.execute.return_value = _Result(scalar=5)
        db, _ = await self._make_db(session=session)
        assert await db.count_audit() == 5


# ---------------------------------------------------------------------------
# Backup codes
# ---------------------------------------------------------------------------
class TestPostgresDatabaseBackupCodes:
    async def _make_db(self, session=None, execute_side_effect=None):
        engine = AsyncMock()
        if session is None:
            session = _MockSession()
        if execute_side_effect is not None:
            session.execute.side_effect = execute_side_effect
        factory = MagicMock(return_value=session)
        with patch("warden.db_postgres.create_async_engine", return_value=engine), \
                patch("warden.db_postgres.sessionmaker", return_value=factory):
            db = PostgresDatabase("postgresql+asyncpg://localhost/warden")
        return db, session

    async def test_add_backup_code(self) -> None:
        session = _MockSession()
        session.execute.return_value = _Result(scalar=1, fetchone=_row(id=1, user_id=1, code_hash="hash123", created_at=NOW, used_at=None))
        db, _ = await self._make_db(session=session)
        code_id = await db.add_backup_code(user_id=1, code_hash="hash123", now=NOW)
        assert code_id == 1
        session.commit.assert_called_once()

    async def test_use_backup_code(self) -> None:
        session, _result = _MockSession(), MagicMock()
        update_result = MagicMock()
        update_result.rowcount = 1
        select_result = _Result(scalar=1)
        session.execute.side_effect = [update_result, select_result]
        db, _ = await self._make_db(session=session)
        user_id = await db.use_backup_code("hash123")
        assert user_id == 1
        session.commit.assert_called_once()

    async def test_list_backup_codes(self) -> None:
        session, result = _MockSession(), MagicMock()
        result.fetchall.return_value = [
            _row(
                id=1, user_id=1, code_hash="hash123", created_at=NOW,
                used_at=None,
            )
        ]
        session.execute.return_value = result
        db, _ = await self._make_db(session=session)
        codes = await db.list_backup_codes(user_id=1)
        assert len(codes) == 1

    async def test_clear_backup_codes(self) -> None:
        session = _MockSession()
        db, _ = await self._make_db(session=session)
        await db.clear_backup_codes(user_id=1)
        session.commit.assert_called_once()


# ---------------------------------------------------------------------------
# OTP
# ---------------------------------------------------------------------------
class TestPostgresDatabaseOtp:
    async def _make_db(self, session=None, execute_side_effect=None):
        engine = AsyncMock()
        if session is None:
            session = _MockSession()
        if execute_side_effect is not None:
            session.execute.side_effect = execute_side_effect
        factory = MagicMock(return_value=session)
        with patch("warden.db_postgres.create_async_engine", return_value=engine), \
                patch("warden.db_postgres.sessionmaker", return_value=factory):
            db = PostgresDatabase("postgresql+asyncpg://localhost/warden")
        return db, session

    async def test_set_otp_secret(self) -> None:
        session = _MockSession()
        db, _ = await self._make_db(session=session)
        await db.set_otp_secret(user_id=1, secret="SECRET", now=NOW)
        session.commit.assert_called_once()

    async def test_get_otp_secret(self) -> None:
        session, result = _MockSession(), MagicMock()
        result.fetchone.return_value = _row(secret="SECRET", verified=1, user_id=1)
        session.execute.return_value = result
        db, _ = await self._make_db(session=session)
        secret = await db.get_otp_secret(user_id=1)
        assert secret == "SECRET"

    async def test_verify_otp(self) -> None:
        session, result = _MockSession(), MagicMock()
        result.fetchone.return_value = _row(
            secret="JBSWY3DPEHPK3PXP", pending_secret=None, verified=1, user_id=1
        )
        session.execute.return_value = result
        db, _ = await self._make_db(session=session)
        valid = await db.verify_otp(user_id=1, code="123456", window=1)
        assert isinstance(valid, bool)
