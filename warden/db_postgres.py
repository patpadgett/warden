"""PostgreSQL adapter for Warden.

Self-contained PostgreSQL backend for Warden's database layer. Implemented as
an independent :class:`Database` subclass whose every operation is routed
through SQLAlchemy (asyncpg for PostgreSQL, compatible with the CockroachDB
wire protocol).

This replaces the SQLite-specific :mod:`warden.db` layer. The public API
exactly matches :class:`warden.db.Database`, so it can be dropped in for any
PostgreSQL consumer of the database abstraction:

* users / credentials / sessions / challenges
* settings / audit log
* backup codes / OTP secrets
* mesh peers

All PostgreSQL access is done via an ``AsyncSession`` bound to a
:class:`sqlalchemy.ext.asyncio.AsyncEngine`; the SQLite dataclasses from
:mod:`warden.db` are reused so the rest of the application sees the same
objects regardless of backend.
"""

from __future__ import annotations

import json
import time
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    Float,
    ForeignKey,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Table,
    Text,
    and_,
    delete,
    func,
    insert,
    select,
    text,
    update,
)
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError

from warden.db import (
    _audit,
    _credential,
    _peer,
    _session,
    _user,
    AlreadyExistsError,
    AuditEvent,
    BackupCode,
    Challenge,
    Database,
    DatabaseError,
    MeshPeer,
    Session,
    User,
    Credential,
)

# ---------------------------------------------------------------------------
# SQLAlchemy Core table definitions. These mirror the SQLite schema in
# warden/db.py so the same row builders apply.
# ---------------------------------------------------------------------------
metadata = MetaData()

users = Table(
    "users",
    metadata,
    Column("id", BigInteger, primary_key=True, autoincrement=True),
    Column("username", String, nullable=False, unique=True),
    Column("display_name", String, nullable=False),
    Column("webauthn_user_id", LargeBinary, nullable=False, unique=True),
    Column("is_admin", Boolean, nullable=False, default=True),
    Column("created_at", Float, nullable=False),
    Column("recovery_token", Text, nullable=True),
)

credentials = Table(
    "credentials",
    metadata,
    Column("id", BigInteger, primary_key=True, autoincrement=True),
    Column("user_id", BigInteger, ForeignKey("users.id"), nullable=False),
    Column("credential_id", LargeBinary, nullable=False, unique=True),
    Column("public_key", LargeBinary, nullable=False),
    Column("sign_count", Integer, nullable=False, default=0),
    Column("transports", Text, nullable=False, default="[]"),
    Column("name", String, nullable=False),
    Column("aaguid", Text, nullable=True),
    Column("fmt", Text, nullable=True),
    Column("user_verified", Boolean, nullable=False, default=False),
    Column("backup_eligible", Boolean, nullable=False, default=False),
    Column("backup_state", Boolean, nullable=False, default=False),
    Column("created_at", Float, nullable=False),
    Column("last_used_at", Float, nullable=True),
)

sessions = Table(
    "sessions",
    metadata,
    Column("id", BigInteger, primary_key=True, autoincrement=True),
    Column("token_hash", String, nullable=False, unique=True),
    Column("user_id", BigInteger, ForeignKey("users.id"), nullable=False),
    Column("created_at", Float, nullable=False),
    Column("expires_at", Float, nullable=False),
    Column("last_seen_at", Float, nullable=False),
    Column("ip", String, nullable=True),
    Column("user_agent", String, nullable=True),
)

challenges = Table(
    "challenges",
    metadata,
    Column("id", String, primary_key=True),
    Column("kind", String, nullable=False),
    Column("payload", Text, nullable=False),
    Column("created_at", Float, nullable=False),
    Column("expires_at", Float, nullable=False),
)

backup_codes = Table(
    "backup_codes",
    metadata,
    Column("id", BigInteger, primary_key=True, autoincrement=True),
    Column("user_id", BigInteger, ForeignKey("users.id"), nullable=False),
    Column("code_hash", String, nullable=False, unique=True),
    Column("created_at", Float, nullable=False),
    Column("used_at", Float, nullable=True),
)

otp_secrets = Table(
    "otp_secrets",
    metadata,
    Column("user_id", BigInteger, primary_key=True),
    Column("secret", String, nullable=False),
    Column("created_at", Float, nullable=False),
)

settings = Table(
    "settings",
    metadata,
    Column("key", String, primary_key=True),
    Column("value", Text, nullable=False),
)

audit = Table(
    "audit",
    metadata,
    Column("id", BigInteger, primary_key=True, autoincrement=True),
    Column("created_at", Float, nullable=False),
    Column("event", String, nullable=False),
    Column("user_id", BigInteger, ForeignKey("users.id"), nullable=True),
    Column("username", String, nullable=True),
    Column("ip", String, nullable=True),
    Column("user_agent", String, nullable=True),
    Column("detail", Text, nullable=True),
)

mesh_peers = Table(
    "mesh_peers",
    metadata,
    Column("id", BigInteger, primary_key=True, autoincrement=True),
    Column("name", String, nullable=False, unique=True),
    Column("public_key", String, nullable=False, unique=True),
    Column("private_key", String, nullable=True),
    Column("preshared_key", String, nullable=False),
    Column("address", String, nullable=False, unique=True),
    Column("endpoint", String, nullable=True),
    Column("keepalive", Integer, nullable=False, default=25),
    Column("enabled", Boolean, nullable=False, default=True),
    Column("created_at", Float, nullable=False),
    Column("last_handshake", Float, nullable=True),
)

#: Schema-version tracking table (backend-agnostic; mirrors the SQLite
#: ``schema_migrations`` table in warden/db.py). Each row records a
#: migration step that has been successfully applied.
schema_migrations = Table(
    "schema_migrations",
    metadata,
    Column("version", BigInteger, primary_key=True),
    Column("applied_on", Float, nullable=False),
)

#: Per-step migration scripts. Keys are the target schema version.
#: Each script runs inside a transaction; RAISE(IGNORE) suppresses
#: "duplicate table" errors when re-running an older migration.
#: These scripts use PostgreSQL-native types (SERIAL/BIGSERIAL, TEXT,
#: etc.) and are executed via ``sqlalchemy.text()``.
_MIGRATIONS: dict[int, str] = {
    1: """
        CREATE TABLE IF NOT EXISTS users (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            display_name TEXT NOT NULL,
            webauthn_user_id BYTEA NOT NULL UNIQUE,
            is_admin BOOLEAN NOT NULL DEFAULT TRUE,
            created_at DOUBLE PRECISION NOT NULL,
            recovery_token TEXT
        );

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            created_at DOUBLE PRECISION NOT NULL,
            event TEXT NOT NULL,
            user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
            username TEXT,
            ip TEXT,
            user_agent TEXT,
            detail TEXT
        );
        """,
    2: """
        CREATE TABLE IF NOT EXISTS mesh_peers (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            public_key TEXT NOT NULL UNIQUE,
            private_key TEXT,
            preshared_key TEXT NOT NULL,
            address TEXT NOT NULL UNIQUE,
            endpoint TEXT,
            keepalive INTEGER NOT NULL DEFAULT 25,
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            created_at DOUBLE PRECISION NOT NULL,
            last_handshake DOUBLE PRECISION
        );
        """,
    3: """
        CREATE TABLE IF NOT EXISTS credentials (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            credential_id BYTEA NOT NULL UNIQUE,
            public_key BYTEA NOT NULL,
            sign_count INTEGER NOT NULL DEFAULT 0,
            transports TEXT NOT NULL DEFAULT '[]',
            name TEXT NOT NULL,
            aaguid TEXT,
            fmt TEXT,
            user_verified BOOLEAN NOT NULL DEFAULT FALSE,
            backup_eligible BOOLEAN NOT NULL DEFAULT FALSE,
            backup_state BOOLEAN NOT NULL DEFAULT FALSE,
            created_at DOUBLE PRECISION NOT NULL,
            last_used_at DOUBLE PRECISION
        );
        CREATE INDEX IF NOT EXISTS idx_credentials_user ON credentials(user_id);

        CREATE TABLE IF NOT EXISTS sessions (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            token_hash TEXT NOT NULL UNIQUE,
            user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at DOUBLE PRECISION NOT NULL,
            expires_at DOUBLE PRECISION NOT NULL,
            last_seen_at DOUBLE PRECISION NOT NULL,
            ip TEXT,
            user_agent TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
        CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);

        CREATE TABLE IF NOT EXISTS challenges (
            id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            payload TEXT NOT NULL,
            created_at DOUBLE PRECISION NOT NULL,
            expires_at DOUBLE PRECISION NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_challenges_expiry ON challenges(expires_at);

        CREATE TABLE IF NOT EXISTS backup_codes (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            code_hash TEXT NOT NULL UNIQUE,
            created_at DOUBLE PRECISION NOT NULL,
            used_at DOUBLE PRECISION
        );
        CREATE INDEX IF NOT EXISTS idx_backup_codes_user ON backup_codes(user_id);

        CREATE TABLE IF NOT EXISTS otp_secrets (
            user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            secret TEXT NOT NULL,
            created_at DOUBLE PRECISION NOT NULL
        );
        """,
}  # type: ignore[assignment]


# Column list that mirrors warden/db.py's ``_SESSION_JOIN`` so the
# ``_session`` / ``_user`` row builders can be reused verbatim.
_SESSION_JOIN = """
SELECT s.id, s.token_hash, s.user_id, s.created_at, s.expires_at, s.last_seen_at,
       s.ip, s.user_agent,
       u.id AS u_id, u.username AS u_username, u.display_name AS u_display_name,
       u.webauthn_user_id AS u_webauthn_user_id, u.is_admin AS u_is_admin,
       u.created_at AS u_created_at, u.recovery_token AS u_recovery_token
FROM sessions s
JOIN users u ON u.id = s.user_id
"""


def _challenge(mapping: dict[str, Any]) -> "Challenge":
    return Challenge(
        id=mapping["id"],
        kind=mapping["kind"],
        payload=mapping["payload"],
        created_at=mapping["created_at"],
        expires_at=mapping["expires_at"],
    )


class PostgresDatabase(Database):
    """SQLAlchemy-based PostgreSQL adapter (works with CockroachDB wire)."""

    def __init__(self, url: str = "postgresql+asyncpg://localhost/warden") -> None:
        self.url = url
        self.engine = create_async_engine(url, echo=False, future=True)
        self.session_factory = sessionmaker(
            self.engine, class_=AsyncSession, expire_on_commit=False
        )

    async def init(self) -> None:
        async with self.engine.begin() as conn:
            # Run per-step schema migrations, tracking versions in
            # ``schema_migrations`` (mirrors the SQLite backend in db.py).
            result = await conn.execute(
                text(
                    "SELECT COALESCE(MAX(version), 0) AS version FROM schema_migrations"
                )
            )
            row = result.fetchone()
            current_version = int(row[0]) if row else 0
            if current_version > self.SCHEMA_VERSION:
                raise DatabaseError(
                    f"Database schema version {current_version} is newer than this Warden build "
                    f"supports ({self.SCHEMA_VERSION})."
                )
            # Run per-step migrations up to the current SCHEMA_VERSION.
            for target_version in range(current_version + 1, self.SCHEMA_VERSION + 1):
                migration = self._MIGRATIONS.get(target_version)
                if migration is None:
                    raise DatabaseError(
                        f"No migration script defined for schema version {target_version}."
                    )
                await conn.execute(text(migration))
                await conn.execute(
                    text(
                        "INSERT INTO schema_migrations (version, applied_on) VALUES (:v, :t)"
                    ),
                    {"v": target_version, "t": time.time()},
                )
            # One-shot schema creation: ensures all tables exist (including any
            # that may not be covered by the per-step migration scripts).
            await conn.run_sync(lambda sync_conn: metadata.create_all(sync_conn))

    async def close(self) -> None:
        await self.engine.dispose()

    # ------------------------------------------------------------------ mesh
    async def list_mesh_peers(self) -> list[MeshPeer]:
        async with self.session_factory() as session:
            result = await session.execute(select(mesh_peers))
            return [MeshPeer(**dict(r._mapping)) for r in result.fetchall()]

    async def add_mesh_peer(
        self,
        *,
        name: str,
        public_key: str,
        private_key: str,
        preshared_key: str,
        address: str,
        endpoint: str | None,
        keepalive: int = 25,
        now: float | None = None,
    ) -> MeshPeer:
        created = now if now is not None else time.time()
        async with self.session_factory() as session:
            try:
                async with session.begin():
                    await session.execute(
                        insert(mesh_peers).values(
                            name=name,
                            public_key=public_key,
                            private_key=private_key,
                            preshared_key=preshared_key,
                            address=address,
                            endpoint=endpoint,
                            keepalive=keepalive,
                            enabled=True,
                            created_at=created,
                        )
                    )
                    await session.commit()
            except IntegrityError:
                raise AlreadyExistsError(
                    "A peer with that name or address already exists."
                )
        result = await session.execute(select(mesh_peers).where(mesh_peers.c.name == name))
        row = result.fetchone()
        if row is None:
            raise DatabaseError("Mesh peer disappeared after creation.")
        return MeshPeer(**dict(row._mapping))

    async def get_mesh_peer(self, peer_id: int) -> MeshPeer | None:
        async with self.session_factory() as session:
            result = await session.execute(
                select(mesh_peers).where(mesh_peers.c.id == peer_id)
            )
            row = result.fetchone()
            return MeshPeer(**dict(row._mapping)) if row else None

    async def delete_mesh_peer(self, peer_id: int) -> bool:
        async with self.session_factory() as session:
            result = await session.execute(delete(mesh_peers).where(mesh_peers.c.id == peer_id))
            await session.commit()
            return result.rowcount > 0

    async def set_mesh_handshake(self, peer_id: int, timestamp: float | None) -> bool:
        async with self.session_factory() as session:
            result = await session.execute(
                update(mesh_peers).where(mesh_peers.c.id == peer_id).values(last_handshake=timestamp)
            )
            await session.commit()
            return result.rowcount > 0

    # ------------------------------------------------------------------ users
    async def user_count(self) -> int:
        async with self.session_factory() as session:
            result = await session.execute(select(func.count(users.c.id)).select_from(users))
            return int(result.scalar() or 0)

    async def create_user(
        self,
        username: str,
        display_name: str,
        webauthn_user_id: bytes,
        *,
        is_admin: bool = True,
        now: float | None = None,
    ) -> "User":
        created = now if now is not None else time.time()
        async with self.session_factory() as session:
            try:
                async with session.begin():
                    await session.execute(
                        insert(users).values(
                            username=username,
                            display_name=display_name,
                            webauthn_user_id=webauthn_user_id,
                            is_admin=bool(is_admin),
                            created_at=created,
                        )
                    )
            except IntegrityError:
                raise AlreadyExistsError("That username is already registered.")
        result = await session.execute(select(users).where(users.c.username == username))
        row = result.fetchone()
        if row is None:
            raise DatabaseError("User disappeared after creation.")
        return _user(row._mapping)

    async def create_user_with_credential(
        self,
        *,
        username: str,
        display_name: str,
        webauthn_user_id: bytes,
        credential_id: bytes,
        public_key: bytes,
        sign_count: int,
        transports: list[str],
        credential_name: str,
        aaguid: str | None,
        fmt: str | None,
        user_verified: bool,
        backup_eligible: bool,
        backup_state: bool,
        setup_mode: bool = False,
        now: float | None = None,
    ) -> tuple["User", "Credential"]:
        created = now if now is not None else time.time()
        async with self.session_factory() as session:
            if setup_mode:
                count_result = await session.execute(
                    select(func.count(users.c.id)).select_from(users)
                )
                if count_result.scalar() > 0:
                    raise AlreadyExistsError("This Warden instance has already been claimed.")
            async with session.begin():
                user_result = await session.execute(
                    insert(users).values(
                        username=username,
                        display_name=display_name,
                        webauthn_user_id=webauthn_user_id,
                        is_admin=True,
                        created_at=created,
                    ).returning(users.c.id)
                )
                user_id = user_result.scalar()
                transports_json = json.dumps(transports)
                cred_result = await session.execute(
                    insert(credentials).values(
                        user_id=user_id,
                        credential_id=credential_id,
                        public_key=public_key,
                        sign_count=sign_count,
                        transports=transports_json,
                        name=credential_name,
                        aaguid=aaguid,
                        fmt=fmt,
                        user_verified=bool(user_verified),
                        backup_eligible=bool(backup_eligible),
                        backup_state=bool(backup_state),
                        created_at=created,
                    ).returning(credentials.c.id)
                )
                credential_row_id = cred_result.scalar()
                if setup_mode:
                    await session.execute(
                        delete(settings).where(
                            settings.c.key.in_(["setup_code_hash", "setup_code_expires_at"])
                        )
                    )
            user_result = await session.execute(select(users).where(users.c.id == user_id))
            user = _user(dict(user_result.fetchone()._mapping))
            cred_result = await session.execute(
                select(credentials).where(credentials.c.id == credential_row_id)
            )
            cred_row = cred_result.fetchone()
            if user is None or cred_row is None:
                raise DatabaseError("User setup failed unexpectedly.")
            return user, _credential(dict(cred_row._mapping))

    async def get_user(self, user_id: int) -> "User | None":
        async with self.session_factory() as session:
            result = await session.execute(select(users).where(users.c.id == user_id))
            row = result.fetchone()
            return _user(row._mapping) if row else None

    async def get_user_by_username(self, username: str) -> "User | None":
        async with self.session_factory() as session:
            result = await session.execute(select(users).where(users.c.username == username))
            row = result.fetchone()
            return _user(row._mapping) if row else None

    async def list_users(self) -> list["User"]:
        async with self.session_factory() as session:
            result = await session.execute(select(users).order_by(users.c.created_at))
            return [_user(r._mapping) for r in result.fetchall()]

    async def get_user_by_webauthn_id(self, webauthn_user_id: bytes) -> "User | None":
        async with self.session_factory() as session:
            result = await session.execute(
                select(users).where(users.c.webauthn_user_id == webauthn_user_id)
            )
            row = result.fetchone()
            return _user(row._mapping) if row else None

    async def delete_user(self, user_id: int) -> bool:
        async with self.session_factory() as session:
            result = await session.execute(delete(users).where(users.c.id == user_id))
            await session.commit()
            return result.rowcount > 0

    async def update_user_admin(self, user_id: int, is_admin: bool) -> bool:
        async with self.session_factory() as session:
            result = await session.execute(
                update(users).where(users.c.id == user_id).values(is_admin=bool(is_admin))
            )
            await session.commit()
            return result.rowcount > 0

    # ------------------------------------------------------------------ credentials
    async def add_credential(
        self,
        *,
        user_id: int,
        credential_id: bytes,
        public_key: bytes,
        sign_count: int,
        transports: list[str],
        name: str,
        aaguid: str | None,
        fmt: str | None,
        user_verified: bool,
        backup_eligible: bool,
        backup_state: bool,
        now: float | None = None,
    ) -> "Credential":
        created = now if now is not None else time.time()
        async with self.session_factory() as session:
            try:
                async with session.begin():
                    await session.execute(
                        insert(credentials).values(
                            user_id=user_id,
                            credential_id=credential_id,
                            public_key=public_key,
                            sign_count=sign_count,
                            transports=json.dumps(transports),
                            name=name,
                            aaguid=aaguid,
                            fmt=fmt,
                            user_verified=bool(user_verified),
                            backup_eligible=bool(backup_eligible),
                            backup_state=bool(backup_state),
                            created_at=created,
                        )
                    )
            except IntegrityError:
                raise AlreadyExistsError("That passkey is already registered.")
        credential = await self.get_credential_by_id(credential_id)
        if credential is None:
            raise DatabaseError("Credential disappeared after creation.")
        return credential

    async def get_credential(self, credential_row_id: int) -> "Credential | None":
        async with self.session_factory() as session:
            result = await session.execute(
                select(credentials).where(credentials.c.id == credential_row_id)
            )
            row = result.fetchone()
            return _credential(row._mapping) if row else None

    async def get_credential_by_id(self, credential_id: bytes) -> "Credential | None":
        async with self.session_factory() as session:
            result = await session.execute(
                select(credentials).where(credentials.c.credential_id == credential_id)
            )
            row = result.fetchone()
            return _credential(row._mapping) if row else None

    async def list_credentials(self, user_id: int | None = None) -> list["Credential"]:
        async with self.session_factory() as session:
            if user_id is None:
                result = await session.execute(select(credentials).order_by(credentials.c.created_at))
            else:
                result = await session.execute(
                    select(credentials)
                    .where(credentials.c.user_id == user_id)
                    .order_by(credentials.c.created_at)
                )
            return [_credential(r._mapping) for r in result.fetchall()]

    async def count_credentials(self, user_id: int | None = None) -> int:
        async with self.session_factory() as session:
            stmt = select(func.count(credentials.c.id))
            if user_id is not None:
                stmt = stmt.where(credentials.c.user_id == user_id)
            result = await session.execute(stmt)
            return int(result.scalar() or 0)

    async def update_credential_use(self, credential_row_id: int, sign_count: int, *, now: float | None = None) -> None:
        used = now if now is not None else time.time()
        async with self.session_factory() as session:
            await session.execute(
                update(credentials)
                .where(credentials.c.id == credential_row_id)
                .values(sign_count=sign_count, last_used_at=used)
            )
            await session.commit()

    async def rename_credential(self, user_id: int, credential_row_id: int, name: str) -> bool:
        async with self.session_factory() as session:
            result = await session.execute(
                update(credentials)
                .where(credentials.c.user_id == user_id, credentials.c.id == credential_row_id)
                .values(name=name)
            )
            await session.commit()
            return result.rowcount > 0

    async def delete_credential(self, user_id: int, credential_row_id: int) -> bool:
        async with self.session_factory() as session:
            result = await session.execute(
                delete(credentials)
                .where(credentials.c.user_id == user_id, credentials.c.id == credential_row_id)
            )
            await session.commit()
            return result.rowcount > 0

    # ------------------------------------------------------------------ reset / vacuum


        async with self.session_factory() as session:
            await session.execute(delete(users))
            await session.execute(delete(credentials))
            await session.execute(delete(sessions))
            await session.execute(delete(challenges))
            await session.execute(delete(backup_codes))
            await session.execute(delete(otp_secrets))
            await session.execute(delete(settings))
            await session.execute(delete(audit))
            await session.execute(delete(mesh_peers))
            await session.commit()

    async def vacuum(self) -> None:
        async with self.session_factory() as session:
            await session.execute(text("VACUUM"))

    # ------------------------------------------------------------------ sessions
    async def create_session(
        self,
        token_hash: str,
        user_id: int,
        expires_at: float,
        *,
        ip: str | None = None,
        user_agent: str | None = None,
        now: float | None = None,
    ) -> int:
        created = now if now is not None else time.time()
        async with self.session_factory() as session:
            result = await session.execute(
                insert(sessions).values(
                    token_hash=token_hash,
                    user_id=user_id,
                    created_at=created,
                    expires_at=expires_at,
                    last_seen_at=created,
                    ip=ip,
                    user_agent=user_agent,
                ).returning(sessions.c.id)
            )
            await session.commit()
            return int(result.scalar() or 0)

    async def get_session(
        self, token_hash: str, *, now: float | None = None, touch: bool = True
    ) -> "Session | None":
        current = now if now is not None else time.time()
        async with self.session_factory() as session:
            result = await session.execute(
                text(_SESSION_JOIN + "WHERE s.token_hash = :h"), {"h": token_hash}
            )
            row = result.fetchone()
            if row is None:
                return None
            s = _session(row._mapping)
            if s.expires_at <= current:
                await self.revoke_session_by_hash(token_hash)
                return None
            if touch and current - s.last_seen_at > 300:
                await session.execute(
                    update(sessions).where(sessions.c.id == s.id).values(last_seen_at=current)
                )
                s.last_seen_at = current
            return s

    async def list_sessions(self, user_id: int, *, current_token_hash: str | None = None) -> list["Session"]:
        async with self.session_factory() as session:
            stmt = text(_SESSION_JOIN + "WHERE s.user_id = :uid")
            if current_token_hash is not None:
                stmt = stmt + text("AND s.token_hash <> :h")
            result = await session.execute(stmt, {"uid": user_id, "h": current_token_hash})
            return [_session(r._mapping) for r in result.fetchall()]

    async def revoke_session(self, user_id: int, session_id: int) -> bool:
        async with self.session_factory() as session:
            result = await session.execute(
                delete(sessions).where(
                    and_(sessions.c.user_id == user_id, sessions.c.id == session_id)
                )
            )
            await session.commit()
            return result.rowcount > 0

    async def revoke_session_by_hash(self, token_hash: str) -> None:
        async with self.session_factory() as session:
            await session.execute(delete(sessions).where(sessions.c.token_hash == token_hash))
            await session.commit()

    async def revoke_other_sessions(self, user_id: int, keep_token_hash: str) -> int:
        async with self.session_factory() as session:
            result = await session.execute(
                delete(sessions).where(
                    and_(sessions.c.user_id == user_id, sessions.c.token_hash != keep_token_hash)
                )
            )
            await session.commit()
            return int(result.rowcount or 0)

    async def delete_expired_sessions(self) -> int:
        async with self.session_factory() as session:
            result = await session.execute(
                delete(sessions).where(sessions.c.expires_at < time.time())
            )
            await session.commit()
            return int(result.rowcount or 0)

    # ------------------------------------------------------------------ challenges
    async def create_challenge(
        self, challenge_id: str, kind: str, payload: dict, ttl_seconds: int, *, now: float | None = None
    ) -> "Challenge":
        created = now if now is not None else time.time()
        expires_at = created + ttl_seconds
        async with self.session_factory() as session:
            await session.execute(
                insert(challenges).values(
                    id=challenge_id, kind=kind, payload=json.dumps(payload),
                    created_at=created, expires_at=expires_at,
                )
            )
            await session.commit()
        result = await session.execute(
            select(challenges).where(challenges.c.id == challenge_id)
        )
        row = result.fetchone()
        if row is None:
            raise DatabaseError("Challenge disappeared after creation.")
        return _challenge(dict(row._mapping))

    async def consume_challenge(self, challenge_id: str, kind: str, *, now: float | None = None) -> "Challenge | None":
        current = now if now is not None else time.time()
        async with self.session_factory() as session:
            result = await session.execute(
                select(challenges).where(
                    and_(challenges.c.id == challenge_id, challenges.c.kind == kind)
                )
            )
            row = result.fetchone()
            if row is None:
                return None
            payload = row["payload"]
            await session.execute(delete(challenges).where(challenges.c.id == challenge_id))
            await session.commit()
            return _challenge(
                {
                    "id": row["id"],
                    "kind": row["kind"],
                    "payload": payload,
                    "created_at": row["created_at"],
                    "expires_at": row["expires_at"],
                }
            )

    async def delete_expired_challenges(self) -> int:
        async with self.session_factory() as session:
            result = await session.execute(
                delete(challenges).where(challenges.c.expires_at < time.time())
            )
            await session.commit()
            return int(result.rowcount or 0)

    # ------------------------------------------------------------------ settings
    async def get_setting(self, key: str) -> str | None:
        async with self.session_factory() as session:
            result = await session.execute(select(settings.c.value).where(settings.c.key == key))
            row = result.fetchone()
            return row["value"] if row else None

    async def set_setting(self, key: str, value: str) -> None:
        async with self.session_factory() as session:
            await session.execute(
                text(
                    "INSERT INTO settings (key, value) VALUES (:key, :value) "
                    "ON CONFLICT (key) DO UPDATE SET value = :value"
                ),
                {"key": key, "value": value},
            )
            await session.commit()

    async def delete_setting(self, key: str) -> None:
        async with self.session_factory() as session:
            await session.execute(delete(settings).where(settings.c.key == key))
            await session.commit()

    # ------------------------------------------------------------------ audit
    async def audit(
        self,
        event: str,
        *,
        user_id: int | None = None,
        username: str | None = None,
        ip: str | None = None,
        user_agent: str | None = None,
        detail: dict | None = None,
    ) -> None:
        async with self.session_factory() as session:
            await session.execute(
                insert(audit).values(
                    created_at=time.time(),
                    event=event,
                    user_id=user_id,
                    username=username,
                    ip=ip,
                    user_agent=user_agent,
                    detail=json.dumps(detail) if detail is not None else None,
                )
            )
            await session.commit()

    async def list_audit(self, limit: int = 50) -> list["AuditEvent"]:
        async with self.session_factory() as session:
            result = await session.execute(select(audit).order_by(audit.c.id.desc()).limit(limit))
            return [_audit(r._mapping) for r in result.fetchall()]

    async def count_audit(self, *, event: str | None = None, since: float | None = None) -> int:
        async with self.session_factory() as session:
            stmt = select(func.count(audit.c.id))
            if event is not None:
                stmt = stmt.where(audit.c.event == event)
            if since is not None:
                stmt = stmt.where(audit.c.created_at >= since)
            result = await session.execute(stmt)
            return int(result.scalar() or 0)

    # ------------------------------------------------------------------ backup codes
    async def add_backup_code(self, user_id: int, code_hash: str, now: float | None = None) -> int:
        created = now if now is not None else time.time()
        async with self.session_factory() as session:
            try:
                async with session.begin():
                    await session.execute(
                        insert(backup_codes).values(
                            user_id=user_id, code_hash=code_hash, created_at=created
                        )
                    )
                    await session.commit()
            except IntegrityError:
                raise AlreadyExistsError("A backup code was already issued for this user.")
        result = await session.execute(
            select(backup_codes.c.id).where(backup_codes.c.user_id == user_id).order_by(backup_codes.c.id.desc()).limit(1)
        )
        return int(result.scalar() or 0)

    async def use_backup_code(self, code_hash: str) -> int | None:
        async with self.session_factory() as session:
            async with session.begin():
                result = await session.execute(
                    update(backup_codes).where(backup_codes.c.code_hash == code_hash).values(used_at=time.time())
                )
                if result.rowcount == 0:
                    await session.commit()
                    return None
                row = await session.execute(
                    select(backup_codes.c.user_id).where(backup_codes.c.code_hash == code_hash)
                )
                await session.commit()
                return int(row.scalar() or 0)

    async def list_backup_codes(self, user_id: int) -> list["BackupCode"]:
        async with self.session_factory() as session:
            result = await session.execute(
                select(backup_codes).where(backup_codes.c.user_id == user_id).order_by(backup_codes.c.id)
            )
            return [
                BackupCode(
                    id=r["id"], user_id=r["user_id"], code_hash=r["code_hash"],
                    created_at=r["created_at"], used_at=r["used_at"],
                )
                for r in result.fetchall()
            ]

    async def clear_backup_codes(self, user_id: int) -> None:
        async with self.session_factory() as session:
            await session.execute(delete(backup_codes).where(backup_codes.c.user_id == user_id))
            await session.commit()

    # ------------------------------------------------------------------ OTP
    async def set_otp_secret(self, user_id: int, secret: str, now: float | None = None) -> None:
        created = now if now is not None else time.time()
        async with self.session_factory() as session:
            await session.execute(
                text(
                    "INSERT INTO otp_secrets (user_id, secret, created_at) VALUES (:user_id, :secret, :created_at) "
                    "ON CONFLICT (user_id) DO UPDATE SET secret = :secret, created_at = :created_at"
                ),
                {
                    "user_id": user_id,
                    "secret": secret,
                    "created_at": created,
                },
            )
            await session.commit()

    async def get_otp_secret(self, user_id: int) -> str | None:
        async with self.session_factory() as session:
            result = await session.execute(
                select(otp_secrets.c.secret).where(otp_secrets.c.user_id == user_id)
            )
            row = result.fetchone()
            return row["secret"] if row else None

    async def verify_otp(self, user_id: int, code: str, *, window: int = 1) -> bool:
        secret = await self.get_otp_secret(user_id)
        if not secret:
            return False
        try:
            import base64

            import hashlib

            import hmac

            import struct

            key = base64.b32decode(secret.upper().replace(" ", ""), casefold=True)
            interval = int(time.time() // 30)
            for offset in range(-window, window + 1):
                counter = interval + offset
                msg = struct.pack(">Q", counter)
                h = hmac.new(key, msg, hashlib.sha1).digest()
                o = h[-1] & 0x0F
                token = (struct.unpack(">I", h[o : o + 4])[0] & 0x7fffffff) % 1000000
                if f"{token:06d}" == code:
                    return True
        except Exception:
            return False
        return False

    # ------------------------------------------------------------------ mesh (extra)
    async def get_mesh_peer(self, peer_id: int) -> MeshPeer | None:
        async with self.session_factory() as session:
            result = await session.execute(
                select(mesh_peers).where(mesh_peers.c.id == peer_id)
            )
            row = result.fetchone()
            return MeshPeer(**dict(row._mapping)) if row else None

    async def delete_mesh_peer(self, peer_id: int) -> bool:
        async with self.session_factory() as session:
            result = await session.execute(delete(mesh_peers).where(mesh_peers.c.id == peer_id))
            await session.commit()
            return result.rowcount > 0

    async def set_mesh_handshake(self, peer_id: int, timestamp: float | None) -> bool:
        async with self.session_factory() as session:
            result = await session.execute(
                update(mesh_peers).where(mesh_peers.c.id == peer_id).values(last_handshake=timestamp)
            )
            await session.commit()
            return result.rowcount > 0
