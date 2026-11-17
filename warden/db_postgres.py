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

import hashlib
import json
import logging
import time
from typing import Any

logger = logging.getLogger(__name__)

try:
    import asyncpg
except ImportError:
    asyncpg = None  # type: ignore[assignment]

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
    make_url,
    select,
    text,
    update,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from warden.db import (
    DEFAULT_ACL_GROUP,
    AclGroup,
    AlreadyExistsError,
    AuditEvent,
    BackupCode,
    Challenge,
    Credential,
    Database,
    DatabaseError,
    MeshPeer,
    Session,
    User,
    _audit,
    _clean_group_name,
    _credential,
    _session,
    _session_touch_interval,
    _user,
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
    Column("email", Text, nullable=True),
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

invites = Table(
    "invites",
    metadata,
    Column("id", BigInteger, primary_key=True, autoincrement=True),
    Column("user_id", BigInteger, ForeignKey("users.id"), nullable=False),
    Column("token_hash", String, nullable=False, unique=True),
    Column("expires_at", Float, nullable=False),
    Column("used", Integer, nullable=False, default=0),
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

acl_groups = Table(
    "acl_groups",
    metadata,
    Column("id", BigInteger, primary_key=True, autoincrement=True),
    Column("name", String, nullable=False),
    Column("created_at", Float, nullable=False),
)

acl_members = Table(
    "acl_members",
    metadata,
    Column("group_id", BigInteger, ForeignKey("acl_groups.id"), primary_key=True),
    Column("user_id", BigInteger, ForeignKey("users.id"), primary_key=True),
    Column("created_at", Float, nullable=False),
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
    4: """\
        CREATE TABLE IF NOT EXISTS invites (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token_hash TEXT NOT NULL UNIQUE,
            expires_at DOUBLE PRECISION NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            created_at DOUBLE PRECISION NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_invites_user ON invites(user_id);
        CREATE INDEX IF NOT EXISTS idx_invites_token ON invites(token_hash);
        CREATE INDEX IF NOT EXISTS idx_invites_used ON invites(used);
        """,
    5: """\
        -- Add user email address for invite delivery and account notices.
        ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT
        """,
    6: """
        -- Named groups for per-route ACLs, mirroring the SQLite schema.
        CREATE TABLE IF NOT EXISTS acl_groups (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            name TEXT NOT NULL,
            created_at DOUBLE PRECISION NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_acl_groups_name
        ON acl_groups (lower(name));

        CREATE TABLE IF NOT EXISTS acl_members (
            group_id BIGINT NOT NULL REFERENCES acl_groups(id) ON DELETE CASCADE,
            user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at DOUBLE PRECISION NOT NULL,
            PRIMARY KEY (group_id, user_id)
        );
        CREATE INDEX IF NOT EXISTS idx_acl_members_user ON acl_members(user_id);

        INSERT INTO acl_groups (name, created_at)
        VALUES ('Users', EXTRACT(EPOCH FROM NOW()))
        ON CONFLICT DO NOTHING
        """,
}  # type: ignore[assignment]


# Column list that mirrors warden/db.py's ``_SESSION_JOIN`` so the
# ``_session`` / ``_user`` row builders can be reused verbatim.
_SESSION_JOIN = """
SELECT s.id, s.token_hash, s.user_id, s.created_at, s.expires_at, s.last_seen_at,
       s.ip, s.user_agent,
       u.id AS u_id, u.username AS u_username, u.display_name AS u_display_name,
       u.webauthn_user_id AS u_webauthn_user_id, u.is_admin AS u_is_admin,
       u.created_at AS u_created_at, u.recovery_token AS u_recovery_token,
       u.email AS u_email,
       COALESCE((
           SELECT string_agg(g.name, chr(31))
           FROM acl_members m
           JOIN acl_groups g ON g.id = m.group_id
           WHERE m.user_id = u.id
       ), '') AS u_groups
FROM sessions s
JOIN users u ON u.id = s.user_id
"""


def _challenge(mapping: dict[str, Any]) -> Challenge:
    """_challenge."""
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
        """__init__."""
        self.url = url
        self.engine = create_async_engine(url, echo=False, future=True)
        self.session_factory = sessionmaker(
            self.engine, class_=AsyncSession, expire_on_commit=False
        )

    async def _ensure_database_exists(self) -> None:
        """_ensure_database_exists."""
        if asyncpg is None:
            raise DatabaseError(
                "asyncpg is required for PostgreSQL auto-create support. "
                "Install it with: pip install asyncpg"
            )
        parsed = make_url(self.url)
        database = parsed.database
        if not database:
            return
        default_url = parsed.set(database="postgres")
        dsn = default_url.render_as_string(hide_password=False).replace(
            "postgresql+asyncpg://", "postgresql://"
        )
        conn = await asyncpg.connect(dsn)
        try:
            result = await conn.fetchval(
                "SELECT 1 FROM pg_database WHERE datname = $1", database
            )
            if result is None:
                await conn.execute(f'CREATE DATABASE "{database}"')
        finally:
            await conn.close()

    async def init(self) -> None:
        """init."""
        await self._ensure_database_exists()
        async with self.engine.begin() as conn:
            # Only create the migration-tracking table here. The actual
            # application schema is created by the numbered migrations below,
            # so a fresh database does not get a ``metadata.create_all()``
            # schema that later conflicts with ``ALTER TABLE`` steps (for
            # example, v5 adding ``users.email``).
            await conn.run_sync(
                lambda sync_conn: schema_migrations.create(sync_conn, checkfirst=True)
            )
            # Per-step schema migrations, tracking versions in
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
            # asyncpg cannot execute a multi-statement string in a single
            # ``conn.execute()`` call, so split each migration into its
            # individual statements and run them one at a time.
            for target_version in range(current_version + 1, self.SCHEMA_VERSION + 1):
                migration = self._MIGRATIONS.get(target_version)
                if migration is None:
                    raise DatabaseError(
                        f"No migration script defined for schema version {target_version}."
                    )
                for statement in migration.split(";"):
                    statement = statement.strip()
                    if statement:
                        await conn.execute(text(statement))
                await conn.execute(
                    text(
                        "INSERT INTO schema_migrations (version, applied_on) VALUES (:v, :t)"
                    ),
                    {"v": target_version, "t": time.time()},
                )

    async def close(self) -> None:
        """close."""
        await self.engine.dispose()

    #: PostgreSQL-native schema migrations. This mirrors the SQLite backend's
    #: ``Database._MIGRATIONS`` but uses PostgreSQL DDL (identity columns,
    #: ``BYTEA``, ``BOOLEAN``) so the same step definitions serve both
    #: backends. ``init()`` reads it off the class so subclasses inherit a
    #: working Postgres migration set.
    _MIGRATIONS = _MIGRATIONS

    # ------------------------------------------------------------------ mesh
    async def list_mesh_peers(self) -> list[MeshPeer]:
        """list_mesh_peers."""
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
        """add_mesh_peer."""
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
        """get_mesh_peer."""
        async with self.session_factory() as session:
            result = await session.execute(
                select(mesh_peers).where(mesh_peers.c.id == peer_id)
            )
            row = result.fetchone()
            return MeshPeer(**dict(row._mapping)) if row else None

    async def delete_mesh_peer(self, peer_id: int) -> bool:
        """delete_mesh_peer."""
        async with self.session_factory() as session:
            result = await session.execute(delete(mesh_peers).where(mesh_peers.c.id == peer_id))
            await session.commit()
            return result.rowcount > 0

    async def set_mesh_handshake(self, peer_id: int, timestamp: float | None) -> bool:
        """set_mesh_handshake."""
        async with self.session_factory() as session:
            result = await session.execute(
                update(mesh_peers).where(mesh_peers.c.id == peer_id).values(last_handshake=timestamp)
            )
            await session.commit()
            return result.rowcount > 0

    # ------------------------------------------------------------------ users
    async def user_count(self) -> int:
        """user_count."""
        async with self.session_factory() as session:
            result = await session.execute(select(func.count(users.c.id)).select_from(users))
            return int(result.scalar() or 0)

    async def create_user(
        self,
        username: str,
        display_name: str,
        webauthn_user_id: bytes,
        *,
        email: str | None = None,
        is_admin: bool = True,
        now: float | None = None,
    ) -> User:
        """create_user."""
        created = now if now is not None else time.time()
        async with self.session_factory() as session:
            try:
                async with session.begin():
                    values = {
                        "username": username,
                        "display_name": display_name,
                        "webauthn_user_id": webauthn_user_id,
                        "is_admin": bool(is_admin),
                        "created_at": created,
                    }
                    if email is not None:
                        values["email"] = email
                    result = await session.execute(
                        insert(users).values(**values).returning(users.c.id)
                    )
                    user_id = int(result.scalar())
                    default_result = await session.execute(
                        select(acl_groups.c.id).where(
                            func.lower(acl_groups.c.name) == DEFAULT_ACL_GROUP.casefold()
                        )
                    )
                    default_group = default_result.scalar()
                    if default_group is not None:
                        await session.execute(
                            insert(acl_members).values(
                                group_id=default_group,
                                user_id=user_id,
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
    ) -> tuple[User, Credential]:
        """create_user_with_credential."""
        created = now if now is not None else time.time()
        async with self.session_factory() as session:
            async with session.begin():
                if setup_mode:
                    count_result = await session.execute(
                        select(func.count(users.c.id)).select_from(users)
                    )
                    if count_result.scalar() > 0:
                        raise AlreadyExistsError("This Warden instance has already been claimed.")
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
                default_result = await session.execute(
                    select(acl_groups.c.id).where(
                        func.lower(acl_groups.c.name) == DEFAULT_ACL_GROUP.casefold()
                    )
                )
                default_group = default_result.scalar()
                if default_group is not None:
                    await session.execute(
                        insert(acl_members).values(
                            group_id=default_group,
                            user_id=user_id,
                            created_at=created,
                        )
                    )
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

    async def get_user(self, user_id: int) -> User | None:
        """get_user."""
        async with self.session_factory() as session:
            result = await session.execute(select(users).where(users.c.id == user_id))
            row = result.fetchone()
            return _user(row._mapping) if row else None

    async def get_user_by_username(self, username: str) -> User | None:
        """get_user_by_username."""
        async with self.session_factory() as session:
            result = await session.execute(select(users).where(users.c.username == username))
            row = result.fetchone()
            return _user(row._mapping) if row else None

    async def list_users(self) -> list[User]:
        """list_users."""
        async with self.session_factory() as session:
            result = await session.execute(select(users).order_by(users.c.created_at))
            return [_user(r._mapping) for r in result.fetchall()]

    async def get_user_by_webauthn_id(self, webauthn_user_id: bytes) -> User | None:
        """get_user_by_webauthn_id."""
        async with self.session_factory() as session:
            result = await session.execute(
                select(users).where(users.c.webauthn_user_id == webauthn_user_id)
            )
            row = result.fetchone()
            return _user(row._mapping) if row else None

    # --------------------------------------------------------------- ACL groups
    async def list_acl_groups(self) -> list[AclGroup]:
        """Return every ACL group with its current member count."""
        async with self.session_factory() as session:
            result = await session.execute(
                select(
                    acl_groups.c.id,
                    acl_groups.c.name,
                    acl_groups.c.created_at,
                    func.count(acl_members.c.user_id).label("member_count"),
                )
                .select_from(acl_groups)
                .join(acl_members, acl_members.c.group_id == acl_groups.c.id, isouter=True)
                .group_by(acl_groups.c.id, acl_groups.c.name, acl_groups.c.created_at)
                .order_by(acl_groups.c.name)
            )
            return [
                AclGroup(
                    id=int(row.id),
                    name=row.name,
                    created_at=float(row.created_at),
                    member_count=int(row.member_count),
                )
                for row in result.fetchall()
            ]

    async def get_acl_group(self, group_id: int) -> AclGroup | None:
        """Fetch a single ACL group, including its member count."""
        async with self.session_factory() as session:
            result = await session.execute(
                select(
                    acl_groups.c.id,
                    acl_groups.c.name,
                    acl_groups.c.created_at,
                    func.count(acl_members.c.user_id).label("member_count"),
                )
                .select_from(acl_groups)
                .join(acl_members, acl_members.c.group_id == acl_groups.c.id, isouter=True)
                .where(acl_groups.c.id == group_id)
                .group_by(acl_groups.c.id, acl_groups.c.name, acl_groups.c.created_at)
            )
            row = result.fetchone()
            if row is None:
                return None
            return AclGroup(
                id=int(row.id),
                name=row.name,
                created_at=float(row.created_at),
                member_count=int(row.member_count),
            )

    async def get_acl_group_by_name(self, name: str) -> AclGroup | None:
        """Fetch an ACL group by name (case-insensitive), or ``None``."""
        try:
            cleaned = _clean_group_name(name)
        except ValueError:
            return None
        async with self.session_factory() as session:
            result = await session.execute(
                select(acl_groups.c.id).where(
                    func.lower(acl_groups.c.name) == cleaned.casefold()
                )
            )
            row = result.fetchone()
        return await self.get_acl_group(int(row.id)) if row else None

    async def create_acl_group(self, name: str, *, now: float | None = None) -> AclGroup:
        """Create a named ACL group. Raises ``AlreadyExistsError`` on a clash."""
        cleaned = _clean_group_name(name)
        async with self.session_factory() as session:
            try:
                result = await session.execute(
                    insert(acl_groups)
                    .values(name=cleaned, created_at=now if now is not None else time.time())
                    .returning(acl_groups.c.id)
                )
                await session.commit()
            except IntegrityError as exc:
                raise AlreadyExistsError(f"A group named {cleaned!r} already exists.") from exc
            group_id = int(result.scalar_one())
        group = await self.get_acl_group(group_id)
        if group is None:
            raise DatabaseError("Group disappeared after creation.")
        return group

    async def delete_acl_group(self, group_id: int) -> bool:
        """Delete a group and its memberships. The default group is permanent."""
        group = await self.get_acl_group(group_id)
        if group is None or group.name.casefold() == DEFAULT_ACL_GROUP.casefold():
            return False
        async with self.session_factory() as session:
            await session.execute(delete(acl_members).where(acl_members.c.group_id == group_id))
            result = await session.execute(delete(acl_groups).where(acl_groups.c.id == group_id))
            await session.commit()
            return result.rowcount > 0

    async def list_user_acl_groups(self, user_id: int) -> list[str]:
        """Return the names of the groups *user_id* belongs to."""
        async with self.session_factory() as session:
            result = await session.execute(
                select(acl_groups.c.name)
                .select_from(acl_members)
                .join(acl_groups, acl_groups.c.id == acl_members.c.group_id)
                .where(acl_members.c.user_id == user_id)
                .order_by(acl_groups.c.name)
            )
            return [row.name for row in result.fetchall()]

    async def acl_memberships(self) -> dict[int, list[str]]:
        """Return ``{user_id: [group names]}`` for every membership."""
        async with self.session_factory() as session:
            result = await session.execute(
                select(acl_members.c.user_id, acl_groups.c.name)
                .select_from(acl_members)
                .join(acl_groups, acl_groups.c.id == acl_members.c.group_id)
                .order_by(acl_groups.c.name)
            )
            memberships: dict[int, list[str]] = {}
            for row in result.fetchall():
                memberships.setdefault(int(row.user_id), []).append(row.name)
            return memberships

    async def add_user_to_acl_group(
        self, user_id: int, group_id: int, *, now: float | None = None
    ) -> bool:
        """Add a user to a group. Returns ``False`` if either side is missing."""
        if await self.get_acl_group(group_id) is None or await self.get_user(user_id) is None:
            return False
        async with self.session_factory() as session:
            await session.execute(
                insert(acl_members).values(
                    group_id=group_id,
                    user_id=user_id,
                    created_at=now if now is not None else time.time(),
                )
            )
            await session.commit()
        return True

    async def remove_user_from_acl_group(self, user_id: int, group_id: int) -> bool:
        """Remove a membership. Members cannot leave the default group."""
        group = await self.get_acl_group(group_id)
        if group is None or group.name.casefold() == DEFAULT_ACL_GROUP.casefold():
            return False
        async with self.session_factory() as session:
            result = await session.execute(
                delete(acl_members).where(
                    acl_members.c.user_id == user_id, acl_members.c.group_id == group_id
                )
            )
            await session.commit()
            return result.rowcount > 0

    async def set_user_acl_groups(self, user_id: int, names: list[str]) -> list[str]:
        """Replace a user's memberships, always keeping the default group."""
        if await self.get_user(user_id) is None:
            raise ValueError("That user does not exist.")
        group_ids: set[int] = set()
        for name in dict.fromkeys(names):
            group = await self.get_acl_group_by_name(name)
            if group is None:
                raise ValueError(f"No group named {name!r}.")
            group_ids.add(group.id)
        default = await self._ensure_default_acl_group()
        group_ids.add(default.id)
        async with self.session_factory() as session:
            await session.execute(delete(acl_members).where(acl_members.c.user_id == user_id))
            now = time.time()
            for group_id in sorted(group_ids):
                await session.execute(
                    insert(acl_members).values(
                        group_id=group_id, user_id=user_id, created_at=now
                    )
                )
            await session.commit()
        return await self.list_user_acl_groups(user_id)

    async def _ensure_default_acl_group(self) -> AclGroup:
        """Return the built-in group, creating it if the row is missing."""
        group = await self.get_acl_group_by_name(DEFAULT_ACL_GROUP)
        if group is not None:
            return group
        try:
            return await self.create_acl_group(DEFAULT_ACL_GROUP)
        except AlreadyExistsError:
            group = await self.get_acl_group_by_name(DEFAULT_ACL_GROUP)
            if group is None:
                raise
            return group

    async def delete_user(self, user_id: int) -> bool:
        """delete_user."""
        async with self.session_factory() as session:
            # Databases created by older versions used ``metadata.create_all``
            # without ``ON DELETE CASCADE``, so remove child rows explicitly
            # before deleting the user.
            await session.execute(delete(invites).where(invites.c.user_id == user_id))
            await session.execute(
                delete(acl_members).where(acl_members.c.user_id == user_id)
            )
            await session.execute(
                delete(backup_codes).where(backup_codes.c.user_id == user_id)
            )
            await session.execute(
                delete(otp_secrets).where(otp_secrets.c.user_id == user_id)
            )
            await session.execute(delete(sessions).where(sessions.c.user_id == user_id))
            await session.execute(
                delete(credentials).where(credentials.c.user_id == user_id)
            )
            await session.execute(
                update(audit).where(audit.c.user_id == user_id).values(user_id=None)
            )
            result = await session.execute(delete(users).where(users.c.id == user_id))
            await session.commit()
            return result.rowcount > 0

    async def update_user_admin(self, user_id: int, is_admin: bool) -> bool:
        """update_user_admin."""
        async with self.session_factory() as session:
            result = await session.execute(
                update(users).where(users.c.id == user_id).values(is_admin=bool(is_admin))
            )
            await session.commit()
            return result.rowcount > 0

    async def demote_admin(self, user_id: int) -> bool:
        """Clear ``is_admin`` unless the user is the last remaining admin."""
        async with self.session_factory() as session:
            remaining = (
                select(func.count(users.c.id))
                .where(users.c.is_admin.is_(True))
                .scalar_subquery()
            )
            result = await session.execute(
                update(users)
                .where(users.c.id == user_id, remaining > 1)
                .values(is_admin=False)
            )
            await session.commit()
            return result.rowcount > 0

    async def update_user_display_name(self, user_id: int, display_name: str) -> bool:
        """update_user_display_name."""
        async with self.session_factory() as session:
            result = await session.execute(
                update(users).where(users.c.id == user_id).values(display_name=display_name)
            )
            await session.commit()
            return result.rowcount > 0

    async def update_user_email(self, user_id: int, email: str | None) -> bool:
        """update_user_email."""
        async with self.session_factory() as session:
            result = await session.execute(
                update(users).where(users.c.id == user_id).values(email=email)
            )
            await session.commit()
            return result.rowcount > 0

    # ------------------------------------------------------------------ invites
    async def create_invite(
        self,
        user_id: int,
        token: str,
        expires_at: float,
        *,
        now: float | None = None,
    ) -> int:
        """Create an invite for ``user_id``. The raw token is stored only as a hash."""
        created = now if now is not None else time.time()
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        async with self.session_factory() as session:
            result = await session.execute(
                insert(invites)
                .values(
                    user_id=user_id,
                    token_hash=token_hash,
                    expires_at=expires_at,
                    used=0,
                    created_at=created,
                )
                .returning(invites.c.id)
            )
            await session.commit()
            return int(result.scalar() or 0)

    async def get_invite(self, token: str) -> Any:
        """get_invite."""
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        async with self.session_factory() as session:
            result = await session.execute(
                select(invites).where(invites.c.token_hash == token_hash)
            )
            row = result.fetchone()
            return dict(row._mapping) if row else None

    async def mark_invite_used(self, invite_id: int) -> bool:
        """mark_invite_used."""
        async with self.session_factory() as session:
            result = await session.execute(
                update(invites)
                .where(invites.c.id == invite_id, invites.c.used == 0)
                .values(used=1)
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
    ) -> Credential:
        """add_credential."""
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

    async def get_credential(self, credential_row_id: int) -> Credential | None:
        """get_credential."""
        async with self.session_factory() as session:
            result = await session.execute(
                select(credentials).where(credentials.c.id == credential_row_id)
            )
            row = result.fetchone()
            return _credential(row._mapping) if row else None

    async def get_credential_by_id(self, credential_id: bytes) -> Credential | None:
        """get_credential_by_id."""
        async with self.session_factory() as session:
            result = await session.execute(
                select(credentials).where(credentials.c.credential_id == credential_id)
            )
            row = result.fetchone()
            return _credential(row._mapping) if row else None

    async def list_credentials(self, user_id: int | None = None) -> list[Credential]:
        """list_credentials."""
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
        """count_credentials."""
        async with self.session_factory() as session:
            stmt = select(func.count(credentials.c.id))
            if user_id is not None:
                stmt = stmt.where(credentials.c.user_id == user_id)
            result = await session.execute(stmt)
            return int(result.scalar() or 0)

    async def update_credential_use(self, credential_row_id: int, sign_count: int, *, now: float | None = None) -> None:
        """update_credential_use."""
        used = now if now is not None else time.time()
        async with self.session_factory() as session:
            await session.execute(
                update(credentials)
                .where(credentials.c.id == credential_row_id)
                .values(sign_count=sign_count, last_used_at=used)
            )
            await session.commit()

    async def rename_credential(self, user_id: int, credential_row_id: int, name: str) -> bool:
        """rename_credential."""
        async with self.session_factory() as session:
            result = await session.execute(
                update(credentials)
                .where(credentials.c.user_id == user_id, credentials.c.id == credential_row_id)
                .values(name=name)
            )
            await session.commit()
            return result.rowcount > 0

    async def delete_credential(self, user_id: int, credential_row_id: int) -> bool:
        """delete_credential."""
        async with self.session_factory() as session:
            result = await session.execute(
                delete(credentials)
                .where(credentials.c.user_id == user_id, credentials.c.id == credential_row_id)
            )
            await session.commit()
            return result.rowcount > 0

    async def reset_auth(self) -> None:
        """Delete all users, credentials, sessions, challenges, backup codes,
        OTP secrets, invites, settings, audit log, and mesh peers (auth reset)."""
        async with self.session_factory() as session:
            # Child rows first: older databases may lack ON DELETE CASCADE.
            await session.execute(delete(invites))
            await session.execute(delete(backup_codes))
            await session.execute(delete(otp_secrets))
            await session.execute(delete(sessions))
            await session.execute(delete(credentials))
            await session.execute(delete(challenges))
            await session.execute(delete(settings))
            await session.execute(delete(audit))
            await session.execute(delete(mesh_peers))
            await session.execute(delete(users))
            await session.commit()

    # ------------------------------------------------------------------ reset / vacuum

    async def health_check(self) -> bool:
        """health_check."""
        try:
            async with self.session_factory() as session:
                await session.execute(text("SELECT 1"))
            return True
        except Exception:  # noqa: BLE001
            return False

    async def vacuum(self) -> None:
        # PostgreSQL relies on ``autovacuum`` (enabled by default) to reclaim
        # dead tuples and keep bloat under control. Manual ``VACUUM`` holds a
        # pooled connection for the duration of the checkpoint, which can
        # starve other requests; rely on autovacuum instead.
        """vacuum."""
        logger.debug(
            "Skipping manual VACUUM on Postgres (relying on autovacuum)"
        )

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
        """create_session."""
        created = now if now is not None else time.time()
        config = getattr(self, "config", None)
        server_cfg = config.server if hasattr(config, "server") else config
        max_sessions = getattr(server_cfg, "max_sessions_per_user", None) if server_cfg is not None else None
        async with self.session_factory() as session:
            if max_sessions is not None and max_sessions > 0:
                result = await session.execute(
                    select(sessions.c.id)
                    .where(sessions.c.user_id == user_id, sessions.c.expires_at > created)
                    .order_by(sessions.c.created_at.asc()),
                )
                current = [row[0] for row in result.fetchall()]
                if len(current) >= max_sessions:
                    overflow = len(current) - max_sessions + 1
                    await session.execute(
                        delete(sessions).where(sessions.c.id.in_(current[:overflow]))
                    )
                    await session.commit()
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
    ) -> Session | None:
        """get_session."""
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
            if touch and current - s.last_seen_at > _session_touch_interval(s.id):
                await session.execute(
                    update(sessions).where(sessions.c.id == s.id).values(last_seen_at=current)
                )
                s.last_seen_at = current
            return s

    async def list_sessions(self, user_id: int, *, current_token_hash: str | None = None) -> list[Session]:
        """list_sessions."""
        async with self.session_factory() as session:
            sql = (
                _SESSION_JOIN
                + "WHERE s.user_id = :uid AND s.expires_at > :now "
                + "ORDER BY s.last_seen_at DESC"
            )
            params: dict[str, Any] = {"uid": user_id, "now": time.time()}
            if current_token_hash is not None:
                sql += " AND s.token_hash <> :h"
                params["h"] = current_token_hash
            result = await session.execute(text(sql), params)
            return [_session(r._mapping) for r in result.fetchall()]

    async def revoke_session(self, user_id: int, session_id: int) -> bool:
        """revoke_session."""
        async with self.session_factory() as session:
            result = await session.execute(
                delete(sessions).where(
                    and_(sessions.c.user_id == user_id, sessions.c.id == session_id)
                )
            )
            await session.commit()
            return result.rowcount > 0

    async def revoke_session_by_hash(self, token_hash: str) -> None:
        """revoke_session_by_hash."""
        async with self.session_factory() as session:
            await session.execute(delete(sessions).where(sessions.c.token_hash == token_hash))
            await session.commit()

    async def revoke_other_sessions(self, user_id: int, keep_token_hash: str) -> int:
        """revoke_other_sessions."""
        async with self.session_factory() as session:
            result = await session.execute(
                delete(sessions).where(
                    and_(sessions.c.user_id == user_id, sessions.c.token_hash != keep_token_hash)
                )
            )
            await session.commit()
            return int(result.rowcount or 0)

    async def delete_expired_sessions(self) -> int:
        """delete_expired_sessions."""
        async with self.session_factory() as session:
            result = await session.execute(
                delete(sessions).where(sessions.c.expires_at < time.time())
            )
            await session.commit()
            return int(result.rowcount or 0)

    # ------------------------------------------------------------------ challenges
    async def create_challenge(
        self, challenge_id: str, kind: str, payload: dict, ttl_seconds: int, *, now: float | None = None
    ) -> Challenge:
        """create_challenge."""
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
            row_data = dict(row._mapping)
            raw_payload = row_data["payload"]  # stored as JSON text; always a str at runtime
            try:
                payload = json.loads(raw_payload) if raw_payload else {}  # type: ignore[arg-type]
            except (TypeError, ValueError):
                payload = {}
            return _challenge(
                {
                    "id": row_data["id"],
                    "kind": row_data["kind"],
                    "payload": payload,
                    "created_at": row_data["created_at"],
                    "expires_at": row_data["expires_at"],
                }
            )

    async def consume_challenge(self, challenge_id: str, kind: str, *, now: float | None = None) -> Challenge | None:
        """consume_challenge."""
        current = now if now is not None else time.time()
        async with self.session_factory() as session:
            result = await session.execute(
                select(challenges).where(
                    and_(
                        challenges.c.id == challenge_id,
                        challenges.c.kind == kind,
                        challenges.c.expires_at > current,
                    )
                )
            )
            row = result.fetchone()
            if row is None:
                # Remove an expired or wrong-kind challenge so it cannot be
                # replayed later.
                await session.execute(
                    delete(challenges).where(challenges.c.id == challenge_id)
                )
                await session.commit()
                return None
            row_data = dict(row._mapping)
            raw_payload = row_data["payload"]  # stored as JSON text; always a str at runtime
            await session.execute(delete(challenges).where(challenges.c.id == challenge_id))
            await session.commit()
            try:
                payload = json.loads(raw_payload) if raw_payload else {}  # type: ignore[arg-type]
            except (TypeError, ValueError):
                payload = {}
            return _challenge(
                {
                    "id": row_data["id"],
                    "kind": row_data["kind"],
                    "payload": payload,
                    "created_at": row_data["created_at"],
                    "expires_at": row_data["expires_at"],
                }
            )

    async def delete_expired_challenges(self) -> int:
        """delete_expired_challenges."""
        async with self.session_factory() as session:
            result = await session.execute(
                delete(challenges).where(challenges.c.expires_at < time.time())
            )
            await session.commit()
            return int(result.rowcount or 0)

    # ------------------------------------------------------------------ settings
    async def get_setting(self, key: str) -> str | None:
        """get_setting."""
        async with self.session_factory() as session:
            result = await session.execute(select(settings.c.value).where(settings.c.key == key))
            row = result.fetchone()
            return row._mapping["value"] if row else None

    async def set_setting(self, key: str, value: str) -> None:
        """set_setting."""
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
        """delete_setting."""
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
        detail: str | dict[str, Any] | None = None,
        now: float | None = None,
    ) -> None:
        """audit."""
        async with self.session_factory() as session:
            await session.execute(
                insert(audit).values(
                    created_at=now if now is not None else time.time(),
                    event=event,
                    user_id=user_id,
                    username=username,
                    ip=ip,
                    user_agent=user_agent,
                    detail=json.dumps(detail) if isinstance(detail, dict) else detail,
                )
            )
            await session.commit()

    async def list_audit(
        self,
        limit: int = 50,
        event: str | None = None,
        offset: int = 0,
        since: float | None = None,
    ) -> list[AuditEvent]:
        """list_audit."""
        async with self.session_factory() as session:
            stmt = select(audit)
            if event is not None:
                stmt = stmt.where(audit.c.event == event)
            if since is not None:
                stmt = stmt.where(audit.c.created_at >= since)
            stmt = (
                stmt.order_by(audit.c.created_at.desc(), audit.c.id.desc())
                .limit(limit)
                .offset(offset)
            )
            result = await session.execute(stmt)
            return [_audit(r._mapping) for r in result.fetchall()]

    async def count_audit(self, *, event: str | None = None, since: float | None = None) -> int:
        """count_audit."""
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
        """add_backup_code."""
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
        """use_backup_code."""
        async with self.session_factory() as session, session.begin():
            result = await session.execute(
                update(backup_codes)
                .where(
                    backup_codes.c.code_hash == code_hash,
                    backup_codes.c.used_at.is_(None),
                )
                .values(used_at=time.time())
            )
            if result.rowcount == 0:
                await session.commit()
                return None
            row = await session.execute(
                select(backup_codes.c.user_id).where(backup_codes.c.code_hash == code_hash)
            )
            await session.commit()
            return int(row.scalar() or 0)

    async def list_backup_codes(self, user_id: int) -> list[BackupCode]:
        """list_backup_codes."""
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
        """clear_backup_codes."""
        async with self.session_factory() as session:
            await session.execute(delete(backup_codes).where(backup_codes.c.user_id == user_id))
            await session.commit()

    # ------------------------------------------------------------------ OTP
    async def set_otp_secret(self, user_id: int, secret: str, now: float | None = None) -> None:
        """set_otp_secret."""
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
        """get_otp_secret."""
        async with self.session_factory() as session:
            result = await session.execute(
                select(otp_secrets.c.secret).where(otp_secrets.c.user_id == user_id)
            )
            row = result.fetchone()
            return row._mapping["secret"] if row else None

    async def verify_otp(self, user_id: int, code: str, *, window: int = 1) -> bool:
        """verify_otp."""
        secret = await self.get_otp_secret(user_id)
        if not secret:
            return False
        try:
            import base64
            import binascii
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
        except (binascii.Error, TypeError, struct.error):
            return False
        return False

    # ------------------------------------------------------------------ mesh (extra)
    async def get_mesh_peer(self, peer_id: int) -> MeshPeer | None:  # noqa: F811
        """get_mesh_peer."""
        async with self.session_factory() as session:
            result = await session.execute(
                select(mesh_peers).where(mesh_peers.c.id == peer_id)
            )
            row = result.fetchone()
            return MeshPeer(**dict(row._mapping)) if row else None

    async def delete_mesh_peer(self, peer_id: int) -> bool:  # noqa: F811
        """delete_mesh_peer."""
        async with self.session_factory() as session:
            result = await session.execute(delete(mesh_peers).where(mesh_peers.c.id == peer_id))
            await session.commit()
            return result.rowcount > 0

    async def set_mesh_handshake(self, peer_id: int, timestamp: float | None) -> bool:  # noqa: F811
        """set_mesh_handshake."""
        async with self.session_factory() as session:
            result = await session.execute(
                update(mesh_peers).where(mesh_peers.c.id == peer_id).values(last_handshake=timestamp)
            )
            await session.commit()
            return result.rowcount > 0
