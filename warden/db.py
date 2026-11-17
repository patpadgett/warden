"""Async SQLite persistence layer for Warden.

The module defines data classes representing the main entities (User, Credential,
Session, and :class:`Database` class) exposing async CRUD methods.
All interactions use ``aiosqlite`` with a connection lock to ensure safe
concurrent access.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import sqlite3
import time
from dataclasses import dataclass, replace
from pathlib import Path
from types import MappingProxyType
from typing import Any

logger = logging.getLogger(__name__)

import aiosqlite

#: Built-in ACL group that every account joins on creation. Routes without an
#: ``allowed_groups`` list are open to every signed-in user, so this group only
#: matters once an administrator gives a route a different ACL.
DEFAULT_ACL_GROUP = "Users"

#: Separator used to pack a user's group names into one SQLite column.
_ACL_GROUP_SEPARATOR = "\x1f"


def _sql_statements(script: str) -> list[str]:
    """Split a migration script into individual SQLite statements.

    ``Connection.executescript`` issues an implicit ``COMMIT`` before running,
    which would break the per-migration transaction. Splitting the script lets
    each step run inside an explicit ``BEGIN IMMEDIATE`` block instead.

    Migration scripts in this module contain only plain DDL with ``;``
    terminators and ``--`` line comments; no string literal contains a
    semicolon, so this simple splitter is sufficient.
    """
    statements: list[str] = []
    without_comments = "\n".join(
        line.split("--", 1)[0] for line in script.splitlines()
    )
    for chunk in without_comments.split(";"):
        sql = chunk.strip()
        if sql:
            statements.append(sql)
    return statements


class DatabaseError(Exception):
    """Base class for database‑related errors, such as connection problems or query failures."""


class AlreadyExistsError(DatabaseError):
    """Raised when attempting to create an entity that already exists (e.g., duplicate username or mesh peer)."""


@dataclass(slots=True)
class User:
    """User."""
    id: int
    username: str
    display_name: str
    webauthn_user_id: bytes
    is_admin: bool
    created_at: float
    recovery_token: str | None = None
    email: str | None = None
    groups: tuple[str, ...] = ()


@dataclass(slots=True)
class AclGroup:
    """A named group used for per-route ACLs."""
    id: int
    name: str
    created_at: float
    member_count: int = 0


@dataclass(slots=True)
class Credential:
    """Credential."""
    id: int
    user_id: int
    credential_id: bytes
    public_key: bytes
    sign_count: int
    transports: list[str]
    name: str
    aaguid: str | None
    fmt: str | None
    user_verified: bool
    backup_eligible: bool
    backup_state: bool
    created_at: float
    last_used_at: float | None


@dataclass(slots=True)
class Session:
    """Session."""
    id: int
    token_hash: str
    user_id: int
    created_at: float
    expires_at: float
    last_seen_at: float
    ip: str | None
    user_agent: str | None
    user: User


@dataclass(slots=True)
class Challenge:
    """Challenge."""
    id: str
    kind: str
    payload: dict[str, Any]
    created_at: float
    expires_at: float


@dataclass(slots=True)
class AuditEvent:
    """AuditEvent."""
    id: int
    created_at: float
    event: str
    user_id: int | None
    username: str | None
    ip: str | None
    user_agent: str | None
    detail: str | None




@dataclass(slots=True)
class BackupCode:
    """BackupCode."""
    id: int
    user_id: int
    code_hash: str
    created_at: float
    used_at: float | None


@dataclass(slots=True)
class MeshPeer:
    """MeshPeer."""
    id: int
    name: str
    public_key: str
    private_key: str | None
    preshared_key: str
    address: str
    endpoint: str | None
    keepalive: int
    enabled: bool
    created_at: float
    last_handshake: float | None




def _clean_group_name(name: str) -> str:
    """Normalise an ACL group name.

    Group names are stored as single-line text so they survive YAML/JSON
    round-trips and can be compared against a route's ``allowed_groups``.
    """
    cleaned = " ".join(str(name).split())
    if not cleaned:
        raise ValueError("Group name cannot be empty.")
    if len(cleaned) > 64:
        raise ValueError("Group names are limited to 64 characters.")
    return cleaned


def _field(row: Any, key: str) -> Any:
    """Return ``row[key]`` when the column is present, otherwise ``None``."""
    try:
        keys = row.keys()
    except AttributeError:
        return None
    if key not in keys:
        return None
    return row[key]


def _row_groups(row: Any, key: str) -> tuple[str, ...]:
    """Parse a separator-joined group-name column into a sorted tuple."""
    raw = _field(row, key)
    if not raw:
        return ()
    names = {part for part in str(raw).split(_ACL_GROUP_SEPARATOR) if part}
    return tuple(sorted(names))


def _user(row: aiosqlite.Row) -> User:
    """_user."""
    return User(
        id=row["id"],
        username=row["username"],
        display_name=row["display_name"],
        webauthn_user_id=bytes(row["webauthn_user_id"]),
        is_admin=bool(row["is_admin"]),
        created_at=float(row["created_at"]),
        recovery_token=row["recovery_token"],
        email=row["email"] if "email" in row.keys() else None,  # noqa: SIM118
        groups=_row_groups(row, "groups"),
    )


def _credential(row: aiosqlite.Row) -> Credential:
    """_credential."""
    try:
        transports = json.loads(row["transports"] or "[]")
    except (TypeError, ValueError):
        transports = []
    return Credential(
        id=row["id"],
        user_id=row["user_id"],
        credential_id=bytes(row["credential_id"]),
        public_key=bytes(row["public_key"]),
        sign_count=int(row["sign_count"]),
        transports=[str(item) for item in transports if isinstance(item, str)],
        name=row["name"],
        aaguid=row["aaguid"],
        fmt=row["fmt"],
        user_verified=bool(row["user_verified"]),
        backup_eligible=bool(row["backup_eligible"]),
        backup_state=bool(row["backup_state"]),
        created_at=float(row["created_at"]),
        last_used_at=float(row["last_used_at"]) if row["last_used_at"] else None,
    )


def _session(row: aiosqlite.Row) -> Session:
    """_session."""
    user = User(
        id=row["u_id"],
        username=row["u_username"],
        display_name=row["u_display_name"],
        webauthn_user_id=bytes(row["u_webauthn_user_id"]),
        is_admin=bool(row["u_is_admin"]),
        created_at=float(row["u_created_at"]),
        recovery_token=row["u_recovery_token"],
        email=row["u_email"] if "u_email" in row.keys() else None,  # noqa: SIM118
        groups=_row_groups(row, "u_groups"),
    )
    return Session(
        id=row["id"],
        token_hash=row["token_hash"],
        user_id=row["user_id"],
        created_at=float(row["created_at"]),
        expires_at=float(row["expires_at"]),
        last_seen_at=float(row["last_seen_at"]),
        ip=row["ip"],
        user_agent=row["user_agent"],
        user=user,
    )


def _audit(row: aiosqlite.Row) -> AuditEvent:
    """_audit."""
    return AuditEvent(
        id=row["id"],
        created_at=float(row["created_at"]),
        event=row["event"],
        user_id=row["user_id"],
        username=row["username"],
        ip=row["ip"],
        user_agent=row["user_agent"],
        detail=row["detail"],
    )


def _peer(row: aiosqlite.Row) -> MeshPeer:
    """_peer."""
    return MeshPeer(
        id=row["id"],
        name=row["name"],
        public_key=row["public_key"],
        private_key=row["private_key"],
        preshared_key=row["preshared_key"],
        address=row["address"],
        endpoint=row["endpoint"],
        keepalive=int(row["keepalive"]),
        enabled=bool(row["enabled"]),
        created_at=float(row["created_at"]),
        last_handshake=float(row["last_handshake"]) if row["last_handshake"] else None,
    )


_SESSION_JOIN = """
SELECT s.id, s.token_hash, s.user_id, s.created_at, s.expires_at, s.last_seen_at, s.ip,
       s.user_agent,
       u.id AS u_id, u.username AS u_username, u.display_name AS u_display_name,
       u.webauthn_user_id AS u_webauthn_user_id, u.is_admin AS u_is_admin,
       u.created_at AS u_created_at, u.recovery_token AS u_recovery_token,
       u.email AS u_email,
       COALESCE((
           SELECT group_concat(g.name, char(31))
           FROM acl_members m
           JOIN acl_groups g ON g.id = m.group_id
           WHERE m.user_id = u.id
       ), '') AS u_groups
FROM sessions s
JOIN users u ON u.id = s.user_id
"""


def _session_touch_interval(session_id: int) -> float:
    """Return a jittered touch interval for session keep-alive writes.

    The base interval is 300s; jitter of ±60s spreads writes across sessions
    so they don't all update at once.
    """
    return 300.0 + ((session_id % 121) - 60)  # 240..360


class Database:
    """Async SQLite database wrapper for Warden.

    Provides CRUD operations for users, credentials, sessions, backup codes,
    OTP secrets, and Mesh peers. All methods acquire a lock to ensure
    safe concurrent access in the async environment.
    """
    def __init__(self, path: str | Path) -> None:
        """Initialise the ``Database`` wrapper.

        * ``path`` – location of the SQLite file, or ``":memory:"`` for an
          in‑memory database (used in tests).
        """
        self.path = Path(path) if str(path) != ":memory:" else Path(":memory:")
        self._conn: aiosqlite.Connection | None = None
        self._init_lock = asyncio.Lock()
        self._lock = asyncio.Lock()

    @property
    def is_memory(self) -> bool:
        """is_memory."""
        return str(self.path) == ":memory:"

    async def init(self) -> None:
        """init."""
        async with self._init_lock:
            if self._conn is not None:
                return
            if not self.is_memory:
                self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            try:
                conn = await aiosqlite.connect(
                    ":memory:" if self.is_memory else str(self.path),
                    isolation_level=None,
                )
            except OSError as exc:
                raise DatabaseError(f"Could not open database {self.path}: {exc}") from exc
            conn.row_factory = aiosqlite.Row
            # Publish the connection *before* running any statement: the PRAGMA
            # calls below can raise (a corrupt or non-database file fails on the
            # first one), and the cleanup path needs ``self._conn`` set in order
            # to close it. A connection left open keeps aiosqlite's worker thread
            # alive, which stops the interpreter from ever exiting.
            self._conn = conn
            try:
                await conn.execute("PRAGMA foreign_keys = ON")
                await conn.execute("PRAGMA busy_timeout = 5000")
                if not self.is_memory:
                    await conn.execute("PRAGMA journal_mode = WAL")
                    await conn.execute("PRAGMA synchronous = NORMAL")
                # Create the schema_migrations tracking table (backend-agnostic;
                # used by all database backends to track applied schema versions).
                await conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS schema_migrations (
                        version INTEGER PRIMARY KEY,
                        applied_on REAL NOT NULL
                    )
                    """
                )
                await self._migrate()
            except Exception:
                await conn.close()
                self._conn = None
                raise
            if not self.is_memory:
                self._secure_files()

    def _secure_files(self) -> None:
        """_secure_files."""
        for candidate in (self.path, Path(f"{self.path}-wal"), Path(f"{self.path}-shm")):
            try:
                if candidate.exists():
                    os.chmod(candidate, 0o600)
            except OSError:
                pass

    #: Schema version number. Incremented whenever the schema changes.
    SCHEMA_VERSION = 8

    #: Per-step migration scripts. Keys are the target schema version.
    #: Each script runs inside a transaction; RAISE(IGNORE) suppresses
    #: "duplicate table" errors when re-running an older migration.
    _MIGRATIONS: MappingProxyType = MappingProxyType({
        1: """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            display_name TEXT NOT NULL,
            webauthn_user_id BLOB NOT NULL UNIQUE,
            is_admin INTEGER NOT NULL DEFAULT 1,
            created_at REAL NOT NULL,
            recovery_token TEXT
        );

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at REAL NOT NULL,
            event TEXT NOT NULL,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            username TEXT,
            ip TEXT,
            user_agent TEXT,
            detail TEXT
        );
        """,
        2: """
        -- Add mesh_peers table for WireGuard peer configuration.
        CREATE TABLE IF NOT EXISTS mesh_peers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE COLLATE NOCASE,
            public_key TEXT NOT NULL UNIQUE,
            private_key TEXT,
            preshared_key TEXT NOT NULL,
            address TEXT NOT NULL UNIQUE,
            endpoint TEXT,
            keepalive INTEGER NOT NULL DEFAULT 25,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at REAL NOT NULL,
            last_handshake REAL
        );
        """,
        3: """
        -- Add credentials, sessions, challenges, backup_codes, otp_secrets tables
        -- to support passkeys and multi-factor authentication.
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            credential_id BLOB NOT NULL UNIQUE,
            public_key BLOB NOT NULL,
            sign_count INTEGER NOT NULL DEFAULT 0,
            transports TEXT NOT NULL DEFAULT '[]',
            name TEXT NOT NULL,
            aaguid TEXT,
            fmt TEXT,
            user_verified INTEGER NOT NULL DEFAULT 0,
            backup_eligible INTEGER NOT NULL DEFAULT 0,
            backup_state INTEGER NOT NULL DEFAULT 0,
            created_at REAL NOT NULL,
            last_used_at REAL
        );
        CREATE INDEX IF NOT EXISTS idx_credentials_user ON credentials(user_id);

        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_hash TEXT NOT NULL UNIQUE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at REAL NOT NULL,
            expires_at REAL NOT NULL,
            last_seen_at REAL NOT NULL,
            ip TEXT,
            user_agent TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
        CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);

        CREATE TABLE IF NOT EXISTS challenges (
            id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            payload TEXT NOT NULL,
            created_at REAL NOT NULL,
            expires_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_challenges_expiry ON challenges(expires_at);

        CREATE TABLE IF NOT EXISTS backup_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            code_hash TEXT NOT NULL UNIQUE,
            created_at REAL NOT NULL,
            used_at REAL
        );
        CREATE INDEX IF NOT EXISTS idx_backup_codes_user ON backup_codes(user_id);

        CREATE TABLE IF NOT EXISTS otp_secrets (
            user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            secret TEXT NOT NULL DEFAULT '',
            verified INTEGER NOT NULL DEFAULT 0,
            pending_secret TEXT,
            pending_created_at REAL,
            created_at REAL NOT NULL
        );
        """,
        4: """
        -- Invite codes for first-login passkey registration.
        CREATE TABLE IF NOT EXISTS invites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token_hash TEXT NOT NULL UNIQUE,
            expires_at REAL NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            created_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_invites_user ON invites(user_id);
        CREATE INDEX IF NOT EXISTS idx_invites_token ON invites(token_hash);
        CREATE INDEX IF NOT EXISTS idx_invites_used ON invites(used);
        """,        5: """\
        -- Add user email address. ``email`` is nullable so that existing
        -- databases without this column carry on; application code supplies
        -- the address when the account is created/invited.
        ALTER TABLE users ADD COLUMN email TEXT
        """,
        6: """
        -- Named groups for per-route ACLs. Every account is added to the
        -- built-in "Users" group on creation; a route with no allowed groups
        -- stays open to all signed-in users.
        CREATE TABLE IF NOT EXISTS acl_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE COLLATE NOCASE,
            created_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS acl_members (
            group_id INTEGER NOT NULL REFERENCES acl_groups(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at REAL NOT NULL,
            PRIMARY KEY (group_id, user_id)
        );
        CREATE INDEX IF NOT EXISTS idx_acl_members_user ON acl_members(user_id);

        INSERT OR IGNORE INTO acl_groups (name, created_at)
        VALUES ('Users', CAST(strftime('%s', 'now') AS REAL));
        """,
        7: """
        -- Track whether an OTP secret is verified and keep a pending secret so
        -- that an abandoned enrolment never clobbers an already-working one.
        ALTER TABLE otp_secrets ADD COLUMN verified INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE otp_secrets ADD COLUMN pending_secret TEXT;
        ALTER TABLE otp_secrets ADD COLUMN pending_created_at REAL;
        UPDATE otp_secrets SET verified = 1 WHERE secret IS NOT NULL AND secret <> '';
        """,
    8: """
        -- Remember the last accepted TOTP step so a code cannot be replayed
        -- inside the drift window.
        ALTER TABLE otp_secrets ADD COLUMN last_used_counter INTEGER;
        """,
})  # type: ignore[assignment]

    async def _migrate(self) -> None:
        """_migrate."""
        conn = self._require_conn()
        # Read the current schema version from the tracking table (backend-agnostic).
        async with conn.execute(
            "SELECT COALESCE(MAX(version), 0) AS version FROM schema_migrations"
        ) as cursor:
            row = await cursor.fetchone()
        current_version = int(row["version"]) if row else 0
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
            statements = _sql_statements(migration)
            # Version 5 only adds the ``email`` column. Databases created by
            # older development builds may already have it, so skip the ALTER
            # rather than failing the whole upgrade.
            if target_version == 5:
                async with conn.execute("PRAGMA table_info(users)") as cursor:
                    columns = {row["name"] for row in await cursor.fetchall()}
                if "email" in columns:
                    statements = []
            # Version 7 adds OTP enrolment columns; skip any that already exist.
            if target_version == 7:
                async with conn.execute("PRAGMA table_info(otp_secrets)") as cursor:
                    columns = {row["name"] for row in await cursor.fetchall()}
                filtered: list[str] = []
                for statement in statements:
                    upper = statement.upper()
                    if "ADD COLUMN VERIFIED" in upper and "verified" in columns:
                        continue
                    if "ADD COLUMN PENDING_SECRET" in upper and "pending_secret" in columns:
                        continue
                    if "ADD COLUMN PENDING_CREATED_AT" in upper and "pending_created_at" in columns:
                        continue
                    filtered.append(statement)
                statements = filtered
            # Version 8 adds the TOTP replay counter; skip it when a development
            # build already created the column.
            if target_version == 8:
                async with conn.execute("PRAGMA table_info(otp_secrets)") as cursor:
                    columns = {row["name"] for row in await cursor.fetchall()}
                if "last_used_counter" in columns:
                    statements = []
            # ``executescript`` would implicitly commit before running, so run
            # each statement inside an explicit transaction and record the
            # version in the same transaction.
            await conn.execute("BEGIN IMMEDIATE")
            try:
                for statement in statements:
                    await conn.execute(statement)
                await conn.execute(
                    "INSERT INTO schema_migrations (version, applied_on) VALUES (?, ?)",
                    (target_version, time.time()),
                )
                await conn.execute("COMMIT")
            except Exception:
                await conn.execute("ROLLBACK")
                raise
        # The default group is part of the schema from version 6 onwards; make
        # sure it exists even if a database was restored without its rows.
        await self._ensure_default_acl_group()
        self._secure_files()

    def _require_conn(self) -> aiosqlite.Connection:
        """_require_conn."""
        if self._conn is None:
            raise DatabaseError("Database is not initialized")
        return self._conn

    async def close(self) -> None:
        """close."""
        async with self._init_lock:
            if self._conn is not None:
                await self._conn.close()
                self._conn = None



    # ------------------------------------------------------------------ helpers
    async def _fetchone(self, sql: str, params: tuple[Any, ...] = ()) -> aiosqlite.Row | None:
        """_fetchone."""
        if self._conn is None:
            await self.init()
        conn = self._require_conn()
        async with self._lock, conn.execute(sql, params) as cursor:
            return await cursor.fetchone()

    async def _fetchall(self, sql: str, params: tuple[Any, ...] = ()) -> list[aiosqlite.Row]:
        """_fetchall."""
        if self._conn is None:
            await self.init()
        conn = self._require_conn()
        async with self._lock, conn.execute(sql, params) as cursor:
            return list(await cursor.fetchall())

    async def _write(self, sql: str, params: tuple[Any, ...] = ()) -> int:
        """_write."""
        if self._conn is None:
            await self.init()
        conn = self._require_conn()
        async with self._lock:
            cursor = await conn.execute(sql, params)
            await conn.commit()
            lastrowid = cursor.lastrowid
            await cursor.close()
            return int(lastrowid or 0)

    async def _write_count(self, sql: str, params: tuple[Any, ...] = ()) -> int:
        """Run a statement and return the number of rows it changed."""
        if self._conn is None:
            await self.init()
        conn = self._require_conn()
        async with self._lock:
            cursor = await conn.execute(sql, params)
            await conn.commit()
            count = cursor.rowcount
            await cursor.close()
            return int(count or 0)

    # ------------------------------------------------------------------- users
    async def user_count(self) -> int:
        """user_count."""
        row = await self._fetchone("SELECT COUNT(*) AS count FROM users")
        return int(row["count"]) if row else 0

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
        """Create a new user with the given username, display name and WebAuthn identifier.
        Returns the persisted ``User`` instance. Raises ``AlreadyExistsError`` if the username is already taken.
        """
        created = now if now is not None else time.time()
        cols = ["username", "display_name", "webauthn_user_id", "is_admin", "created_at"]
        vals = [username, display_name, webauthn_user_id, int(is_admin), created]
        if email is not None:
            cols.append("email")
            vals.append(email)
        sql = f"INSERT INTO users ({', '.join(cols)}) VALUES ({', '.join('?' * len(vals))})"
        try:
            user_id = await self._write(sql, tuple(vals))
        except sqlite3.IntegrityError as exc:
            raise AlreadyExistsError("That username is already registered.") from exc
        await self._join_default_acl_group(user_id, now=created)
        user = await self.get_user(user_id)
        if user is None:
            raise DatabaseError("User disappeared after creation.")
        return replace(user, groups=tuple(await self.list_user_acl_groups(user_id)))


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
        return await self._write(
            "INSERT INTO invites (user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?)",
            (user_id, token_hash, expires_at, created),
        )

    async def get_invite(self, token: str) -> Any:
        """get_invite."""
        conn = self._require_conn()
        async with conn.execute(
            "SELECT * FROM invites WHERE token_hash = ?",
            (hashlib.sha256(token.encode("utf-8")).hexdigest(),),
        ) as cursor:
            return await cursor.fetchone()

    async def mark_invite_used(self, invite_id: int) -> bool:
        """mark_invite_used."""
        if self._conn is None:
            await self.init()
        conn = self._require_conn()
        async with self._lock, conn.execute(
            "UPDATE invites SET used = 1 WHERE id = ? AND used = 0", (invite_id,)
        ) as cursor:
            await conn.commit()
            return cursor.rowcount > 0


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
        """Atomically create a user and its initial credential.
        If ``setup_mode`` is true, the operation ensures the users table is empty to allow first‑run claims.
        Returns a tuple of the created ``User`` and ``Credential``.
        """
        """Atomically create a user and their first passkey.

        In setup mode this also requires an empty users table, which makes the
        first-run claim race-safe (even across multiple workers sharing SQLite).
        """
        created = now if now is not None else time.time()
        if self._conn is None:
            await self.init()
        conn = self._require_conn()
        async with self._lock:
            await conn.execute("BEGIN IMMEDIATE")
            try:
                if setup_mode:
                    async with conn.execute("SELECT COUNT(*) AS count FROM users") as cursor:
                        row = await cursor.fetchone()
                    if row and int(row["count"]) > 0:
                        raise AlreadyExistsError("This Warden instance has already been claimed.")
                cursor = await conn.execute(
                    "INSERT INTO users (username, display_name, webauthn_user_id, is_admin, created_at) "
                    "VALUES (?, ?, ?, 1, ?)",
                    (username, display_name, webauthn_user_id, created),
                )
                user_id = int(cursor.lastrowid or 0)
                await cursor.close()
                cursor = await conn.execute(
                    "INSERT INTO credentials "
                    "(user_id, credential_id, public_key, sign_count, transports, name, aaguid, fmt, "
                    "user_verified, backup_eligible, backup_state, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        user_id,
                        credential_id,
                        public_key,
                        sign_count,
                        json.dumps(transports),
                        credential_name,
                        aaguid,
                        fmt,
                        int(user_verified),
                        int(backup_eligible),
                        int(backup_state),
                        created,
                    ),
                )
                credential_row_id = int(cursor.lastrowid or 0)
                await cursor.close()
                if setup_mode:
                    await conn.execute(
                        "DELETE FROM settings WHERE key IN "
                        "('setup_code_hash', 'setup_code_expires_at')"
                    )
                async with conn.execute(
                    "SELECT id FROM acl_groups WHERE name = ?", (DEFAULT_ACL_GROUP,)
                ) as cursor:
                    default_group = await cursor.fetchone()
                if default_group is not None:
                    await conn.execute(
                        "INSERT OR IGNORE INTO acl_members (group_id, user_id, created_at) "
                        "VALUES (?, ?, ?)",
                        (default_group["id"], user_id, created),
                    )
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
            async with conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)) as cursor:
                user_row = await cursor.fetchone()
            async with conn.execute(
                "SELECT * FROM credentials WHERE id = ?", (credential_row_id,)
            ) as cursor:
                credential_row = await cursor.fetchone()
        if user_row is None or credential_row is None:
            raise DatabaseError("User setup failed unexpectedly.")
        return (
            replace(_user(user_row), groups=tuple(await self.list_user_acl_groups(user_id))),
            _credential(credential_row),
        )

    async def get_user(self, user_id: int) -> User | None:
        """Fetch a user by its primary key ID. Returns ``None`` if not found."""
        row = await self._fetchone("SELECT * FROM users WHERE id = ?", (user_id,))
        return _user(row) if row else None

    async def get_user_by_username(self, username: str) -> User | None:
        """Fetch a user by its unique username. Returns ``None`` if no match."""
        row = await self._fetchone("SELECT * FROM users WHERE username = ?", (username,))
        return _user(row) if row else None

    async def list_users(self) -> list[User]:
        """Return a list of all users ordered by creation timestamp."""
        rows = await self._fetchall("SELECT * FROM users ORDER BY created_at")
        return [_user(row) for row in rows]

    async def get_user_by_webauthn_id(self, webauthn_user_id: bytes) -> User | None:
        """Fetch a user by its WebAuthn identifier. Returns ``None`` if not found."""
        row = await self._fetchone(
            "SELECT * FROM users WHERE webauthn_user_id = ?", (webauthn_user_id,)
        )
        return _user(row) if row else None

    async def delete_user(self, user_id: int) -> bool:
        """Delete a user by ID. Returns ``True`` if a row was removed."""
        if self._conn is None:
            await self.init()
        conn = self._require_conn()
        async with self._lock:
            await conn.execute("DELETE FROM credentials WHERE user_id = ?", (user_id,))
            await conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            await conn.execute("DELETE FROM backup_codes WHERE user_id = ?", (user_id,))
            await conn.execute("DELETE FROM otp_secrets WHERE user_id = ?", (user_id,))
            await conn.execute("DELETE FROM invites WHERE user_id = ?", (user_id,))
            await conn.execute("DELETE FROM acl_members WHERE user_id = ?", (user_id,))
            cursor = await conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
            await conn.commit()
            changed = cursor.rowcount
            await cursor.close()
        return bool(changed)

    async def update_user_admin(self, user_id: int, is_admin: bool) -> bool:
        """Set the ``is_admin`` flag for a user. Returns ``True`` on success."""
        if self._conn is None:
            await self.init()
        conn = self._require_conn()
        async with self._lock:
            cursor = await conn.execute(
                "UPDATE users SET is_admin = ? WHERE id = ?", (int(is_admin), user_id)
            )
            await conn.commit()
            changed = cursor.rowcount
            await cursor.close()
        return bool(changed)

    async def demote_admin(self, user_id: int) -> bool:
        """Clear ``is_admin`` unless the user is the last remaining admin.

        The guard is part of the ``UPDATE`` so two concurrent demotions cannot
        both observe two admins and leave zero. Returns ``False`` when the
        change was refused.
        """
        if self._conn is None:
            await self.init()
        conn = self._require_conn()
        async with self._lock:
            cursor = await conn.execute(
                "UPDATE users SET is_admin = 0 WHERE id = ? "
                "AND (SELECT COUNT(*) FROM users WHERE is_admin = 1) > 1",
                (user_id,),
            )
            await conn.commit()
            changed = cursor.rowcount
            await cursor.close()
        return bool(changed)

    async def update_user_display_name(self, user_id: int, display_name: str) -> bool:
        """Set the ``display_name`` for a user. Returns ``True`` on success."""
        if self._conn is None:
            await self.init()
        conn = self._require_conn()
        async with self._lock:
            cursor = await conn.execute(
                "UPDATE users SET display_name = ? WHERE id = ?", (display_name, user_id)
            )
            await conn.commit()
            changed = cursor.rowcount
            await cursor.close()
        return bool(changed)

    async def update_user_email(self, user_id: int, email: str | None) -> bool:
        """Set the ``email`` for a user. Returns ``True`` on success."""
        if self._conn is None:
            await self.init()
        conn = self._require_conn()
        async with self._lock:
            try:
                cursor = await conn.execute(
                    "UPDATE users SET email = ? WHERE id = ?", (email, user_id)
                )
            except sqlite3.OperationalError:
                # Column ``email`` may not exist in older schema versions.
                return False
            await conn.commit()
            changed = cursor.rowcount
            await cursor.close()
        return bool(changed)

    # --------------------------------------------------------------- ACL groups
    async def list_acl_groups(self) -> list[AclGroup]:
        """Return every ACL group with its current member count."""
        rows = await self._fetchall(
            "SELECT g.id, g.name, g.created_at, COUNT(m.user_id) AS member_count "
            "FROM acl_groups g LEFT JOIN acl_members m ON m.group_id = g.id "
            "GROUP BY g.id, g.name, g.created_at ORDER BY g.name"
        )
        return [
            AclGroup(
                id=int(row["id"]),
                name=row["name"],
                created_at=float(row["created_at"]),
                member_count=int(row["member_count"]),
            )
            for row in rows
        ]

    async def get_acl_group(self, group_id: int) -> AclGroup | None:
        """Fetch a single ACL group, including its member count."""
        row = await self._fetchone(
            "SELECT g.id, g.name, g.created_at, "
            "(SELECT COUNT(*) FROM acl_members m WHERE m.group_id = g.id) AS member_count "
            "FROM acl_groups g WHERE g.id = ?",
            (group_id,),
        )
        if row is None:
            return None
        return AclGroup(
            id=int(row["id"]),
            name=row["name"],
            created_at=float(row["created_at"]),
            member_count=int(row["member_count"]),
        )

    async def get_acl_group_by_name(self, name: str) -> AclGroup | None:
        """Fetch an ACL group by name (case-insensitive), or ``None``."""
        try:
            cleaned = _clean_group_name(name)
        except ValueError:
            return None
        row = await self._fetchone(
            "SELECT id FROM acl_groups WHERE name = ?", (cleaned,)
        )
        return await self.get_acl_group(int(row["id"])) if row else None

    async def create_acl_group(self, name: str, *, now: float | None = None) -> AclGroup:
        """Create a named ACL group. Raises ``AlreadyExistsError`` on a clash."""
        cleaned = _clean_group_name(name)
        try:
            group_id = await self._write(
                "INSERT INTO acl_groups (name, created_at) VALUES (?, ?)",
                (cleaned, now if now is not None else time.time()),
            )
        except sqlite3.IntegrityError as exc:
            raise AlreadyExistsError(f"A group named {cleaned!r} already exists.") from exc
        group = await self.get_acl_group(group_id)
        if group is None:
            raise DatabaseError("Group disappeared after creation.")
        return group

    async def delete_acl_group(self, group_id: int) -> bool:
        """Delete a group and its memberships. The default group is permanent."""
        group = await self.get_acl_group(group_id)
        if group is None or group.name.casefold() == DEFAULT_ACL_GROUP.casefold():
            return False
        if self._conn is None:
            await self.init()
        conn = self._require_conn()
        async with self._lock:
            await conn.execute("DELETE FROM acl_members WHERE group_id = ?", (group_id,))
            cursor = await conn.execute("DELETE FROM acl_groups WHERE id = ?", (group_id,))
            await conn.commit()
            changed = cursor.rowcount
            await cursor.close()
        return bool(changed)

    async def list_user_acl_groups(self, user_id: int) -> list[str]:
        """Return the names of the groups *user_id* belongs to."""
        rows = await self._fetchall(
            "SELECT g.name FROM acl_members m JOIN acl_groups g ON g.id = m.group_id "
            "WHERE m.user_id = ? ORDER BY g.name",
            (user_id,),
        )
        return [row["name"] for row in rows]

    async def acl_memberships(self) -> dict[int, list[str]]:
        """Return ``{user_id: [group names]}`` for every membership."""
        rows = await self._fetchall(
            "SELECT m.user_id, g.name FROM acl_members m "
            "JOIN acl_groups g ON g.id = m.group_id ORDER BY g.name"
        )
        memberships: dict[int, list[str]] = {}
        for row in rows:
            memberships.setdefault(int(row["user_id"]), []).append(row["name"])
        return memberships

    async def add_user_to_acl_group(
        self, user_id: int, group_id: int, *, now: float | None = None
    ) -> bool:
        """Add a user to a group. Returns ``False`` if either side is missing."""
        if await self.get_acl_group(group_id) is None or await self.get_user(user_id) is None:
            return False
        await self._write(
            "INSERT OR IGNORE INTO acl_members (group_id, user_id, created_at) "
            "VALUES (?, ?, ?)",
            (group_id, user_id, now if now is not None else time.time()),
        )
        return True

    async def remove_user_from_acl_group(self, user_id: int, group_id: int) -> bool:
        """Remove a membership. Members cannot leave the default group."""
        group = await self.get_acl_group(group_id)
        if group is None or group.name.casefold() == DEFAULT_ACL_GROUP.casefold():
            return False
        if self._conn is None:
            await self.init()
        conn = self._require_conn()
        async with self._lock:
            cursor = await conn.execute(
                "DELETE FROM acl_members WHERE user_id = ? AND group_id = ?",
                (user_id, group_id),
            )
            await conn.commit()
            changed = cursor.rowcount
            await cursor.close()
        return bool(changed)

    async def set_user_acl_groups(self, user_id: int, names: list[str]) -> list[str]:
        """Replace a user's memberships, always keeping the default group.

        Unknown group names raise ``ValueError`` rather than being silently
        dropped, so a typo in the admin UI surfaces instead of locking the user
        out of a route.
        """
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
        if self._conn is None:
            await self.init()
        conn = self._require_conn()
        async with self._lock:
            await conn.execute("BEGIN IMMEDIATE")
            try:
                await conn.execute("DELETE FROM acl_members WHERE user_id = ?", (user_id,))
                now = time.time()
                for group_id in sorted(group_ids):
                    await conn.execute(
                        "INSERT OR IGNORE INTO acl_members (group_id, user_id, created_at) "
                        "VALUES (?, ?, ?)",
                        (group_id, user_id, now),
                    )
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise
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

    async def _join_default_acl_group(self, user_id: int, *, now: float | None = None) -> None:
        """Add a freshly created account to the built-in group."""
        group = await self._ensure_default_acl_group()
        await self._write(
            "INSERT OR IGNORE INTO acl_members (group_id, user_id, created_at) "
            "VALUES (?, ?, ?)",
            (group.id, user_id, now if now is not None else time.time()),
        )

    async def reset_auth(self) -> None:
        """Delete all users, passkeys, sessions, settings, audit log, challenges,
        backup codes, OTP secrets, and mesh peers (auth reset)."""
        conn = self._require_conn()
        async with self._lock:
            await conn.execute("DELETE FROM challenges")
            await conn.execute("DELETE FROM credentials")
            await conn.execute("DELETE FROM sessions")
            await conn.execute("DELETE FROM backup_codes")
            await conn.execute("DELETE FROM otp_secrets")
            await conn.execute("DELETE FROM invites")
            await conn.execute("DELETE FROM acl_members")
            await conn.execute("DELETE FROM acl_groups WHERE name <> ?", (DEFAULT_ACL_GROUP,))
            await conn.execute("DELETE FROM settings")
            await conn.execute("DELETE FROM audit")
            await conn.execute("DELETE FROM users")
            await conn.execute("DELETE FROM mesh_peers")
            await conn.commit()

    async def health_check(self) -> bool:
        """health_check."""
        try:
            conn = self._require_conn()
            await conn.execute("SELECT 1")
            return True
        except Exception:  # noqa: BLE001
            return False

    async def vacuum(self) -> None:
        """vacuum."""
        conn = self._require_conn()
        config = getattr(self, "config", None)
        if config is not None:
            # ``PRAGMA database_path`` is not a real SQLite pragma, so read the
            # main database's file path from ``PRAGMA database_list`` instead.
            async with conn.execute("PRAGMA database_list") as cursor:
                rows = await cursor.fetchall()
            path = None
            for row in rows:
                if row["name"] == "main":
                    path = row["file"]
                    break
            if path:
                try:
                    size = os.path.getsize(path)
                except OSError:
                    size = 0
            else:
                size = 0
            if size < config.max_vacuum_bytes:
                logger.debug(
                    "VACUUM skipped, database file %d bytes < threshold %d",
                    size,
                    config.max_vacuum_bytes,
                )
                return
        async with self._lock:
            await conn.execute("VACUUM")

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
        """Insert a new credential for a user and return the ``Credential`` object.
        Raises ``AlreadyExistsError`` if the credential ID is already present.
        """
        created = now if now is not None else time.time()
        try:
            credential_row = await self._write(
                "INSERT INTO credentials "
                "(user_id, credential_id, public_key, sign_count, transports, name, aaguid, fmt, "
                "user_verified, backup_eligible, backup_state, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    user_id,
                    credential_id,
                    public_key,
                    sign_count,
                    json.dumps(transports),
                    name,
                    aaguid,
                    fmt,
                    int(user_verified),
                    int(backup_eligible),
                    int(backup_state),
                    created,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise AlreadyExistsError("That passkey is already registered.") from exc
        credential = await self.get_credential(credential_row)
        if credential is None:
            raise DatabaseError("Credential disappeared after creation.")
        return credential

    async def get_credential(self, credential_row_id: int) -> Credential | None:
        """Retrieve a credential by its database row ID. Returns ``None`` if missing."""
        row = await self._fetchone("SELECT * FROM credentials WHERE id = ?", (credential_row_id,))
        return _credential(row) if row else None

    async def get_credential_by_id(self, credential_id: bytes) -> Credential | None:
        """Fetch a credential by its raw credential ID (bytes). Returns ``None`` if not found."""
        row = await self._fetchone(
            "SELECT * FROM credentials WHERE credential_id = ?", (credential_id,)
        )
        return _credential(row) if row else None

    async def list_credentials(self, user_id: int | None = None) -> list[Credential]:
        """List credentials for all users or for a specific ``user_id`` if provided."""
        if user_id is None:
            rows = await self._fetchall("SELECT * FROM credentials ORDER BY created_at")
        else:
            rows = await self._fetchall(
                "SELECT * FROM credentials WHERE user_id = ? ORDER BY created_at", (user_id,)
            )
        return [_credential(row) for row in rows]

    async def count_credentials(self, user_id: int | None = None) -> int:
        """Count credential rows overall or for a specific user if ``user_id`` is given."""
        if user_id is None:
            row = await self._fetchone("SELECT COUNT(*) AS count FROM credentials")
        else:
            row = await self._fetchone(
                "SELECT COUNT(*) AS count FROM credentials WHERE user_id = ?", (user_id,)
            )
        return int(row["count"]) if row else 0

    async def update_credential_use(
        self, credential_row_id: int, sign_count: int, *, now: float | None = None
    ) -> None:
        """Update ``sign_count`` and ``last_used_at`` for a credential row."""
        used = now if now is not None else time.time()
        await self._write(
            "UPDATE credentials SET sign_count = ?, last_used_at = ? WHERE id = ?",
            (sign_count, used, credential_row_id),
        )

    async def rename_credential(self, user_id: int, credential_row_id: int, name: str) -> bool:
        """rename_credential."""
        if self._conn is None:
            await self.init()
        conn = self._require_conn()
        async with self._lock:
            cursor = await conn.execute(
                "UPDATE credentials SET name = ? WHERE id = ? AND user_id = ?",
                (name, credential_row_id, user_id),
            )
            await conn.commit()
            changed = cursor.rowcount
            await cursor.close()
        return bool(changed)

    async def delete_credential(
        self, user_id: int, credential_row_id: int, *, keep_last: bool = False
    ) -> bool:
        """Delete a credential row.

        With ``keep_last`` the "never remove the only passkey" rule runs inside
        the DELETE, so two concurrent removals cannot both see two keys and
        between them delete the last one.
        """
        if self._conn is None:
            await self.init()
        conn = self._require_conn()
        async with self._lock:
            if keep_last:
                cursor = await conn.execute(
                    "DELETE FROM credentials WHERE id = ? AND user_id = ? "
                    "AND (SELECT COUNT(*) FROM credentials WHERE user_id = ?) > 1",
                    (credential_row_id, user_id, user_id),
                )
            else:
                cursor = await conn.execute(
                    "DELETE FROM credentials WHERE id = ? AND user_id = ?",
                    (credential_row_id, user_id),
                )
            await conn.commit()
            changed = cursor.rowcount
            await cursor.close()
        return bool(changed)

    # ---------------------------------------------------------------- sessions
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
        if max_sessions is not None and max_sessions > 0:
            rows = await self._fetchall(
                "SELECT id FROM sessions WHERE user_id = ? AND expires_at > ? ORDER BY created_at ASC",
                (user_id, created),
            )
            if len(rows) >= max_sessions:
                overflow = len(rows) - max_sessions + 1
                for row in rows[:overflow]:
                    await self.revoke_session(user_id, row["id"])
        return await self._write(
            "INSERT INTO sessions "
            "(token_hash, user_id, created_at, expires_at, last_seen_at, ip, user_agent) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (token_hash, user_id, created, expires_at, created, ip, user_agent),
        )

    async def get_session(
        self, token_hash: str, *, now: float | None = None, touch: bool = True
    ) -> Session | None:
        """get_session."""
        current = now if now is not None else time.time()
        row = await self._fetchone(f"{_SESSION_JOIN} WHERE s.token_hash = ?", (token_hash,))
        if row is None:
            return None
        session = _session(row)
        if session.expires_at <= current:
            await self.revoke_session_by_hash(token_hash)
            return None
        if touch and current - session.last_seen_at > _session_touch_interval(session.id):
            await self._write(
                "UPDATE sessions SET last_seen_at = ? WHERE id = ?", (current, session.id)
            )
            session.last_seen_at = current
        return session

    async def list_sessions(
        self, user_id: int, *, current_token_hash: str | None = None
    ) -> list[Session]:
        """list_sessions."""
        sql = f"{_SESSION_JOIN} WHERE s.user_id = ? AND s.expires_at > ?"
        params: tuple[Any, ...] = (user_id, time.time())
        if current_token_hash is not None:
            sql += " AND s.token_hash <> ?"
            params += (current_token_hash,)
        sql += " ORDER BY s.last_seen_at DESC"
        rows = await self._fetchall(sql, params)
        return [_session(row) for row in rows]

    async def revoke_session(self, user_id: int, session_id: int) -> bool:
        """revoke_session."""
        if self._conn is None:
            await self.init()
        conn = self._require_conn()
        async with self._lock:
            cursor = await conn.execute(
                "DELETE FROM sessions WHERE id = ? AND user_id = ?", (session_id, user_id)
            )
            await conn.commit()
            changed = cursor.rowcount
            await cursor.close()
        return bool(changed)

    async def revoke_session_by_hash(self, token_hash: str) -> None:
        """revoke_session_by_hash."""
        await self._write("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))

    async def revoke_other_sessions(self, user_id: int, keep_token_hash: str) -> int:
        """revoke_other_sessions."""
        if self._conn is None:
            await self.init()
        conn = self._require_conn()
        async with self._lock:
            cursor = await conn.execute(
                "DELETE FROM sessions WHERE user_id = ? AND token_hash != ?",
                (user_id, keep_token_hash),
            )
            await conn.commit()
            changed = cursor.rowcount
            await cursor.close()
        return int(changed or 0)

    async def delete_expired_sessions(self) -> int:
        """delete_expired_sessions."""
        if self._conn is None:
            await self.init()
        conn = self._require_conn()
        async with self._lock:
            cursor = await conn.execute(
                "DELETE FROM sessions WHERE expires_at <= ?", (time.time(),)
            )
            await conn.commit()
            changed = cursor.rowcount
            await cursor.close()
        return int(changed or 0)

    # -------------------------------------------------------------- challenges
    async def create_challenge(
        self,
        challenge_id: str,
        kind: str,
        payload: dict[str, Any],
        ttl_seconds: int,
        *,
        now: float | None = None,
    ) -> Challenge:
        """create_challenge."""
        created = now if now is not None else time.time()
        expires = created + ttl_seconds
        await self._write(
            "INSERT INTO challenges (id, kind, payload, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
            (challenge_id, kind, json.dumps(payload), created, expires),
        )
        return Challenge(challenge_id, kind, payload, created, expires)

    async def consume_challenge(
        self, challenge_id: str, kind: str, *, now: float | None = None
    ) -> Challenge | None:
        """consume_challenge."""
        current = now if now is not None else time.time()
        if self._conn is None:
            await self.init()
        conn = self._require_conn()
        async with self._lock:
            cursor = await conn.execute(
                "DELETE FROM challenges WHERE id = ? AND kind = ? AND expires_at > ? "
                "RETURNING id, kind, payload, created_at, expires_at",
                (challenge_id, kind, current),
            )
            row = await cursor.fetchone()
            await cursor.close()
            if row is None:
                await conn.execute("DELETE FROM challenges WHERE id = ?", (challenge_id,))
            await conn.commit()
        if row is None:
            return None
        try:
            payload = json.loads(row["payload"])
        except (TypeError, ValueError):
            return None
        return Challenge(
            id=row["id"],
            kind=row["kind"],
            payload=payload,
            created_at=float(row["created_at"]),
            expires_at=float(row["expires_at"]),
        )

    async def get_challenge(
        self, challenge_id: str, kind: str, *, now: float | None = None
    ) -> Challenge | None:
        """Return a live challenge without consuming it.

        A flow that verifies a value before deciding whether to spend the
        challenge (the TOTP second factor) uses this so a mistyped code does
        not force the whole ceremony to restart. Expired and wrong-kind rows
        are simply not returned; the cleanup loop removes them.
        """
        current = now if now is not None else time.time()
        row = await self._fetchone(
            "SELECT id, kind, payload, created_at, expires_at FROM challenges "
            "WHERE id = ? AND kind = ? AND expires_at > ?",
            (challenge_id, kind, current),
        )
        if row is None:
            return None
        try:
            payload = json.loads(row["payload"])
        except (TypeError, ValueError):
            return None
        return Challenge(
            id=row["id"],
            kind=row["kind"],
            payload=payload,
            created_at=float(row["created_at"]),
            expires_at=float(row["expires_at"]),
        )

    async def delete_expired_challenges(self) -> int:
        """delete_expired_challenges."""
        if self._conn is None:
            await self.init()
        conn = self._require_conn()
        async with self._lock:
            cursor = await conn.execute(
                "DELETE FROM challenges WHERE expires_at <= ?", (time.time(),)
            )
            await conn.commit()
            changed = cursor.rowcount
            await cursor.close()
        return int(changed or 0)

    # ---------------------------------------------------------------- settings
    async def get_setting(self, key: str) -> str | None:
        """get_setting."""
        row = await self._fetchone("SELECT value FROM settings WHERE key = ?", (key,))
        return row["value"] if row else None

    async def set_setting(self, key: str, value: str) -> None:
        """set_setting."""
        await self._write(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    async def delete_setting(self, key: str) -> None:
        """delete_setting."""
        await self._write("DELETE FROM settings WHERE key = ?", (key,))

    # ------------------------------------------------------------------- audit
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
        if isinstance(detail, dict):
            detail = json.dumps(detail)
        await self._write(
            "INSERT INTO audit (created_at, event, user_id, username, ip, user_agent, detail) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                now if now is not None else time.time(),
                event,
                user_id,
                username,
                ip,
                user_agent,
                detail,
            ),
        )

    async def list_audit(
        self,
        limit: int = 50,
        event: str | None = None,
        offset: int = 0,
        since: float | None = None,
    ) -> list[AuditEvent]:
        """list_audit."""
        clauses: list[str] = []
        params: list[Any] = []
        if event:
            clauses.append("event = ?")
            params.append(event)
        if since is not None:
            clauses.append("created_at >= ?")
            params.append(since)
        query = "SELECT * FROM audit"
        if clauses:
            query += f" WHERE {' AND '.join(clauses)}"
        query += " ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"
        params.append(max(1, int(limit)))
        params.append(int(offset))
        rows = await self._fetchall(query, tuple(params))
        return [_audit(row) for row in rows]

    async def count_audit(self, *, event: str | None = None, since: float | None = None) -> int:
        """count_audit."""
        clauses: list[str] = []
        params: list[Any] = []
        if event:
            clauses.append("event = ?")
            params.append(event)
        if since is not None:
            clauses.append("created_at >= ?")
            params.append(since)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        row = await self._fetchone(f"SELECT COUNT(*) AS count FROM audit{where}", tuple(params))
        return int(row["count"]) if row else 0

    # -------------------------------------------------------------------- mesh
    async def list_mesh_peers(self) -> list[MeshPeer]:
        """list_mesh_peers."""
        rows = await self._fetchall("SELECT * FROM mesh_peers ORDER BY created_at")
        return [_peer(row) for row in rows]

    async def set_mesh_handshake(self, peer_id: int, timestamp: float | None) -> bool:
        """set_mesh_handshake."""
        conn = self._require_conn()
        async with self._lock:
            cursor = await conn.execute(
                "UPDATE mesh_peers SET last_handshake = ? WHERE id = ?",
                (timestamp, peer_id),
            )
            await conn.commit()
            await cursor.close()
            return bool(cursor.rowcount)

    async def get_mesh_peer(self, peer_id: int) -> MeshPeer | None:
        """get_mesh_peer."""
        row = await self._fetchone("SELECT * FROM mesh_peers WHERE id = ?", (peer_id,))
        return _peer(row) if row else None

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
        try:
            peer_id = await self._write(
                "INSERT INTO mesh_peers "
                "(name, public_key, private_key, preshared_key, address, endpoint, keepalive, "
                "enabled, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)",
                (
                    name,
                    public_key,
                    private_key,
                    preshared_key,
                    address,
                    endpoint,
                    keepalive,
                    now if now is not None else time.time(),
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise AlreadyExistsError("A peer with that name or address already exists.") from exc
        peer = await self.get_mesh_peer(peer_id)
        if peer is None:
            raise DatabaseError("Mesh peer disappeared after creation.")
        return peer

    async def delete_mesh_peer(self, peer_id: int) -> bool:
        """delete_mesh_peer."""
        if self._conn is None:
            await self.init()
        conn = self._require_conn()
        async with self._lock:
            cursor = await conn.execute("DELETE FROM mesh_peers WHERE id = ?", (peer_id,))
            await conn.commit()
            changed = cursor.rowcount
            await cursor.close()
        return bool(changed)

    async def add_backup_code(self, user_id: int, code_hash: str, now: float | None = None) -> int:
        """add_backup_code."""
        created = now if now is not None else time.time()
        return await self._write(
            "INSERT INTO backup_codes (user_id, code_hash, created_at) VALUES (?, ?, ?)",
            (user_id, code_hash, created),
        )

    async def use_backup_code(self, code_hash: str) -> int | None:
        """use_backup_code."""
        if self._conn is None:
            await self.init()
        conn = self._require_conn()
        async with self._lock:
            cursor = await conn.execute(
                "SELECT user_id FROM backup_codes WHERE code_hash = ? AND used_at IS NULL", (code_hash,)
            )
            row = await cursor.fetchone()
            if row:
                user_id = row["user_id"]
                await conn.execute(
                    "UPDATE backup_codes SET used_at = ? WHERE code_hash = ?", (time.time(), code_hash)
                )
                await conn.commit()
                return user_id
            return None

    async def list_backup_codes(self, user_id: int) -> list[BackupCode]:
        """list_backup_codes."""
        rows = await self._fetchall(
            "SELECT * FROM backup_codes WHERE user_id = ? ORDER BY created_at DESC", (user_id,)
        )
        return [
            BackupCode(
                id=row["id"],
                user_id=row["user_id"],
                code_hash=row["code_hash"],
                created_at=float(row["created_at"]),
                used_at=float(row["used_at"]) if row["used_at"] else None,
            )
            for row in rows
        ]

    async def clear_backup_codes(self, user_id: int) -> None:
        """clear_backup_codes."""
        await self._write("DELETE FROM backup_codes WHERE user_id = ?", (user_id,))

    # OTP secret management
    async def set_pending_otp_secret(self, user_id: int, secret: str, now: float | None = None) -> None:
        """Store a *pending* OTP secret without touching any verified one.

        An enrolment is only promoted to the active secret by
        :meth:`verify_otp`, so abandoning the flow leaves the previous
        (working) secret untouched.
        """
        created = now if now is not None else time.time()
        await self._write(
            "INSERT INTO otp_secrets (user_id, secret, verified, pending_secret, pending_created_at, created_at) "
            "VALUES (?, '', 0, ?, ?, ?) "
            "ON CONFLICT(user_id) DO UPDATE SET "
            "pending_secret = excluded.pending_secret, "
            "pending_created_at = excluded.pending_created_at",
            (user_id, secret, created, created),
        )

    async def set_otp_secret(self, user_id: int, secret: str, now: float | None = None) -> None:
        """set_otp_secret (promote a secret directly, marked verified)."""
        created = now if now is not None else time.time()
        await self._write(
            "INSERT INTO otp_secrets (user_id, secret, verified, created_at) VALUES (?, ?, 1, ?) "
            "ON CONFLICT(user_id) DO UPDATE SET "
            "secret = excluded.secret, verified = 1, pending_secret = NULL, "
            "pending_created_at = NULL, last_used_counter = NULL, "
            "created_at = excluded.created_at",
            (user_id, secret, created),
        )

    async def get_otp_secret(self, user_id: int) -> str | None:
        """Return the active (verified) OTP secret, if any."""
        row = await self._fetchone(
            "SELECT secret FROM otp_secrets WHERE user_id = ? AND verified = 1", (user_id,)
        )
        if row and row["secret"]:
            return row["secret"]
        return None

    async def get_pending_otp_secret(self, user_id: int) -> str | None:
        """Return the pending (unverified) OTP secret, if any."""
        row = await self._fetchone(
            "SELECT pending_secret FROM otp_secrets WHERE user_id = ?", (user_id,)
        )
        return row["pending_secret"] if row else None

    async def clear_pending_otp_secret(self, user_id: int) -> None:
        """Discard a pending OTP secret."""
        await self._write(
            "UPDATE otp_secrets SET pending_secret = NULL, pending_created_at = NULL WHERE user_id = ?",
            (user_id,),
        )

    async def clear_otp_secret(self, user_id: int) -> None:
        """Remove a user's TOTP enrolment entirely (pending and active)."""
        await self._write("DELETE FROM otp_secrets WHERE user_id = ?", (user_id,))

    async def otp_user_ids(self) -> set[int]:
        """Return the ids of every user with a verified TOTP secret."""
        rows = await self._fetchall(
            "SELECT user_id FROM otp_secrets WHERE verified = 1 AND secret <> ''"
        )
        return {int(row["user_id"]) for row in rows}

    @staticmethod
    def totp_match_counter(
        secret: str, code: str, *, window: int = 1, at: float | None = None
    ) -> int | None:
        """Return the TOTP time-step that *code* matches, or ``None``.

        ``window`` accepts that many 30-second steps either side of the current
        one to tolerate clock drift. A malformed secret or code never matches.
        """
        import base64
        import binascii
        import hashlib
        import hmac
        import struct

        code = (code or "").strip()
        if len(code) != 6 or not code.isdigit():
            return None
        try:
            key = base64.b32decode(secret.upper().replace(" ", ""), casefold=True)
        except (binascii.Error, TypeError, ValueError):
            return None
        interval = int((at if at is not None else time.time()) // 30)
        for offset in range(-window, window + 1):
            counter = interval + offset
            digest = hmac.new(
                key, struct.pack(">Q", counter), hashlib.sha1
            ).digest()
            start = digest[-1] & 0x0F
            token = (
                struct.unpack(">I", digest[start : start + 4])[0] & 0x7FFFFFFF
            ) % 1_000_000
            if f"{token:06d}" == code:
                return counter
        return None

    @staticmethod
    def totp_matches(
        secret: str, code: str, *, window: int = 1, at: float | None = None
    ) -> bool:
        """Return ``True`` when *code* is a valid TOTP for *secret*."""
        return Database.totp_match_counter(secret, code, window=window, at=at) is not None

    async def verify_otp(
        self, user_id: int, code: str, *, window: int = 1, at: float | None = None
    ) -> bool:
        """Verify *code* and spend the time-step it matched.

        The pending secret is tried first and promoted on success. A pending
        secret that does not match does **not** hide the active one: an
        abandoned re-enrolment must never stop the authenticator the user
        already has from signing in, because that would lock them out of the
        page that can finish the enrolment.

        The step that matched is recorded in ``last_used_counter`` by the same
        ``UPDATE`` that accepts the code, and a replay of that code (or of an
        older step still inside ``window``) is refused. Checking and writing in
        one statement keeps two concurrent requests from spending one code.
        """
        active = await self.get_otp_secret(user_id)
        pending = await self.get_pending_otp_secret(user_id)
        for secret, is_pending in ((pending, True), (active, False)):
            if not secret:
                continue
            counter = self.totp_match_counter(secret, code, window=window, at=at)
            if counter is None:
                continue
            if is_pending:
                # Promote the pending secret to the active one. Promotion is
                # idempotent and only possible while the pending row exists, so
                # it does not need the replay guard.
                written = await self._write_count(
                    "UPDATE otp_secrets SET secret = ?, verified = 1, "
                    "pending_secret = NULL, pending_created_at = NULL, "
                    "created_at = ?, last_used_counter = ? WHERE user_id = ?",
                    (secret, time.time(), counter, user_id),
                )
            else:
                written = await self._write_count(
                    "UPDATE otp_secrets SET last_used_counter = ? "
                    "WHERE user_id = ? "
                    "AND (last_used_counter IS NULL OR last_used_counter < ?)",
                    (counter, user_id, counter),
                )
            if written:
                return True
        return False


    