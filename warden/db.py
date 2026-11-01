"""Async SQLite persistence layer for Warden.

The module defines data classes representing the main entities (User, Credential,
Session, and :class:`Database` class) exposing async CRUD methods.
All interactions use ``aiosqlite`` with a connection lock to ensure safe
concurrent access.
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import aiosqlite

SCHEMA_VERSION = 3

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name TEXT NOT NULL,
    webauthn_user_id BLOB NOT NULL UNIQUE,
    is_admin INTEGER NOT NULL DEFAULT 1,
    created_at REAL NOT NULL,
    recovery_token TEXT
);

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
    secret TEXT NOT NULL,
    created_at REAL NOT NULL
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
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit(created_at);

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

-- users table carries is_admin flag
"""


class DatabaseError(Exception):
    """Base class for database‑related errors, such as connection problems or query failures."""


class AlreadyExistsError(DatabaseError):
    """Raised when attempting to create an entity that already exists (e.g., duplicate username or mesh peer)."""


@dataclass(slots=True)
class User:
    id: int
    username: str
    display_name: str
    webauthn_user_id: bytes
    is_admin: bool
    created_at: float
    recovery_token: str | None = None


@dataclass(slots=True)
class Credential:
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
    id: str
    kind: str
    payload: dict[str, Any]
    created_at: float
    expires_at: float


@dataclass(slots=True)
class AuditEvent:
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
    id: int
    user_id: int
    code_hash: str
    created_at: float
    used_at: float | None


@dataclass(slots=True)
class MeshPeer:
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


def _user(row: aiosqlite.Row) -> User:
    return User(
        id=row["id"],
        username=row["username"],
        display_name=row["display_name"],
        webauthn_user_id=bytes(row["webauthn_user_id"]),
        is_admin=bool(row["is_admin"]),
        created_at=float(row["created_at"]),
        recovery_token=row["recovery_token"],
    )


def _credential(row: aiosqlite.Row) -> Credential:
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
    user = User(
        id=row["u_id"],
        username=row["u_username"],
        display_name=row["u_display_name"],
        webauthn_user_id=bytes(row["u_webauthn_user_id"]),
        is_admin=bool(row["u_is_admin"]),
        created_at=float(row["u_created_at"]),
        recovery_token=row["u_recovery_token"],
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
       u.created_at AS u_created_at, u.recovery_token AS u_recovery_token
FROM sessions s
JOIN users u ON u.id = s.user_id
"""


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
        return str(self.path) == ":memory:"

    async def init(self) -> None:
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
            await conn.execute("PRAGMA foreign_keys = ON")
            await conn.execute("PRAGMA busy_timeout = 5000")
            if not self.is_memory:
                await conn.execute("PRAGMA journal_mode = WAL")
                await conn.execute("PRAGMA synchronous = NORMAL")
            self._conn = conn
            try:
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
        for candidate in (self.path, Path(f"{self.path}-wal"), Path(f"{self.path}-shm")):
            try:
                if candidate.exists():
                    os.chmod(candidate, 0o600)
            except OSError:
                pass

    #: Schema version number. Incremented whenever the schema changes.
    SCHEMA_VERSION = 3

    #: Per-step migration scripts. Keys are the target schema version.
    #: Each script runs inside a transaction; RAISE(IGNORE) suppresses
    #: "duplicate table" errors when re-running an older migration.
    _MIGRATIONS: dict[int, str] = {
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
            secret TEXT NOT NULL,
            created_at REAL NOT NULL
        );
        """,
    }  # type: ignore[assignment]

    async def _migrate(self) -> None:
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
            async with conn.execute("BEGIN IMMEDIATE") as _:
                await conn.executescript(migration)
                # Record the migration so future upgrades skip it.
                await conn.execute(
                    "INSERT INTO schema_migrations (version, applied_on) VALUES (?, ?)",
                    (target_version, time.time()),
                )
        self._secure_files()

    def _require_conn(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise DatabaseError("Database is not initialized")
        return self._conn

    async def close(self) -> None:
        async with self._init_lock:
            if self._conn is not None:
                await self._conn.close()
                self._conn = None



    # ------------------------------------------------------------------ helpers
    async def _fetchone(self, sql: str, params: tuple[Any, ...] = ()) -> aiosqlite.Row | None:
        if self._conn is None:
            await self.init()
        conn = self._require_conn()
        async with self._lock:
            async with conn.execute(sql, params) as cursor:
                return await cursor.fetchone()

    async def _fetchall(self, sql: str, params: tuple[Any, ...] = ()) -> list[aiosqlite.Row]:
        if self._conn is None:
            await self.init()
        conn = self._require_conn()
        async with self._lock:
            async with conn.execute(sql, params) as cursor:
                return list(await cursor.fetchall())

    async def _write(self, sql: str, params: tuple[Any, ...] = ()) -> int:
        if self._conn is None:
            await self.init()
        conn = self._require_conn()
        async with self._lock:
            cursor = await conn.execute(sql, params)
            await conn.commit()
            lastrowid = cursor.lastrowid
            await cursor.close()
            return int(lastrowid or 0)

    # ------------------------------------------------------------------- users
    async def user_count(self) -> int:
        row = await self._fetchone("SELECT COUNT(*) AS count FROM users")
        return int(row["count"]) if row else 0

    async def create_user(
        self,
        username: str,
        display_name: str,
        webauthn_user_id: bytes,
        *,
        is_admin: bool = True,
        now: float | None = None,
    ) -> User:
        """Create a new user with the given username, display name and WebAuthn identifier.
        Returns the persisted ``User`` instance. Raises ``AlreadyExistsError`` if the username is already taken.
        """
        created = now if now is not None else time.time()
        try:
            user_id = await self._write(
                "INSERT INTO users (username, display_name, webauthn_user_id, is_admin, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (username, display_name, webauthn_user_id, int(is_admin), created),
            )
        except sqlite3.IntegrityError as exc:
            raise AlreadyExistsError("That username is already registered.") from exc
        user = await self.get_user(user_id)
        if user is None:
            raise DatabaseError("User disappeared after creation.")
        return user

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
        return _user(user_row), _credential(credential_row)

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

    async def reset_auth(self) -> None:
        """Delete all users, passkeys, sessions, settings, audit log, and mesh peers (auth reset)."""
        conn = self._require_conn()
        async with self._lock:
            await conn.execute("DELETE FROM settings")
            await conn.execute("DELETE FROM audit")
            await conn.execute("DELETE FROM users")
            await conn.execute("DELETE FROM mesh_peers")
            await conn.commit()

    async def vacuum(self) -> None:
        conn = self._require_conn()
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

    async def delete_credential(self, user_id: int, credential_row_id: int) -> bool:
        if self._conn is None:
            await self.init()
        conn = self._require_conn()
        async with self._lock:
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
        created = now if now is not None else time.time()
        return await self._write(
            "INSERT INTO sessions "
            "(token_hash, user_id, created_at, expires_at, last_seen_at, ip, user_agent) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (token_hash, user_id, created, expires_at, created, ip, user_agent),
        )

    async def get_session(
        self, token_hash: str, *, now: float | None = None, touch: bool = True
    ) -> Session | None:
        current = now if now is not None else time.time()
        row = await self._fetchone(f"{_SESSION_JOIN} WHERE s.token_hash = ?", (token_hash,))
        if row is None:
            return None
        session = _session(row)
        if session.expires_at <= current:
            await self.revoke_session_by_hash(token_hash)
            return None
        if touch and current - session.last_seen_at > 300:
            await self._write(
                "UPDATE sessions SET last_seen_at = ? WHERE id = ?", (current, session.id)
            )
            session.last_seen_at = current
        return session

    async def list_sessions(
        self, user_id: int, *, current_token_hash: str | None = None
    ) -> list[Session]:
        rows = await self._fetchall(
            f"{_SESSION_JOIN} WHERE s.user_id = ? AND s.expires_at > ? ORDER BY s.last_seen_at DESC",
            (user_id, time.time()),
        )
        return [_session(row) for row in rows]

    async def revoke_session(self, user_id: int, session_id: int) -> bool:
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
        await self._write("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))

    async def revoke_other_sessions(self, user_id: int, keep_token_hash: str) -> int:
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

    async def delete_expired_challenges(self) -> int:
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
        row = await self._fetchone("SELECT value FROM settings WHERE key = ?", (key,))
        return row["value"] if row else None

    async def set_setting(self, key: str, value: str) -> None:
        await self._write(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    async def delete_setting(self, key: str) -> None:
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

    async def list_audit(self, limit: int = 50) -> list[AuditEvent]:
        rows = await self._fetchall(
            "SELECT * FROM audit ORDER BY created_at DESC LIMIT ?", (max(1, int(limit)),)
        )
        return [_audit(row) for row in rows]

    async def count_audit(self, *, event: str | None = None, since: float | None = None) -> int:
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
        rows = await self._fetchall("SELECT * FROM mesh_peers ORDER BY created_at")
        return [_peer(row) for row in rows]

    async def set_mesh_handshake(self, peer_id: int, timestamp: float | None) -> bool:
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
        created = now if now is not None else time.time()
        return await self._write(
            "INSERT INTO backup_codes (user_id, code_hash, created_at) VALUES (?, ?, ?)",
            (user_id, code_hash, created),
        )

    async def use_backup_code(self, code_hash: str) -> int | None:
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
        await self._write("DELETE FROM backup_codes WHERE user_id = ?", (user_id,))

    # OTP secret management
    async def set_otp_secret(self, user_id: int, secret: str, now: float | None = None) -> None:
        created = now if now is not None else time.time()
        await self._write(
            "INSERT INTO otp_secrets (user_id, secret, created_at) VALUES (?, ?, ?) "
            "ON CONFLICT(user_id) DO UPDATE SET secret = excluded.secret, created_at = excluded.created_at",
            (user_id, secret, created),
        )

    async def get_otp_secret(self, user_id: int) -> str | None:
        row = await self._fetchone("SELECT secret FROM otp_secrets WHERE user_id = ?", (user_id,))
        return row["secret"] if row else None

    async def verify_otp(self, user_id: int, code: str, *, window: int = 1) -> bool:
        secret = await self.get_otp_secret(user_id)
        if not secret:
            return False
        try:
            import base64, hmac, hashlib, struct
            key = base64.b32decode(secret.upper().replace(' ', ''), casefold=True)
            interval = int(time.time() // 30)
            for offset in range(-window, window + 1):
                counter = interval + offset
                msg = struct.pack('>Q', counter)
                h = hmac.new(key, msg, hashlib.sha1).digest()
                o = h[-1] & 0x0F
                token = (struct.unpack('>I', h[o:o+4])[0] & 0x7fffffff) % 1000000
                if f"{token:06d}" == code:
                    return True
        except Exception:
            return False
        return False


    