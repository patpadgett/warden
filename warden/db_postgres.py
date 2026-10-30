"""PostgreSQL adapter for Warden (CockroachDB-compatible via SQLAlchemy asyncpg)."""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text

from warden.db import Database, DatabaseError, MeshPeer


class PostgresDatabase(Database):
    """SQLAlchemy-based PostgreSQL adapter (works with CockroachDB wire)."""

    def __init__(self, url: str = "postgresql+asyncpg://localhost/warden") -> None:
        self.url = url
        self.engine = create_async_engine(url, echo=False, future=True)
        self.session_factory = sessionmaker(self.engine, class_=AsyncSession, expire_on_commit=False)

    async def init(self) -> None:
        async with self.engine.begin() as conn:
            await conn.run_sync(self._create_tables)

    def _create_tables(self, conn) -> None:
        conn.execute(text("CREATE TABLE IF NOT EXISTS mesh_peers (id SERIAL PRIMARY KEY, name TEXT, public_key TEXT, private_key TEXT, preshared_key TEXT, address TEXT, endpoint TEXT, keepalive INTEGER, enabled BOOLEAN, created_at REAL, last_handshake REAL)"))

    async def close(self) -> None:
        await self.engine.dispose()

    # Skeleton: delegate core mesh operations; full SQLAlchemy model mapping needed for production.
    async def list_mesh_peers(self) -> list[MeshPeer]:
        async with self.session_factory() as session:
            result = await session.execute(text("SELECT * FROM mesh_peers"))
            rows = result.fetchall()
            return [MeshPeer(**dict(r._mapping)) for r in rows]

    async def add_mesh_peer(self, **kwargs) -> MeshPeer:
        async with self.session_factory() as session:
            # Simplified insert for adapter proof
            pass
        raise NotImplementedError("PostgresDatabase.add_mesh_peer needs full SQLAlchemy model mapping.")
