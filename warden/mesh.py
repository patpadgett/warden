"""WireGuard mesh peer management and configuration generation for Warden.

Provides :class:`MeshManager` (facade) over
:class:`warden.mesh_peer.MeshPeerIntake` (intake/config render)
and :class:`warden.mesh_apply.MeshApplyAdapter` (apply/status/refresh).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from warden.config import ConfigManager
from warden.db import Database, MeshPeer
from warden.mesh_apply import MeshApplyAdapter
from warden.mesh_peer import (
    MeshPeerIntake,
)


class MeshManager:
    """Thin facade over the split mesh modules."""

    def __init__(self, db: Database, manager: ConfigManager) -> None:
        """__init__."""
        self.db = db
        self.manager = manager
        self.intake = MeshPeerIntake(db, manager)
        self.adapter = MeshApplyAdapter(self.intake)
        self.last_apply: dict[str, Any] | None = None

    @property
    def config(self):
        """config."""
        return self.manager.config

    def _require_enabled(self) -> None:
        """_require_enabled."""
        self.intake._require_enabled()

    async def ensure_hub_key(self) -> str:
        """ensure_hub_key."""
        return await self.intake.ensure_hub_key()

    async def hub_public_key(self) -> str:
        """hub_public_key."""
        return await self.intake.hub_public_key()

    async def rotate_hub_key(self) -> str:
        """rotate_hub_key."""
        return await self.intake.rotate_hub_key()

    async def add_peer(
        self,
        *,
        name: str,
        address: str | None = None,
        endpoint: str | None = None,
        keepalive: int = 25,
    ) -> MeshPeer:
        """add_peer."""
        return await self.intake.add_peer(
            name=name, address=address, endpoint=endpoint, keepalive=keepalive
        )

    async def render_server_config(self) -> str:
        """render_server_config."""
        return await self.intake.render_server_config()

    async def render_peer_config(self, peer: MeshPeer) -> str:
        """render_peer_config."""
        return await self.intake.render_peer_config(peer)

    def _config_file(self) -> Path:
        """_config_file."""
        return self.intake._config_file()

    async def write_config(self) -> Path:
        """write_config."""
        result = await self.intake.write_config()
        return result

    async def apply(self) -> dict[str, Any]:
        """apply."""
        try:
            result = await self.adapter.apply()
            self.last_apply = result
            return result
        except Exception:
            # Capture failure result set by adapter on intake
            if self.intake.last_apply is not None:
                self.last_apply = self.intake.last_apply
            raise

    async def status(self) -> dict[str, Any]:
        """status."""
        return await self.adapter.status()

    async def refresh_handshakes(self) -> dict[str, Any]:
        """refresh_handshakes."""
        status = await self.adapter.refresh_handshakes()
        self.last_apply = status
        return status
