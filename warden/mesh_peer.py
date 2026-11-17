"""WireGuard mesh peer management and configuration generation for Warden.

Provides :class:`MeshManager` which can add peers, render server/peer config files,
apply the configuration using ``wg``/``wg‑quick`` and keep the mesh status up‑to‑date.
"""

from __future__ import annotations

import base64
import ipaddress
import os
import re
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from warden.config import ConfigManager
from warden.db import AlreadyExistsError, Database, MeshPeer

HUB_KEY_SETTING = "mesh_hub_private_key"
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_. -]{0,38}$")


class MeshError(Exception):
    """Raised for errors in WireGuard mesh management or configuration."""


@dataclass(slots=True)
class PeerStatus:
    """Peer status summary."""
    endpoint: str | None
    last_handshake: float | None
    rx_bytes: int
    tx_bytes: int
    keepalive: str | None


def _b64(value: bytes) -> str:
    """Base64‑url‑encode ``value`` without padding.

    Helper used for key encoding.
    """
    return base64.b64encode(value).decode("ascii")


def generate_keypair() -> tuple[str, str]:
    """Generate a new X25519 private/public key pair.

    Returns a tuple of base64‑url‑encoded ``(private_key, public_key)`` strings.
    """
    private = X25519PrivateKey.generate()
    private_b64 = _b64(private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
    public_b64 = _b64(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    return private_b64, public_b64


def generate_psk() -> str:
    """Generate a random pre‑shared key (PSK) for WireGuard.

    Returns a base64‑url‑encoded 32‑byte string.
    """
    return _b64(secrets.token_bytes(32))


def public_from_private(private_b64: str) -> str:
    """Derive the public key from a base64‑encoded private key.

    The input is a base64‑url‑encoded X25519 private key; the function returns the
    corresponding public key, also base64‑url‑encoded.
    """
    raw = base64.b64decode(private_b64)
    private = X25519PrivateKey.from_private_bytes(raw)
    return _b64(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


class MeshPeerIntake:
    """Deep mesh peer-intake and config module.

    Provides peer validation, address assignment, hub-key management,
    and server/peer config rendering. Apply/status are handled by
    MeshApplyAdapter.
    """
    def __init__(self, db: Database, manager: ConfigManager) -> None:
        """Create a ``MeshPeerIntake`` instance.

        * ``db`` – database access for mesh peers.
        * ``manager`` – configuration manager providing mesh settings.
        """
        self.db = db
        self.manager = manager
        self.last_apply: dict[str, Any] | None = None

    @property
    def config(self):
        """Print hub WireGuard config."""
        return self.manager.config

    def _require_enabled(self) -> None:
        """Require mesh to be enabled."""
        if not self.config.mesh.enabled:
            raise MeshError("WireGuard mesh is disabled in warden.yaml.")

    async def ensure_hub_key(self) -> str:
        """Generate or refresh hub key."""
        key = await self.db.get_setting(HUB_KEY_SETTING)
        if not key:
            key, _ = generate_keypair()
            await self.db.set_setting(HUB_KEY_SETTING, key)
        return key

    async def hub_public_key(self) -> str:
        """Return the public key derived from the stored hub private key."""
        return public_from_private(await self.ensure_hub_key())

    async def rotate_hub_key(self) -> str:
        """Generate a new hub private key and store it in settings.

        This replaces the existing hub key used for the WireGuard mesh.
        Returns the new private key (base64‑url encoded). Call ``write_config``
        and ``apply`` to propagate the change.
        """
        self._require_enabled()
        private_key, _ = generate_keypair()
        await self.db.set_setting(HUB_KEY_SETTING, private_key)
        return private_key

    async def add_peer(
        self,
        *,
        name: str,
        address: str | None = None,
        endpoint: str | None = None,
        keepalive: int = 25,
    ) -> MeshPeer:
        """Add a new peer to the WireGuard mesh.

        * Validates the peer name against ``NAME_RE``.
        * Ensures the keepalive interval is within the allowed range.
        * Assigns an available IPv4 address from the mesh network if ``address``
          is not provided.
        * Generates a private/public key pair and a pre‑shared key.
        * Stores the peer in the database and returns the ``MeshPeer`` instance.
        """
        self._require_enabled()
        name = name.strip()
        if not NAME_RE.match(name):
            raise MeshError("Peer name must be 1–39 characters using letters, numbers, dots, dashes, or spaces.")
        if not 0 <= keepalive <= 65535:
            raise MeshError("Keepalive must be between 0 and 65535.")
        peers = await self.db.list_mesh_peers()
        if any(peer.name.lower() == name.lower() for peer in peers):
            raise MeshError("A peer with that name already exists.")
        mesh = self.config.mesh
        interface = ipaddress.ip_interface(mesh.address)
        network = interface.network
        hub_ip = interface.ip
        used = {peer.address for peer in peers}
        if address:
            address = address.strip()
            try:
                candidate = ipaddress.ip_interface(address)
            except ValueError as exc:
                raise MeshError("Peer address must be an IPv4 address, e.g. 10.44.0.2.") from exc
            if candidate.version != 4:
                raise MeshError("Only IPv4 mesh addresses are supported.")
            peer_ip = candidate.ip
        else:
            peer_ip = None
            for host in network.hosts():
                if host == hub_ip:
                    continue
                if str(host) not in used:
                    peer_ip = host
                    break
            if peer_ip is None:
                raise MeshError("The mesh network has no free addresses.")
        if peer_ip not in network:
            raise MeshError(f"{peer_ip} is outside the mesh network {network}.")
        if peer_ip == hub_ip or peer_ip in {network.network_address, network.broadcast_address}:
            raise MeshError("That address is reserved by the mesh.")
        if str(peer_ip) in used:
            raise MeshError("Another peer already uses that address.")
        if endpoint:
            endpoint = endpoint.strip()
            if ":" not in endpoint:
                raise MeshError("Peer endpoint must be host:port.")
            host, port = endpoint.rsplit(":", 1)
            if not host or not port.isdigit() or not (1 <= int(port) <= 65535):
                raise MeshError("Peer endpoint has an invalid port.")
        else:
            endpoint = None
        private_key, public_key = generate_keypair()
        psk = generate_psk()
        try:
            return await self.db.add_mesh_peer(
                name=name,
                public_key=public_key,
                private_key=private_key,
                preshared_key=psk,
                address=str(peer_ip),
                endpoint=endpoint,
                keepalive=keepalive,
            )
        except AlreadyExistsError as exc:
            raise MeshError(str(exc)) from exc

    async def render_server_config(self) -> str:
        """Render the WireGuard server configuration file.

        Includes the hub private key and a ``[Peer]`` section for each enabled
        mesh peer. Returns the configuration as a string (ending with a newline).
        """
        self._require_enabled()
        mesh = self.config.mesh
        hub_key = await self.ensure_hub_key()
        peers = await self.db.list_mesh_peers()
        lines = [
            "# Generated by Warden. Edit peers in the dashboard, not this file.",
            "[Interface]",
            f"Address = {mesh.address}",
            f"ListenPort = {mesh.listen_port}",
            f"PrivateKey = {hub_key}",
            "",
        ]
        for peer in peers:
            if not peer.enabled:
                continue
            lines.extend(
                [
                    f"# {peer.name}",
                    "[Peer]",
                    f"PublicKey = {peer.public_key}",
                    f"PresharedKey = {peer.preshared_key}",
                    f"AllowedIPs = {peer.address}/32",
                ]
            )
            if peer.endpoint:
                lines.append(f"Endpoint = {peer.endpoint}")
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    async def render_peer_config(self, peer: MeshPeer) -> str:
        """Render the client configuration for a specific mesh peer.

        * Uses the hub's public key and the peer's private key.
        * Includes DNS settings if configured on the mesh.
        * Sets the allowed IPs to the mesh's client range and optional ``PersistentKeepalive``.
        """
        self._require_enabled()
        mesh = self.config.mesh
        hub_public = await self.hub_public_key()
        lines = [
            "# Warden WireGuard peer",
            f"# {peer.name}",
            "[Interface]",
            f"PrivateKey = {peer.private_key or '<peer private key unavailable>'}",
            f"Address = {peer.address}/32",
        ]
        if mesh.dns:
            lines.append(f"DNS = {mesh.dns}")
        lines.extend(["", "[Peer]", f"PublicKey = {hub_public}", f"PresharedKey = {peer.preshared_key}"])
        endpoint = mesh.endpoint
        if endpoint:
            lines.append(f"Endpoint = {endpoint}")
        else:
            lines.append("# Set mesh.endpoint (public host:port) to make this config dial home.")
        lines.append(f"AllowedIPs = {mesh.client_allowed_ips}")
        if peer.keepalive:
            lines.append(f"PersistentKeepalive = {peer.keepalive}")
        return "\n".join(lines).rstrip() + "\n"

    def _config_file(self) -> Path:
        """Load mesh config file."""
        path = self.config.mesh_config_path
        if path is None:
            raise MeshError("Set mesh.config_path to the WireGuard config file, e.g. /etc/wireguard/wg0.conf.")
        return path

    async def write_config(self) -> Path:
        """Write the generated server configuration to ``mesh.config_path``.

        * Creates the parent directory with ``0o700`` permissions if needed.
        * Writes to a temporary file then atomically replaces the target.
        * Returns the ``Path`` to the final config file.
        """
        self._require_enabled()
        path = self._config_file()
        content = await self.render_server_config()
        parent = path.parent
        existed = parent.exists()
        parent.mkdir(parents=True, exist_ok=True)
        if not existed:
            # Only lockdown a directory Warden created. ``mesh.config_path`` can
            # point into /etc/wireguard or a shared directory, and chmod-ing an
            # existing one strips group/other access from unrelated files.
            try:
                os.chmod(parent, 0o700)
            except OSError:
                pass
        temp = path.with_name(f".{path.name}.warden-tmp")
        temp.write_text(content, encoding="utf-8")
        os.chmod(temp, 0o600)
        os.replace(temp, path)
        return path
