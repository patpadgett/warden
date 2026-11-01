"""WireGuard mesh apply adapter.

Implements the apply/status/refresh_handshakes seam for WireGuard mesh configuration.
Backed by wg/wg-quick subprocesses.
"""

from __future__ import annotations

import asyncio
import shutil
import time
from typing import Any

from warden.mesh_peer import MeshError, MeshPeerIntake, PeerStatus


class MeshApplyAdapter:
    """Apply adapter for WireGuard mesh configuration.

    Takes a MeshPeerIntake instance to access config rendering and writes,
    and the mesh configuration to apply.
    """

    def __init__(self, intake: MeshPeerIntake) -> None:
        self.intake = intake
        self.config = intake.config

    async def _run(self, args: list[str], *, input_bytes: bytes | None = None, timeout: int = 60) -> tuple[int, str]:
        """Execute a subprocess command with timeout enforcement."""
        try:
            process = await asyncio.create_subprocess_exec(
                *args,
                stdin=asyncio.subprocess.PIPE if input_bytes is not None else asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        except OSError as exc:
            raise MeshError(f"Could not run {args[0]}: {exc}") from exc

        try:
            output, _ = await asyncio.wait_for(process.communicate(input_bytes), timeout=timeout)
        except TimeoutError:
            process.kill()
            await process.wait()
            raise MeshError(f"{args[0]} timed out after {timeout} seconds.")

        return process.returncode or 0, output.decode("utf-8", "replace").strip()

    async def apply(self) -> dict[str, Any]:
        """Apply the current WireGuard configuration.

        * Writes the config file via MeshPeerIntake.write_config
        * Checks if the interface is up using wg show
        * If up, uses wg-quick strip to trim config and syncs it
        * If down, brings interface up with wg-quick up
        * Returns result dict with ok, output, config_path, interface, timestamp
        """
        self.intake._require_enabled()
        wg = shutil.which("wg")
        wg_quick = shutil.which("wg-quick")

        if not wg:
            raise MeshError("WireGuard isn't installed: the 'wg' command was not found.")

        path = await self.intake.write_config()
        interface = self.config.mesh.interface
        check_code, _ = await self._run([wg, "show", interface], timeout=10)

        if check_code == 0:
            if not wg_quick:
                raise MeshError(
                    f"Interface {interface} is already up, but 'wg-quick' is unavailable "
                    "for stripping the Warden config. Install wireguard-tools."
                )
            strip_code, stripped = await self._run(
                [wg_quick, "strip", str(path)], timeout=20
            )
            if strip_code != 0:
                raise MeshError(f"wg-quick strip failed: {stripped}")
            code, output = await self._run(
                [wg, "syncconf", interface, "/dev/stdin"],
                input_bytes=stripped.encode("utf-8"),
            )
        else:
            if not wg_quick:
                raise MeshError(
                    f"Interface {interface} is down and 'wg-quick' is unavailable. Bring it up manually."
                )
            code, output = await self._run([wg_quick, "up", str(path)], timeout=90)

        result = {
            "ok": code == 0,
            "output": output,
            "config_path": str(path),
            "interface": interface,
            "timestamp": time.time(),
        }
        self.intake.last_apply = result

        if code != 0:
            raise MeshError(output or f"WireGuard returned exit code {code}")

        return result

    async def status(self) -> dict[str, Any]:
        """Return the current status of the mesh interface."""
        mesh = self.config.mesh
        wg = shutil.which("wg")

        if not mesh.enabled or not wg:
            return {"available": False, "applied": False, "peers": {}}

        code, output = await self._run([wg, "show", mesh.interface, "dump"], timeout=10)

        if code != 0:
            return {
                "available": True,
                "applied": False,
                "peers": {},
                "detail": output or f"Interface {mesh.interface} is not up.",
            }

        peers: dict[str, PeerStatus] = {}
        for line in output.splitlines()[1:]:
            fields = line.split("\t")
            if len(fields) < 8:
                continue
            public_key = fields[0]
            handshake = int(fields[4]) if fields[4].isdigit() else 0
            try:
                rx = int(fields[5])
                tx = int(fields[6])
            except ValueError:
                rx = tx = 0

            peers[public_key] = PeerStatus(
                endpoint=fields[2] or None,
                last_handshake=float(handshake) if handshake else None,
                rx_bytes=rx,
                tx_bytes=tx,
                keepalive=fields[7] or None,
            )

        return {"available": True, "applied": True, "peers": peers, "detail": ""}

    async def refresh_handshakes(self) -> dict[str, Any]:
        """Refresh handshake timestamps for all peers."""
        status = await self.status()
        if status.get("applied"):
            live = status.get("peers", {})
            for peer in await self.intake.db.list_mesh_peers():
                info = live.get(peer.public_key)
                await self.intake.db.set_mesh_handshake(
                    peer.id, info.last_handshake if info else None
                )
        return status
