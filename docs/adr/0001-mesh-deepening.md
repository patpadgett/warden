# ADR-0001: MeshPeerIntake deepening and apply-adapter seam

## Status
Implemented (mesh split complete; MetricsModule + health adapter split complete)

## Context
`MeshManager` (445 lines, `warden/mesh.py`) combines peer intake (DB validation, address assignment), config rendering, WireGuard subprocess apply, and status parsing in one shallow interface. Recent changes (`test_mesh_targeted.py`, `test_mesh_coverage.py`) confirm the split is testable separately.

## Decision
Split into two deep modules behind a real seam:

- `MeshPeerIntake` — intake + hub-key management + config render (DB, regex, address assignment, `render_server_config`, `render_peer_config`).
- Apply adapter (`MeshApplyAdapter`) — `apply`, `status`, `refresh_handshakes`; backed by `wg`/`wg-quick` subprocess.

Two adapters (test stub + prod) make the seam real.

## Consequences
- Routes / CLI / dashboard callers must point to `MeshPeerIntake` for peer operations; adapter for apply/status.
- `MeshManager` shrinks to coordination layer or is retired.
- Tests: intake survives; apply tests become adapter-mock tests.

## Terms (per GLOSSARY.md)
- Peer intake; MeshPeerIntake; Mesh; apply adapter; seam.
