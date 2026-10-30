# Warden Glossary

Terms that name seams and modules in this codebase.

- **Order** — not used here; the domain term for a routed proxy request is `RouteConfig` + `TrafficEvent`.
- **Route** (`RouteConfig`) — a configured upstream service; the unit of proxy routing, metrics, and health checks.
- **Mesh** (`MeshManager`) — WireGuard peer network managed by Warden; includes hub key, peer config, and apply lifecycle.
- **Metrics module** (`MetricsModule`) — in-memory traffic recording, health monitoring, and Prometheus export. Deepened into `MetricsModule` (stats) + `HealthMonitor` adapter (health adapter).
- **Peer intake** — the sub-module of mesh responsible for peer validation and DB storage (currently inside `MeshManager`); deepened form is `MeshPeerIntake`.
- **MeshPeerIntake** — deepened intake module (DB validation, address assignment, name regex, config render); backed by MeshApplyAdapter for apply/status.
- **MeshApplyAdapter** — apply adapter for WireGuard (`apply`, `status`, `refresh_handshakes`) backed by `wg`/`wg-quick`; routed through `MeshManager` facade.
- **Health adapter** — the adapter that takes `Stats` health checks and exposes them to external consumers (dashboard / Prometheus).
