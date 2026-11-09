# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Primary user: a single self-hosting homelab administrator, or a small team sharing one instance. They manage reverse-proxy routes, TLS, WireGuard mesh, users, and access from a browser on their own network, often on a desktop or laptop.

## Product Purpose

Warden is a self-hosted reverse proxy and dashboard built around passkeys. It provides one passkey-protected front door for homelab services, including host-based routing, HTTP/WebSocket proxying, TLS and certificate renewal, optional WireGuard mesh management, metrics, audit logging, and user/access management.

## Positioning

Passkey-first, single-process, zero-build-step homelab gateway: native WebAuthn registration/login, server-rendered HTML with vanilla JS and one CSS file, YAML as source of truth, and integrated mesh/TLS/metrics in one self-hosted app.

## Operating Context

Used in a browser on the local network or over TLS. Configuration is YAML (`warden.yaml`); routes, users, mesh peers, and TLS are managed from the dashboard or CLI. The database (SQLite by default, PostgreSQL optional) stores sensitive material and must be protected. Single process; no multi-worker support.

## Capabilities and Constraints

- Passkey (WebAuthn) registration/login, backup codes, optional TOTP.
- Host-based routing, WebSocket proxying, IP allow/deny, per-route options.
- TLS termination and ACME renewal hooks.
- WireGuard hub-and-spoke mesh management.
- Prometheus metrics, health checks, audit log.
- No frontend build step; server-rendered Jinja templates + vanilla JS.
- Dark, utilitarian, lightweight UI preferred.

## Brand Commitments

Name: Warden. Tagline: "One door to your homelab." Dark color scheme by default. Minimal brand identity; functional and restrained.

## Evidence on Hand

- `README.md` documents features, config, API, deployment, security.
- Templates in `warden/templates/`, styles in `warden/templates/static/warden.css`.
- CLI and admin APIs as implemented.

## Product Principles

- One passkey-protected front door for all services.
- YAML remains source of truth; dashboard edits apply or clearly require restart.
- Quiet by default: protected routes redirect to a polished sign-in page.
- No build step: server-rendered HTML and vanilla JS.
- Single process, self-hosted, operator-controlled.

## Accessibility & Inclusion

Keyboard navigation, visible focus states, and readable contrast are expected. No known specialized accessibility requirements beyond baseline.