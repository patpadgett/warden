from __future__ import annotations

import sqlite3
from pathlib import Path

from warden.config import load_config

from .conftest import (
    add_session,
    admin_headers,
    config_dict,
    count_rows,
    host_headers,
    write_config,
)


def test_health_and_security_headers(client) -> None:
    response = client.get("/_warden/health", headers={"host": "admin.home.lan"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["name"] == "warden"
    assert payload["setup_required"] is False
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert "default-src 'self'" in response.headers["content-security-policy"]

    static = client.get("/_warden/static/warden.css", headers={"host": "admin.home.lan"})
    assert static.status_code == 200
    assert static.headers["x-content-type-options"] == "nosniff"
    assert "cache-control" not in static.headers


def test_unclaimed_instance_redirects_to_setup(unclaimed_client) -> None:
    response = unclaimed_client.get(
        "/",
        headers={"host": "admin.home.lan", "accept": "text/html"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/_warden/setup"

    api = unclaimed_client.get(
        "/_warden/api/status",
        headers={"host": "admin.home.lan", "accept": "application/json"},
        follow_redirects=False,
    )
    assert api.status_code == 401
    assert api.json()["setup_required"] is True
    assert api.json()["setup_url"] == "/_warden/setup"

    setup = unclaimed_client.get("/_warden/setup", headers={"host": "admin.home.lan"})
    assert setup.status_code == 200
    assert "Claim" in setup.text or "setup" in setup.text.lower()


def test_admin_pages_require_session(client) -> None:
    response = client.get(
        "/", headers={"host": "admin.home.lan", "accept": "text/html"}, follow_redirects=False
    )
    assert response.status_code == 303
    assert response.headers["location"].startswith("/_warden/login?next=")
    assert response.headers["cache-control"] == "no-store"

    api = client.get(
        "/_warden/api/status",
        headers={"host": "admin.home.lan", "accept": "application/json"},
        follow_redirects=False,
    )
    assert api.status_code == 401
    assert api.json()["detail"] == "Sign in to continue."

    post = client.post(
        "/_warden/api/services",
        json={"host": "x.home.lan", "upstream": "http://127.0.0.1:9"},
        headers={"host": "admin.home.lan"},
        follow_redirects=False,
    )
    assert post.status_code == 401


def test_dashboard_and_pages_render(client, app_and_path) -> None:
    _app, path = app_and_path
    dashboard = client.get("/", headers=admin_headers())
    assert dashboard.status_code == 200
    assert "App" in dashboard.text
    assert "Public" in dashboard.text
    assert "TLS is off" in dashboard.text
    assert dashboard.headers["cache-control"] == "no-store"
    assert "frame-ancestors 'none'" in dashboard.headers["content-security-policy"]

    passkeys = client.get("/passkeys", headers=admin_headers())
    assert passkeys.status_code == 200
    assert "Test passkey" in passkeys.text
    assert "Spare 1" in passkeys.text

    activity = client.get("/activity", headers=admin_headers())
    assert activity.status_code == 200
    assert "Signed in with a passkey" in activity.text

    config_page = client.get("/config", headers=admin_headers())
    assert config_page.status_code == 200
    assert str(path) in config_page.text
    assert "routes:" in config_page.text

    mesh = client.get("/mesh", headers=admin_headers())
    assert mesh.status_code == 200
    assert "WireGuard" in mesh.text

    # Admin routes are only reachable on the admin host.
    not_admin = client.get("/passkeys", headers=host_headers("app.home.lan"))
    assert not_admin.status_code == 200
    assert "warden" not in not_admin.text.lower()[:200]

    status = client.get("/_warden/api/status", headers=admin_headers())
    assert status.status_code == 200
    payload = status.json()
    assert payload["totals"]["services"] == 6
    assert "app.home.lan" in payload["services"]
    assert payload["services"]["app.home.lan"]["state"] in {"checking", "online", "offline"}


def test_login_page_redirects_authenticated_session(client) -> None:
    response = client.get("/_warden/login", headers=admin_headers(), follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/"

    response = client.get(
        "/_warden/login?next=%2Fconfig", headers=admin_headers(), follow_redirects=False
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/config"

    anonymous = client.get(
        "/_warden/login", headers={"host": "admin.home.lan"}, follow_redirects=False
    )
    assert anonymous.status_code == 200

    setup = client.get("/_warden/setup", headers={"host": "admin.home.lan"}, follow_redirects=False)
    assert setup.status_code == 303
    assert setup.headers["location"] == "/_warden/login?next=%2F"


def test_unknown_host_and_internal_prefix(client) -> None:
    html = client.get(
        "/anything",
        headers={"host": "unknown.home.lan", "accept": "text/html"},
        follow_redirects=False,
    )
    assert html.status_code == 404
    assert "connected to a service" in html.text
    assert html.headers["cache-control"] == "no-store"

    api = client.get(
        "/anything",
        headers={"host": "unknown.home.lan", "accept": "application/json"},
        follow_redirects=False,
    )
    assert api.status_code == 404
    assert api.json()["detail"] == "No service here"

    internal = client.get(
        "/_warden/api/status",
        headers=host_headers("app.home.lan", "test-session-token"),
        follow_redirects=False,
    )
    assert internal.status_code == 404

    missing = client.get("/_warden/does-not-exist", headers=admin_headers())
    assert missing.status_code == 404
    assert "Warden" in missing.text or "not found" in missing.text.lower()


def test_public_route_is_proxied(client) -> None:
    response = client.get(
        "/hello?x=1",
        headers=host_headers("public.home.lan"),
        follow_redirects=False,
    )
    assert response.status_code == 200
    assert "path=/hello?x=1" in response.text
    assert "xff=testclient" in response.text
    assert "xfp=http" in response.text
    assert "user=None" in response.text
    assert "cookie=None" in response.text

    # Public paths bypass auth on an otherwise protected route.
    public = client.get("/public/info", headers=host_headers("app.home.lan"))
    assert public.status_code == 200
    assert "path=/public/info" in public.text


def test_protected_route_requires_session(client) -> None:
    response = client.get(
        "/dashboard",
        headers={"host": "app.home.lan", "accept": "text/html"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"].startswith("/_warden/login?next=")
    assert "%2Fdashboard" in response.headers["location"]

    api = client.get(
        "/api/data",
        headers={"host": "app.home.lan", "accept": "application/json"},
        follow_redirects=False,
    )
    assert api.status_code == 401
    assert api.json()["login_url"].startswith("/_warden/login?next=")

    post = client.post(
        "/submit",
        headers={"host": "app.home.lan"},
        content=b"nope",
        follow_redirects=False,
    )
    assert post.status_code == 401


def test_proxy_authenticates_and_sanitizes_headers(client) -> None:
    headers = {
        "host": "app.home.lan",
        "cookie": "warden_session=test-session-token; theme=dark; warden_challenge=spoof",
        "x-forwarded-for": "6.6.6.6",
        "x-forwarded-proto": "https",
        "x-real-ip": "6.6.6.6",
        "x-warden-user": "evil",
        "x-warden-user-id": "999",
        "x-forwarded-user": "evil",
        "forwarded": "for=6.6.6.6",
    }
    response = client.get("/whoami", headers=headers)
    assert response.status_code == 200
    assert "path=/whoami" in response.text
    assert "host=127.0.0.1:" in response.text
    assert "xff=testclient" in response.text
    assert "xfp=http" in response.text
    assert "user=pat" in response.text
    assert "cookie=theme=dark" in response.text
    assert "route=yes" in response.text
    assert "evil" not in response.text


def test_proxy_preserve_host(client) -> None:
    response = client.get("/x", headers=host_headers("preserve.home.lan"))
    assert response.status_code == 200
    assert "host=preserve.home.lan" in response.text


def test_proxy_rewrites_redirects_and_cookies(client) -> None:
    response = client.get(
        "/redirect",
        headers=host_headers("public.home.lan"),
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert response.headers["location"] == "http://public.home.lan/landing?x=1"
    cookies = response.headers.get_list("set-cookie")
    assert any(cookie.startswith("session=abc") for cookie in cookies)
    assert not any(cookie.startswith("warden_session=") for cookie in cookies)


def test_proxy_post_body(client) -> None:
    response = client.post(
        "/submit",
        content=b"hello=world",
        headers=host_headers("public.home.lan"),
    )
    assert response.status_code == 200
    assert "body=hello=world" in response.text


def test_proxy_disabled_route_and_wildcard(client) -> None:
    disabled = client.get("/", headers=host_headers("disabled.home.lan"))
    assert disabled.status_code == 404
    assert "This service is paused" in disabled.text

    wildcard = client.get("/media", headers=host_headers("video.apps.home.lan"))
    assert wildcard.status_code == 200
    assert "path=/media" in wildcard.text


def test_proxy_upstream_failure(client) -> None:
    response = client.get(
        "/", headers={"host": "dead.home.lan", "accept": "text/html"}, follow_redirects=False
    )
    assert response.status_code == 502
    assert "out of reach" in response.text.lower()
    assert response.headers["cache-control"] == "no-store"

    api = client.get(
        "/", headers={"host": "dead.home.lan", "accept": "application/json"}, follow_redirects=False
    )
    assert api.status_code == 502
    assert api.json()["status"] == 502


def test_admin_api_requires_csrf_header_and_same_origin(client) -> None:
    payload = {"host": "csrf.home.lan", "upstream": "http://127.0.0.1:9"}
    missing = client.post("/_warden/api/services", json=payload, headers=admin_headers())
    assert missing.status_code == 403
    assert missing.json()["detail"] == "Missing X-Warden-Request header."

    cross = client.post(
        "/_warden/api/services",
        json=payload,
        headers=admin_headers(**{"X-Warden-Request": "1", "Origin": "http://evil.example"}),
    )
    assert cross.status_code == 403
    assert cross.json()["detail"] == "Cross-origin request blocked."

    allowed = client.post(
        "/_warden/api/services",
        json=payload,
        headers=admin_headers(
            **{"X-Warden-Request": "1", "Origin": "http://admin.home.lan"}
        ),
    )
    assert allowed.status_code == 200
    assert allowed.json()["ok"] is True


def test_service_api_crud(client, app_and_path, upstream_server) -> None:
    app, path = app_and_path
    manager = app.state.manager
    _server, upstream = upstream_server
    headers = admin_headers(**{"X-Warden-Request": "1"})

    created = client.post(
        "/_warden/api/services",
        json={"host": "new.home.lan", "upstream": upstream, "name": "New", "auth": False},
        headers=headers,
    )
    assert created.status_code == 200
    assert created.json()["restart_required"] == []
    assert manager.config.match_route("new.home.lan").name == "New"
    assert "new.home.lan" in path.read_text()

    live = client.get("/live", headers=host_headers("new.home.lan"))
    assert live.status_code == 200
    assert "path=/live" in live.text

    updated = client.put(
        "/_warden/api/services/new.home.lan",
        json={"host": "new.home.lan", "upstream": upstream, "name": "Renamed", "enabled": False},
        headers=headers,
    )
    assert updated.status_code == 200
    route = manager.config.match_route("new.home.lan")
    assert route.name == "Renamed"
    assert route.enabled is False

    duplicate = client.post(
        "/_warden/api/services",
        json={"host": "new.home.lan", "upstream": upstream},
        headers=headers,
    )
    assert duplicate.status_code == 400
    assert "already exists" in duplicate.json()["detail"]

    invalid = client.post(
        "/_warden/api/services",
        json={"host": "admin.home.lan", "upstream": upstream},
        headers=headers,
    )
    assert invalid.status_code == 400

    deleted = client.delete("/_warden/api/services/new.home.lan", headers=headers)
    assert deleted.status_code == 200
    assert manager.config.match_route("new.home.lan") is None
    assert "new.home.lan" not in path.read_text()


def test_config_api_reads_validates_and_saves(client, app_and_path, tmp_path: Path) -> None:
    app, path = app_and_path
    manager = app.state.manager
    headers = admin_headers(**{"X-Warden-Request": "1"})

    read = client.get("/_warden/api/config", headers=admin_headers())
    assert read.status_code == 200
    assert read.json()["path"] == str(path)
    original = read.json()["yaml"]
    assert "admin_host: admin.home.lan" in original

    invalid = client.post(
        "/_warden/api/config/validate", json={"yaml": "routes: [\n"}, headers=headers
    )
    assert invalid.status_code == 400
    assert invalid.json()["ok"] is False
    assert invalid.json()["detail"]

    valid = client.post(
        "/_warden/api/config/validate", json={"yaml": original}, headers=headers
    )
    assert valid.status_code == 200
    assert valid.json()["ok"] is True
    assert valid.json()["restart_required"] == []

    changed = original.replace("admin_host: admin.home.lan", "admin_host: console.home.lan")
    saved = client.post("/_warden/api/config", json={"yaml": changed}, headers=headers)
    assert saved.status_code == 200
    assert "server.admin_host" in saved.json()["restart_required"]
    # The running process keeps the old host until it restarts.
    assert manager.config.server.admin_host == "admin.home.lan"
    assert load_config(path).server.admin_host == "console.home.lan"
    assert client.get("/", headers=admin_headers()).status_code == 200

    bad = client.post("/_warden/api/config", json={"yaml": "version: nope"}, headers=headers)
    assert bad.status_code == 400
    assert "Invalid configuration" in bad.json()["detail"]
    assert load_config(path).server.admin_host == "console.home.lan"


def test_passkey_and_session_apis(client, app_and_path) -> None:
    app, _path = app_and_path
    db_path = app.state.db.path
    headers = admin_headers(**{"X-Warden-Request": "1"})

    with sqlite3.connect(db_path) as connection:
        credential_ids = [
            row[0] for row in connection.execute("SELECT id FROM credentials ORDER BY id")
        ]
    assert len(credential_ids) == 2

    renamed = client.patch(
        f"/_warden/api/passkeys/{credential_ids[0]}",
        json={"name": "Renamed key"},
        headers=headers,
    )
    assert renamed.status_code == 200
    with sqlite3.connect(db_path) as connection:
        assert (
            connection.execute(
                "SELECT name FROM credentials WHERE id = ?", (credential_ids[0],)
            ).fetchone()[0]
            == "Renamed key"
        )

    empty = client.patch(
        f"/_warden/api/passkeys/{credential_ids[0]}", json={"name": "  "}, headers=headers
    )
    assert empty.status_code == 400
    missing = client.patch(
        "/_warden/api/passkeys/9999", json={"name": "Nope"}, headers=headers
    )
    assert missing.status_code == 404

    deleted = client.delete(
        f"/_warden/api/passkeys/{credential_ids[1]}", headers=headers
    )
    assert deleted.status_code == 200
    last = client.delete(f"/_warden/api/passkeys/{credential_ids[0]}", headers=headers)
    assert last.status_code == 409

    add_session(db_path, "second-session", user_id=1)
    assert count_rows(db_path, "sessions") == 2
    revoked = client.post("/_warden/api/sessions/revoke-others", headers=headers)
    assert revoked.status_code == 200
    assert revoked.json()["count"] == 1
    assert count_rows(db_path, "sessions") == 1

    with sqlite3.connect(db_path) as connection:
        session_id = connection.execute("SELECT id FROM sessions").fetchone()[0]
    current = client.delete(f"/_warden/api/sessions/{session_id}", headers=headers)
    assert current.status_code == 200
    assert current.json()["redirect"].startswith("/_warden/login")
    assert count_rows(db_path, "sessions") == 0

    # The revoked cookie no longer authenticates.
    stale = client.get(
        "/", headers={"host": "admin.home.lan", "accept": "text/html"}, follow_redirects=False
    )
    assert stale.status_code == 303


def test_mesh_api_disabled(client) -> None:
    headers = admin_headers(**{"X-Warden-Request": "1"})
    response = client.post(
        "/_warden/api/mesh/peers", json={"name": "Phone"}, headers=headers
    )
    assert response.status_code == 400
    assert "disabled" in response.json()["detail"]

    status = client.get("/_warden/api/mesh/status", headers=admin_headers())
    assert status.status_code == 400


def test_acme_challenge_route(tmp_path: Path) -> None:
    from starlette.testclient import TestClient

    from warden.main import create_app

    webroot = tmp_path / "acme"
    webroot.mkdir()
    (webroot / "token123").write_text("challenge-value\n")
    data = config_dict(
        tmp_path, tls={"enabled": False, "acme_webroot": str(webroot)}
    )
    path = write_config(tmp_path, data)
    app = create_app(path)
    with TestClient(app) as test_client:
        response = test_client.get(
            "/.well-known/acme-challenge/token123", headers={"host": "admin.home.lan"}
        )
        assert response.status_code == 200
        assert response.text == "challenge-value"
        assert response.headers["cache-control"] == "no-store"

        missing = test_client.get(
            "/.well-known/acme-challenge/nope", headers={"host": "admin.home.lan"}
        )
        assert missing.status_code == 404
        invalid = test_client.get(
            "/.well-known/acme-challenge/bad.token", headers={"host": "admin.home.lan"}
        )
        assert invalid.status_code == 404
        # The route is public even on a service host.
        public = test_client.get(
            "/.well-known/acme-challenge/token123", headers={"host": "app.home.lan"}
        )
        assert public.status_code == 200
