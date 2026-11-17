from __future__ import annotations

import json
import socket
import threading
from contextlib import contextmanager
from pathlib import Path

import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from websockets.sync.server import serve

from warden.main import create_app

from .conftest import config_dict, seed_user, write_config


def _handler(connection) -> None:
    request = connection.request
    path = request.path if request is not None else "/"
    headers = request.headers if request is not None else {}
    if path.startswith("/headers"):
        connection.send(
            json.dumps(
                {
                    "path": path,
                    "cookie": headers.get("Cookie"),
                    "user": headers.get("X-Warden-User"),
                    "user_id": headers.get("X-Warden-User-Id"),
                    "xff": headers.get("X-Forwarded-For"),
                    "xfp": headers.get("X-Forwarded-Proto"),
                }
            )
        )
    try:
        for message in connection:
            connection.send(message)
    except Exception:  # noqa: BLE001,S110
        pass


def _select_subprotocol(connection, subprotocols):
    # Accept clients that don't offer a subprotocol so the echo tests can run
    # against the same upstream as the negotiation test.
    return "chat" if "chat" in subprotocols else None


@contextmanager
def websocket_upstream():
    server = serve(
        _handler,
        "127.0.0.1",
        0,
        subprotocols=["chat"],
        select_subprotocol=_select_subprotocol,
    )
    port = server.socket.getsockname()[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)


def closed_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@pytest.fixture
def ws_client(tmp_path: Path):
    with websocket_upstream() as upstream:
        data = config_dict(
            tmp_path,
            routes=[
                {"host": "ws-public.home.lan", "upstream": upstream, "auth": False},
                {"host": "ws-auth.home.lan", "upstream": upstream, "auth": True},
                {
                    "host": "ws-disabled.home.lan",
                    "upstream": upstream,
                    "auth": False,
                    "websocket": False,
                },
                {
                    "host": "ws-dead.home.lan",
                    "upstream": f"http://127.0.0.1:{closed_port()}",
                    "auth": False,
                },
            ],
        )
        path = write_config(tmp_path, data)
        seed_user(tmp_path / "warden.db", credential_count=1)
        app = create_app(path)
        with TestClient(app, base_url="http://admin.home.lan") as client:
            yield client


def test_websocket_echo_public(ws_client) -> None:
    with ws_client.websocket_connect(
        "/echo", headers={"host": "ws-public.home.lan"}
    ) as websocket:
        websocket.send_text("hello")
        assert websocket.receive_text() == "hello"
        websocket.send_bytes(b"\x00\x01")
        assert websocket.receive_bytes() == b"\x00\x01"


def test_websocket_forwards_path_and_headers(ws_client) -> None:
    with ws_client.websocket_connect(
        "/headers?x=1", headers={"host": "ws-public.home.lan"}
    ) as websocket:
        payload = json.loads(websocket.receive_text())
    assert payload["path"] == "/headers?x=1"
    assert payload["cookie"] is None
    assert payload["user"] is None
    assert payload["xff"] == "testclient"
    assert payload["xfp"] == "http"


def test_websocket_authenticated_identity(ws_client) -> None:
    headers = {
        "host": "ws-auth.home.lan",
        "cookie": "warden_session=test-session-token; theme=dark",
        "x-warden-user": "evil",
        "x-forwarded-for": "6.6.6.6",
        "x-warden-user-id": "999",
    }
    with ws_client.websocket_connect("/headers", headers=headers) as websocket:
        payload = json.loads(websocket.receive_text())
    assert payload["path"] == "/headers"
    assert payload["cookie"] == "theme=dark"
    assert payload["user"] == "pat"
    assert payload["user_id"] == "1"
    assert payload["xff"] == "testclient"


def test_websocket_requires_session(ws_client) -> None:
    with pytest.raises(WebSocketDisconnect) as excinfo, ws_client.websocket_connect(
        "/echo", headers={"host": "ws-auth.home.lan"}
    ) as websocket:
        websocket.receive_text()
    assert excinfo.value.code == 4401
    assert "Sign in required" in excinfo.value.reason


def test_websocket_unknown_service(ws_client) -> None:
    with pytest.raises(WebSocketDisconnect) as excinfo, ws_client.websocket_connect(
        "/echo", headers={"host": "nothing.home.lan"}
    ) as websocket:
        websocket.receive_text()
    assert excinfo.value.code == 4404

    # The admin host does not expose proxy WebSockets.
    with pytest.raises(WebSocketDisconnect) as excinfo, ws_client.websocket_connect(
        "/echo", headers={"host": "admin.home.lan"}
    ) as websocket:
        websocket.receive_text()
    assert excinfo.value.code == 4404


def test_websocket_bad_origin(ws_client) -> None:
    with pytest.raises(WebSocketDisconnect) as excinfo, ws_client.websocket_connect(
        "/echo",
        headers={"host": "ws-public.home.lan", "origin": "http://evil.example"},
    ) as websocket:
        websocket.receive_text()
    assert excinfo.value.code == 4403
    assert "Origin" in excinfo.value.reason


def test_websocket_allows_configured_origin(ws_client) -> None:
    with ws_client.websocket_connect(
        "/echo",
        headers={"host": "ws-public.home.lan", "origin": "http://ws-public.home.lan"},
    ) as websocket:
        websocket.send_text("ok")
        assert websocket.receive_text() == "ok"


def test_websocket_disabled_route(ws_client) -> None:
    with pytest.raises(WebSocketDisconnect) as excinfo, ws_client.websocket_connect(
        "/echo", headers={"host": "ws-disabled.home.lan"}
    ) as websocket:
        websocket.receive_text()
    assert excinfo.value.code == 1008
    assert "disabled" in excinfo.value.reason.lower()


def test_websocket_upstream_unavailable(ws_client) -> None:
    with pytest.raises(WebSocketDisconnect) as excinfo, ws_client.websocket_connect(
        "/echo", headers={"host": "ws-dead.home.lan"}
    ) as websocket:
        websocket.receive_text()
    assert excinfo.value.code == 1011
    assert "Upstream" in excinfo.value.reason


def test_websocket_subprotocol(ws_client) -> None:
    with ws_client.websocket_connect(
        "/echo",
        headers={"host": "ws-public.home.lan"},
        subprotocols=["chat"],
    ) as websocket:
        assert websocket.accepted_subprotocol == "chat"
        websocket.send_text("hi")
        assert websocket.receive_text() == "hi"

def test_websocket_is_rate_limited(tmp_path: Path) -> None:
    """`routes[].rate_limit` applies to upgrades, not only to HTTP requests."""
    with websocket_upstream() as upstream:
        data = config_dict(
            tmp_path,
            routes=[
                {
                    "host": "ws-limited.home.lan",
                    "upstream": upstream,
                    "auth": False,
                    "rate_limit": 1,
                },
            ],
        )
        path = write_config(tmp_path, data)
        seed_user(tmp_path / "warden.db", credential_count=1)
        app = create_app(path)
        with TestClient(app, base_url="http://admin.home.lan") as client:
            with client.websocket_connect(
                "/echo", headers={"host": "ws-limited.home.lan"}
            ) as websocket:
                websocket.send_text("first")
                assert websocket.receive_text() == "first"
            with (
                pytest.raises(WebSocketDisconnect) as excinfo,
                client.websocket_connect(
                    "/echo", headers={"host": "ws-limited.home.lan"}
                ) as websocket,
            ):
                websocket.receive_text()
    assert excinfo.value.code == 4429


def test_websocket_rejects_an_unlisted_upstream_subprotocol(tmp_path: Path) -> None:
    """The upstream cannot select a protocol the route did not allow.

    The pre-flight check only proves that one of the offered protocols is
    allowed; offering an allowed one alongside another let an upstream choose
    the other and have it accepted.
    """
    with websocket_upstream() as upstream:
        data = config_dict(
            tmp_path,
            routes=[
                {
                    "host": "ws-subprotocol.home.lan",
                    "upstream": upstream,
                    "auth": False,
                    "websocket_subprotocols": ["other"],
                },
            ],
        )
        path = write_config(tmp_path, data)
        seed_user(tmp_path / "warden.db", credential_count=1)
        app = create_app(path)
        with (
            TestClient(app, base_url="http://admin.home.lan") as client,
            pytest.raises(WebSocketDisconnect) as excinfo,
            client.websocket_connect(
                "/echo",
                headers={"host": "ws-subprotocol.home.lan"},
                subprotocols=["other", "chat"],
            ) as websocket,
        ):
            websocket.receive_text()
    assert excinfo.value.code == 1008
    assert "Subprotocol" in excinfo.value.reason


def test_websocket_respects_ip_allow_list(tmp_path: Path) -> None:
    """A route restricted by IP must reject the upgrade, not just HTTP requests."""
    with websocket_upstream() as upstream:
        data = config_dict(
            tmp_path,
            routes=[
                {
                    "host": "ws-locked.home.lan",
                    "upstream": upstream,
                    "auth": False,
                    "allowed_ips": ["10.0.0.0/8"],
                },
            ],
        )
        path = write_config(tmp_path, data)
        seed_user(tmp_path / "warden.db", credential_count=1)
        app = create_app(path)
        with (
            TestClient(app, base_url="http://admin.home.lan") as client,
            pytest.raises(WebSocketDisconnect) as excinfo,
            client.websocket_connect(
                "/echo", headers={"host": "ws-locked.home.lan"}
            ) as websocket,
        ):
            websocket.receive_text()
    assert excinfo.value.code == 4403
    assert "Access denied" in excinfo.value.reason


def test_websocket_respects_blocked_paths(tmp_path: Path) -> None:
    """A blocked path must stop the upgrade, not just plain HTTP requests."""
    with websocket_upstream() as upstream:
        data = config_dict(
            tmp_path,
            routes=[
                {
                    "host": "ws-blocked.home.lan",
                    "upstream": upstream,
                    "auth": False,
                    "blocked_paths": ["/echo"],
                },
            ],
        )
        path = write_config(tmp_path, data)
        seed_user(tmp_path / "warden.db", credential_count=1)
        app = create_app(path)
        with (
            TestClient(app, base_url="http://admin.home.lan") as client,
            pytest.raises(WebSocketDisconnect) as excinfo,
            client.websocket_connect(
                "/echo", headers={"host": "ws-blocked.home.lan"}
            ) as websocket,
        ):
            websocket.receive_text()
    assert excinfo.value.code == 4403
