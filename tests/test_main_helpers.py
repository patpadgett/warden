"""Tests for internal helper functions in warden.main.

These tests target the private helpers that are not exercised directly by the
public test suite: the URL builder (`_public_base_url`) and the error response
factory (`_error_response`).  By constructing minimal config objects and a
Starlette ``Request`` we can verify the expected behaviour without pulling in
the full application.
"""

import json

from starlette.requests import Request

from warden.main import _error_response, _public_base_url


class DummyTLS:
    def __init__(self, enabled: bool):
        self.enabled = enabled


class DummyServer:
    def __init__(
        self,
        admin_host: str,
        public_url: str | None = None,
        https_port: int = 443,
        http_port: int = 80,
        tls: DummyTLS | None = None,
    ):
        self.admin_host = admin_host
        self.public_url = public_url
        self.https_port = https_port
        self.http_port = http_port
        self.tls = tls or DummyTLS(enabled=False)


class DummyConfig:
    def __init__(self, server: DummyServer):
        self.server = server


def test_public_base_url_uses_public_url_when_set():
    cfg = DummyConfig(DummyServer(admin_host="admin.example.com", public_url="https://custom.example.com"))
    assert _public_base_url(cfg) == "https://custom.example.com"


def test_public_base_url_http_default_port():
    server = DummyServer(admin_host="admin.example.com", tls=DummyTLS(enabled=False), http_port=80, https_port=443)
    cfg = DummyConfig(server)
    assert _public_base_url(cfg) == "http://admin.example.com"


def test_public_base_url_https_default_port():
    server = DummyServer(admin_host="admin.example.com", tls=DummyTLS(enabled=True), http_port=80, https_port=443)
    cfg = DummyConfig(server)
    assert _public_base_url(cfg) == "https://admin.example.com"


def test_public_base_url_nonstandard_port_is_included():
    server = DummyServer(admin_host="admin.example.com", tls=DummyTLS(enabled=False), http_port=8080)
    cfg = DummyConfig(server)
    assert _public_base_url(cfg) == "http://admin.example.com:8080"


def test_public_base_url_ipv6_brackets_are_added():
    server = DummyServer(admin_host="2001:db8::1", tls=DummyTLS(enabled=False), http_port=80)
    cfg = DummyConfig(server)
    assert _public_base_url(cfg) == "http://[2001:db8::1]"


def test_error_response_returns_json_when_client_accepts_json():
    # Build a minimal ASGI scope that advertises a JSON Accept header.
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/test",
        "headers": [(b"accept", b"application/json")],
        "client": ("127.0.0.1", 12345),
        "server": ("127.0.0.1", 8000),
    }
    request = Request(scope)
    response = _error_response(request, 404, "Not Found", "Missing resource")
    # The response should be a JSONResponse with status 404.
    assert response.status_code == 404
    # The body is JSON-encoded bytes.
    payload = json.loads(response.body)
    assert payload["detail"] == "Missing resource"
    # Cache‑Control must be set to no‑store for error responses.
    assert response.headers["Cache-Control"] == "no-store"

