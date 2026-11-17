from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from warden.main import create_app
from warden.utils import SESSION_COOKIE

from .conftest import config_dict, seed_user, write_config


# Helper to generate a TOTP code compatible with the server's verification logic
def _generate_totp(secret: str) -> str:
    # Decode the base32 secret (case‑insensitive, ignore spaces)
    key = base64.b32decode(secret.upper().replace(' ', ''), casefold=True)
    # Current 30‑second interval
    interval = int(time.time() // 30)
    # Compute the HMAC‑SHA1 of the counter
    msg = struct.pack('>Q', interval)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    # Dynamic truncation per RFC 4226
    o = h[-1] & 0x0F
    token = (struct.unpack('>I', h[o:o + 4])[0] & 0x7fffffff) % 1000000
    return f"{token:06d}"


@pytest.fixture
def auth_headers():
    """Headers for an authenticated admin‑host request.

    The seed_user fixture creates a session with token ``test-session-token``.
    """
    return {
        "host": "admin.home.lan",
        "origin": "http://admin.home.lan",
        "cookie": f"{SESSION_COOKIE}=test-session-token",
        "x-warden-request": "1",
    }


def test_otp_success_increments_metric(client, auth_headers):
    # Initialise OTP for the user – this creates a secret and returns it.
    resp = client.post("/_warden/auth/otp/setup", headers=auth_headers)
    assert resp.status_code == 200
    secret = resp.json()["secret"]

    # Generate a valid code for the freshly created secret.
    code = _generate_totp(secret)

    # Verify the OTP – should succeed and increment the success counter.
    resp2 = client.post("/_warden/auth/otp/verify", json={"code": code}, headers=auth_headers)
    assert resp2.status_code == 200
    assert resp2.json()["ok"] is True

    # Check the Prometheus metrics for the increment.
    metrics = client.get("/_warden/metrics", headers=auth_headers).text
    assert "warden_otp_success_total 1" in metrics


def test_otp_failure_increments_metric(client, auth_headers):
    # Initialise OTP – we will deliberately submit a wrong code.
    resp = client.post("/_warden/auth/otp/setup", headers=auth_headers)
    assert resp.status_code == 200
    # Use an obviously incorrect code.
    resp2 = client.post("/_warden/auth/otp/verify", json={"code": "000000"}, headers=auth_headers)
    assert resp2.status_code == 401
    assert resp2.json()["ok"] is False

    # Verify the failure counter was incremented.
    metrics = client.get("/_warden/metrics", headers=auth_headers).text
    assert "warden_otp_failure_total 1" in metrics


def test_backup_code_usage_increments_metric(client, auth_headers):
    # Create a backup code via the admin API.
    create_resp = client.post("/_warden/api/backup_codes", headers=auth_headers)
    assert create_resp.status_code == 200
    backup_code = create_resp.json()["code"]

    # Use the backup code to log in – this should increment the backup‑code metric.
    login_resp = client.post(
        "/_warden/auth/login/backup",
        json={"code": backup_code},
        headers=auth_headers,
    )
    assert login_resp.status_code == 200
    assert login_resp.json()["ok"] is True

    # Verify the metric reflecting backup‑code usage.
    metrics = client.get("/_warden/metrics", headers=auth_headers).text
    assert "warden_backup_code_used_total 1" in metrics


def test_auth_routes_await_async_rate_limiter(tmp_path: Path) -> None:
    """``rate_limiter.backend: redis`` returns a coroutine from ``allow``.

    The in-process limiter is synchronous, so auth routes have to await only
    when the result is awaitable; otherwise every sign-in request fails with a
    ``TypeError`` (and the limit is never enforced).
    """

    class _AsyncLimiter:
        async def allow(self, key: str, limit: int, window: float) -> tuple[bool, int]:
            return False, 0

    path = write_config(tmp_path, config_dict(tmp_path))
    seed_user(tmp_path / "warden.db", credential_count=1)
    app = create_app(path)
    with TestClient(app, base_url="http://admin.home.lan") as client:
        app.state.rate_limiter = _AsyncLimiter()
        response = client.post(
            "/_warden/auth/login/begin",
            json={},
            headers={"host": "admin.home.lan", "origin": "http://admin.home.lan"},
        )
    assert response.status_code == 429
    assert response.headers["x-ratelimit-limit"] == "30"
    assert response.headers["x-ratelimit-remaining"] == "0"
