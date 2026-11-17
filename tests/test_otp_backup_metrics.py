from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import struct
import time
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from warden.db import Database
from warden.main import create_app
from warden.utils import SESSION_COOKIE

from .conftest import config_dict, seed_user, write_config


# Helper to generate a TOTP code compatible with the server's verification logic
def _generate_totp(secret: str, offset: int = 0) -> str:
    # Decode the base32 secret (case‑insensitive, ignore spaces)
    key = base64.b32decode(secret.upper().replace(' ', ''), casefold=True)
    # Current 30‑second interval, shifted by *offset* steps when needed
    interval = int(time.time() // 30) + offset
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


def test_otp_status_and_disable(client, auth_headers):
    """Two-factor can be enrolled and turned off without `warden auth reset`."""
    status = client.get("/_warden/auth/otp/status", headers=auth_headers)
    assert status.status_code == 200
    assert status.json() == {"enabled": False, "pending": False}

    secret = client.post("/_warden/auth/otp/setup", headers=auth_headers).json()["secret"]
    assert client.get("/_warden/auth/otp/status", headers=auth_headers).json() == {
        "enabled": False,
        "pending": True,
    }

    verify = client.post(
        "/_warden/auth/otp/verify", json={"code": _generate_totp(secret)}, headers=auth_headers
    )
    assert verify.status_code == 200
    assert client.get("/_warden/auth/otp/status", headers=auth_headers).json() == {
        "enabled": True,
        "pending": False,
    }

    wrong = client.post(
        "/_warden/auth/otp/disable", json={"code": "000000"}, headers=auth_headers
    )
    assert wrong.status_code == 401
    assert client.get("/_warden/auth/otp/status", headers=auth_headers).json()["enabled"] is True

    # The enrolment code was spent by the verify above, so use the next step
    # (still inside the accepted drift window) rather than replaying it.
    off = client.post(
        "/_warden/auth/otp/disable",
        json={"code": _generate_totp(secret, offset=1)},
        headers=auth_headers,
    )
    assert off.status_code == 200
    assert off.json() == {"ok": True, "enabled": False}
    assert client.get("/_warden/auth/otp/status", headers=auth_headers).json() == {
        "enabled": False,
        "pending": False,
    }


def test_require_otp_confines_an_unenrolled_admin(tmp_path: Path) -> None:
    """With the policy on, only the passkeys page is reachable until enrolment."""
    path = write_config(tmp_path, config_dict(tmp_path, require_otp_for_admins=True))
    seed_user(tmp_path / "warden.db")
    app = create_app(path)
    headers = {
        "host": "admin.home.lan",
        "origin": "http://admin.home.lan",
        "cookie": f"{SESSION_COOKIE}=test-session-token",
        "x-warden-request": "1",
    }
    navigation = {**headers, "accept": "text/html", "sec-fetch-mode": "navigate"}
    with TestClient(app, base_url="http://admin.home.lan") as client:
        blocked = client.get("/users", headers=navigation, follow_redirects=False)
        assert blocked.status_code == 303
        assert blocked.headers["location"] == "/passkeys?otp_required=1"

        page = client.get("/passkeys?otp_required=1", headers=navigation)
        assert page.status_code == 200
        assert "Two-factor is required" in page.text

        api = client.get("/_warden/api/status", headers={**headers, "accept": "application/json"})
        assert api.status_code == 403
        assert api.json()["otp_setup_required"] is True

        # Enrolling through the page's own endpoints lifts the restriction
        # without a second sign-in.
        secret = client.post("/_warden/auth/otp/setup", headers=headers).json()["secret"]
        verified = client.post(
            "/_warden/auth/otp/verify",
            json={"code": _generate_totp(secret)},
            headers=headers,
        )
        assert verified.status_code == 200, verified.text
        assert client.get("/users", headers=navigation).status_code == 200


def test_admin_can_reset_another_users_totp(tmp_path: Path) -> None:
    """A lost authenticator is recoverable per account, not per instance."""
    path = write_config(tmp_path, config_dict(tmp_path))
    admin_id, _token = seed_user(tmp_path / "warden.db")

    async def _seed() -> int:
        db = Database(tmp_path / "warden.db")
        await db.init()
        try:
            user = await db.create_user(
                username="robin",
                display_name="Robin",
                webauthn_user_id=b"r" * 16,
                is_admin=False,
            )
            await db.set_otp_secret(user.id, "JBSWY3DPEHPK3PXP")
            return user.id
        finally:
            await db.close()

    robin_id = asyncio.run(_seed())
    app = create_app(path)
    headers = {
        "host": "admin.home.lan",
        "origin": "http://admin.home.lan",
        "cookie": f"{SESSION_COOKIE}=test-session-token",
        "x-warden-request": "1",
    }
    page_headers = {**headers, "accept": "text/html"}
    with TestClient(app, base_url="http://admin.home.lan") as client:
        page = client.get("/users", headers=page_headers)
        assert page.status_code == 200
        assert f'data-user-id="{robin_id}"' in page.text
        assert "Reset 2FA" in page.text

        reset = client.post(f"/_warden/api/users/{robin_id}/otp/reset", headers=headers)
        assert reset.status_code == 200
        assert reset.json() == {"ok": True, "reset": True}
        assert "Reset 2FA" not in client.get("/users", headers=page_headers).text

        again = client.post(f"/_warden/api/users/{robin_id}/otp/reset", headers=headers)
        assert again.json() == {"ok": True, "reset": False}

        own = client.post(f"/_warden/api/users/{admin_id}/otp/reset", headers=headers)
        assert own.status_code == 400

        missing = client.post("/_warden/api/users/9999/otp/reset", headers=headers)
        assert missing.status_code == 404


def test_login_otp_challenge_survives_a_wrong_code(tmp_path: Path) -> None:
    """A mistyped code must not send the user back through the passkey step."""
    path = write_config(tmp_path, config_dict(tmp_path))
    user_id, _token = seed_user(tmp_path / "warden.db")
    secret = "JBSWY3DPEHPK3PXP"

    async def _seed() -> None:
        db = Database(tmp_path / "warden.db")
        await db.init()
        try:
            await db.set_otp_secret(user_id, secret)
            await db.create_challenge(
                "login-otp-challenge",
                "login_otp",
                {"user_id": user_id, "next": "/"},
                300,
            )
        finally:
            await db.close()

    asyncio.run(_seed())

    app = create_app(path)
    headers = {"host": "admin.home.lan", "origin": "http://admin.home.lan"}
    with TestClient(app, base_url="http://admin.home.lan") as client:
        wrong = client.post(
            "/_warden/auth/login/otp",
            json={"challenge": "login-otp-challenge", "code": "000000"},
            headers=headers,
        )
        assert wrong.status_code == 401

        retried = client.post(
            "/_warden/auth/login/otp",
            json={"challenge": "login-otp-challenge", "code": _generate_totp(secret)},
            headers=headers,
        )
        assert retried.status_code == 200, retried.text
        assert retried.json()["ok"] is True
