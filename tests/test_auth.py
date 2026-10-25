from __future__ import annotations

import base64
import sqlite3
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from starlette.testclient import TestClient

from warden.auth.passkeys import SETUP_EXPIRY_KEY, normalize_setup_code
from warden.main import create_app

from .conftest import config_dict, count_rows, host_headers, write_config

ADMIN = {"host": "admin.home.lan"}
SAME_ORIGIN = {**ADMIN, "origin": "http://admin.home.lan"}
SETUP_CODE = "TEST-SETUP-CODE-1234"


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def fake_registration(credential_id: bytes = b"n" * 32):
    return SimpleNamespace(
        credential_id=credential_id,
        credential_public_key=b"public-key" * 8,
        sign_count=0,
        aaguid="00000000-0000-0000-0000-000000000000",
        fmt="none",
        user_verified=True,
        credential_backed_up=False,
    )


def fake_authentication(credential_id: bytes = b"c" * 32, sign_count: int = 2):
    return SimpleNamespace(credential_id=credential_id, new_sign_count=sign_count)


def begin_setup(client, *, code: str = SETUP_CODE, username: str = "pat", next_path: str = "/"):
    return client.post(
        "/_warden/auth/setup/begin",
        json={
            "username": username,
            "display_name": username.title(),
            "setup_code": code,
            "next": next_path,
        },
        headers=SAME_ORIGIN,
    )


def complete_setup(client, challenge: str, credential: dict | None = None, *, headers=None):
    return client.post(
        "/_warden/auth/setup/complete",
        json={"credential": credential or {"id": "x", "rawId": "eA", "type": "public-key"}},
        headers=headers or {**SAME_ORIGIN, "cookie": f"warden_challenge={challenge}"},
    )


def begin_login(client, *, username: str | None = "pat", next_path: str = "/", headers=None):
    return client.post(
        "/_warden/auth/login/begin",
        json={"username": username, "next": next_path},
        headers=headers or SAME_ORIGIN,
    )


def complete_login(client, challenge: str, credential: dict, *, headers=None):
    return client.post(
        "/_warden/auth/login/complete",
        json={"credential": credential},
        headers=headers or {**SAME_ORIGIN, "cookie": f"warden_challenge={challenge}"},
    )


def db_path(client) -> Path:
    return client.app.state.db.path


def test_setup_code_normalization() -> None:
    assert normalize_setup_code("TEST-SETUP-CODE-1234") == "TESTSETUPCODE1234"
    assert normalize_setup_code("  test setup ") == "TESTSETUP"


def test_setup_rejects_bad_code_and_cross_origin(unclaimed_client) -> None:
    wrong = begin_setup(unclaimed_client, code="WRONG-CODE-1234")
    assert wrong.status_code == 400
    assert "isn't right" in wrong.json()["detail"]

    cross = unclaimed_client.post(
        "/_warden/auth/setup/begin",
        json={"username": "pat", "setup_code": SETUP_CODE},
        headers={"host": "admin.home.lan", "origin": "http://evil.example"},
    )
    assert cross.status_code == 403
    assert cross.json()["detail"] == "Cross-origin request blocked."

    with sqlite3.connect(db_path(unclaimed_client)) as connection:
        events = [row[0] for row in connection.execute("SELECT event FROM audit ORDER BY id")]
    assert "setup_failed" in events
    assert "setup_blocked" in events

    assert count_rows(db_path(unclaimed_client), "users") == 0


def test_setup_content_type_and_username_validation(unclaimed_client) -> None:
    plain = unclaimed_client.post(
        "/_warden/auth/setup/begin",
        content=b"username=pat",
        headers={**SAME_ORIGIN, "content-type": "text/plain"},
    )
    assert plain.status_code == 415
    assert "application/json" in plain.json()["detail"]

    bad_name = begin_setup(unclaimed_client, username="!")
    assert bad_name.status_code == 400
    assert "Username must be" in bad_name.json()["detail"]

    long_name = begin_setup(unclaimed_client, username="a" * 40)
    assert long_name.status_code == 400


def test_setup_begin_returns_options_and_challenge(unclaimed_client) -> None:
    response = begin_setup(unclaimed_client, next_path="/activity")
    assert response.status_code == 200
    payload = response.json()
    assert payload["publicKey"]["rp"]["id"] == "home.lan"
    assert payload["publicKey"]["rp"]["name"] == "Warden Test"
    assert payload["publicKey"]["user"]["name"] == "pat"
    assert payload["expiresIn"] == 300
    assert response.headers["cache-control"] == "no-store"
    challenge = response.cookies.get("warden_challenge")
    assert challenge
    assert any(
        "warden_challenge=" in cookie and "HttpOnly" in cookie
        for cookie in response.headers.get_list("set-cookie")
    )


def test_setup_complete_claims_instance(
    unclaimed_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    begin = begin_setup(unclaimed_client, next_path="/activity")
    challenge = begin.cookies.get("warden_challenge")
    assert challenge

    seen = {}

    def verify(**kwargs):
        seen.update(kwargs)
        return fake_registration()

    monkeypatch.setattr("warden.auth.passkeys.verify_registration_response", verify)
    complete = complete_setup(unclaimed_client, challenge)
    assert complete.status_code == 200
    assert complete.json() == {"ok": True, "redirect": "/activity"}
    assert seen["expected_rp_id"] == "home.lan"
    assert seen["expected_origin"] == "http://admin.home.lan"
    assert seen["require_user_verification"] is False

    session = complete.cookies.get("warden_session")
    assert session
    set_cookies = complete.headers.get_list("set-cookie")
    assert any("warden_session=" in cookie and "HttpOnly" in cookie for cookie in set_cookies)
    assert any("warden_challenge=" in cookie and "Max-Age=0" in cookie for cookie in set_cookies)

    assert count_rows(db_path(unclaimed_client), "users") == 1
    assert count_rows(db_path(unclaimed_client), "credentials") == 1
    with sqlite3.connect(db_path(unclaimed_client)) as connection:
        user = connection.execute("SELECT username, display_name FROM users").fetchone()
        audit = [row[0] for row in connection.execute("SELECT event FROM audit")]
    assert user == ("pat", "Pat")
    assert "setup_completed" in audit

    page = unclaimed_client.get(
        "/activity",
        headers={"host": "admin.home.lan", "cookie": f"warden_session={session}"},
    )
    assert page.status_code == 200
    assert "Signed in with a passkey" not in page.text

    # The challenge is single use.
    replay = complete_setup(unclaimed_client, challenge)
    assert replay.status_code == 400

    # The instance is claimed now; setup cannot begin again.
    again = begin_setup(unclaimed_client)
    assert again.status_code == 409
    assert "already been set up" in again.json()["detail"]


def test_setup_complete_requires_challenge(unclaimed_client) -> None:
    response = complete_setup(
        unclaimed_client,
        "",
        headers={**SAME_ORIGIN},
    )
    assert response.status_code == 400
    assert "expired" in response.json()["detail"].lower()


def test_setup_expired_code(tmp_path: Path) -> None:
    path = write_config(tmp_path, config_dict(tmp_path))
    app = create_app(path)
    with TestClient(app) as client:
        settings = sqlite3.connect(db_path(client))
        try:
            settings.execute(
                "UPDATE settings SET value = ? WHERE key = ?",
                (str(time.time() - 10), SETUP_EXPIRY_KEY),
            )
            settings.commit()
        finally:
            settings.close()
        response = client.post(
            "/_warden/auth/setup/begin",
            json={"username": "pat", "setup_code": "WHATEVER-CODE-1"},
            headers=SAME_ORIGIN,
        )
        assert response.status_code == 400
        assert "expired" in response.json()["detail"]


def test_setup_origin_mismatch(unclaimed_client, monkeypatch: pytest.MonkeyPatch) -> None:
    begin = begin_setup(unclaimed_client)
    challenge = begin.cookies.get("warden_challenge")
    assert challenge
    monkeypatch.setattr(
        "warden.auth.passkeys.verify_registration_response", lambda **kwargs: fake_registration()
    )
    complete = complete_setup(
        unclaimed_client,
        challenge,
        headers={
            "host": "app.home.lan",
            "origin": "http://app.home.lan",
            "cookie": f"warden_challenge={challenge}",
        },
    )
    assert complete.status_code == 403
    assert "origin did not match" in complete.json()["detail"]
    assert count_rows(db_path(unclaimed_client), "users") == 0


def test_login_begin_lists_credentials(client) -> None:
    response = begin_login(client)
    assert response.status_code == 200
    options = response.json()["publicKey"]
    assert options["rpId"] == "home.lan"
    assert len(options["allowCredentials"]) == 2
    assert options["allowCredentials"][0] == {
        "id": b64(b"c" * 32),
        "type": "public-key",
        "transports": ["internal"],
    }
    assert {item["id"] for item in options["allowCredentials"]} == {
        b64(b"c" * 32),
        b64(b"\x01" * 32),
    }
    assert "challenge" in options
    assert response.cookies.get("warden_challenge")

    all_users = begin_login(client, username=None)
    assert all_users.status_code == 200
    assert all_users.json()["publicKey"]["allowCredentials"] == []

    unknown = begin_login(client, username="nobody")
    assert unknown.status_code == 404
    assert "No user" in unknown.json()["detail"]

    with sqlite3.connect(db_path(client)) as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM audit WHERE event='login_failed'").fetchone()[0]
            == 1
        )


def test_login_complete_creates_session(client, monkeypatch: pytest.MonkeyPatch) -> None:
    begin = begin_login(client, next_path="/config")
    challenge = begin.cookies.get("warden_challenge")
    assert challenge

    seen = {}

    def verify(**kwargs):
        seen.update(kwargs)
        return fake_authentication()

    monkeypatch.setattr("warden.auth.passkeys.verify_authentication_response", verify)
    response = complete_login(
        client,
        challenge,
        {"rawId": b64(b"c" * 32), "id": b64(b"c" * 32), "type": "public-key"},
    )
    assert response.status_code == 200
    assert response.json() == {"ok": True, "redirect": "/config"}
    session = response.cookies.get("warden_session")
    assert session
    assert seen["expected_rp_id"] == "home.lan"
    assert seen["expected_origin"] == "http://admin.home.lan"
    assert seen["credential_current_sign_count"] == 1
    assert seen["require_user_verification"] is False

    with sqlite3.connect(db_path(client)) as connection:
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 2
        assert (
            connection.execute("SELECT sign_count FROM credentials WHERE id=1").fetchone()[0] == 2
        )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM audit WHERE event='login_succeeded'"
            ).fetchone()[0]
            >= 2
        )

    authenticated = client.get(
        "/config",
        headers={"host": "admin.home.lan", "cookie": f"warden_session={session}"},
    )
    assert authenticated.status_code == 200

    # Challenge replay is rejected.
    replay = complete_login(client, challenge, {"rawId": b64(b"c" * 32)})
    assert replay.status_code == 400


def test_login_complete_unknown_and_malformed(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "warden.auth.passkeys.verify_authentication_response",
        lambda **kwargs: fake_authentication(),
    )
    begin = begin_login(client)
    challenge = begin.cookies.get("warden_challenge")
    assert challenge

    unknown = complete_login(client, challenge, {"rawId": b64(b"z" * 32)})
    assert unknown.status_code == 404
    assert "not registered" in unknown.json()["detail"]

    begin = begin_login(client)
    challenge = begin.cookies.get("warden_challenge")
    malformed = complete_login(client, challenge, {"rawId": "!!!"})
    assert malformed.status_code == 400
    assert "invalid" in malformed.json()["detail"].lower()

    no_cookie = complete_login(
        client,
        "",
        {"rawId": b64(b"c" * 32)},
        headers={**SAME_ORIGIN},
    )
    assert no_cookie.status_code == 400
    assert "expired" in no_cookie.json()["detail"].lower()


def test_login_complete_origin_mismatch(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "warden.auth.passkeys.verify_authentication_response",
        lambda **kwargs: fake_authentication(),
    )
    begin = begin_login(client)
    challenge = begin.cookies.get("warden_challenge")
    assert challenge
    response = complete_login(
        client,
        challenge,
        {"rawId": b64(b"c" * 32)},
        headers={
            "host": "app.home.lan",
            "origin": "http://app.home.lan",
            "cookie": f"warden_challenge={challenge}",
        },
    )
    assert response.status_code == 403
    assert "origin did not match" in response.json()["detail"]


def test_login_origin_and_content_type_guards(client) -> None:
    cross = client.post(
        "/_warden/auth/login/begin",
        json={"username": "pat"},
        headers={"host": "admin.home.lan", "origin": "http://evil.example"},
    )
    assert cross.status_code == 403
    assert "Cross-origin" in cross.json()["detail"]

    with sqlite3.connect(db_path(client)) as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM audit WHERE event='login_blocked'").fetchone()[0]
            == 1
        )

    plain = client.post(
        "/_warden/auth/login/begin",
        content=b"{}",
        headers={**SAME_ORIGIN, "content-type": "text/plain"},
    )
    assert plain.status_code == 415


def test_logout_revokes_session(client) -> None:
    assert count_rows(db_path(client), "sessions") == 1
    response = client.post(
        "/_warden/auth/logout",
        headers={"host": "admin.home.lan", "cookie": "warden_session=test-session-token"},
    )
    assert response.status_code == 200
    assert response.json()["redirect"] == "/_warden/login"
    assert any(
        "warden_session=" in cookie and "Max-Age=0" in cookie
        for cookie in response.headers.get_list("set-cookie")
    )
    assert count_rows(db_path(client), "sessions") == 0
    with sqlite3.connect(db_path(client)) as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM audit WHERE event='logout'").fetchone()[0] == 1
        )

    stale = client.get(
        "/",
        headers={"host": "admin.home.lan", "accept": "text/html"},
        follow_redirects=False,
    )
    assert stale.status_code == 303

    # Logging out again is harmless.
    again = client.post(
        "/_warden/auth/logout", headers={"host": "admin.home.lan"}
    )
    assert again.status_code == 200


def test_logout_blocks_cross_origin(client) -> None:
    response = client.post(
        "/_warden/auth/logout",
        headers={
            "host": "admin.home.lan",
            "origin": "http://evil.example",
            "cookie": "warden_session=test-session-token",
        },
    )
    assert response.status_code == 403
    assert count_rows(db_path(client), "sessions") == 1


def test_register_additional_passkey(client, monkeypatch: pytest.MonkeyPatch) -> None:
    headers = {
        "host": "admin.home.lan",
        "origin": "http://admin.home.lan",
        "cookie": "warden_session=test-session-token",
    }
    begin = client.post(
        "/_warden/auth/register/begin",
        json={"name": "Phone"},
        headers=headers,
    )
    assert begin.status_code == 200
    options = begin.json()["publicKey"]
    excluded = {item["id"] for item in options["excludeCredentials"]}
    assert b64(b"c" * 32) in excluded
    challenge = begin.cookies.get("warden_challenge")
    assert challenge

    monkeypatch.setattr(
        "warden.auth.passkeys.verify_registration_response",
        lambda **kwargs: fake_registration(b"p" * 32),
    )
    complete = client.post(
        "/_warden/auth/register/complete",
        json={"credential": {"id": b64(b"p" * 32), "rawId": b64(b"p" * 32)}},
        headers={
            "host": "admin.home.lan",
            "origin": "http://admin.home.lan",
            "cookie": f"warden_session=test-session-token; warden_challenge={challenge}",
        },
    )
    assert complete.status_code == 200
    assert complete.json()["redirect"] == "/passkeys?added=1"
    assert count_rows(db_path(client), "credentials") == 3
    with sqlite3.connect(db_path(client)) as connection:
        assert (
            connection.execute(
                "SELECT name FROM credentials WHERE id=3"
            ).fetchone()[0]
            == "Phone"
        )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM audit WHERE event='passkey_registered'"
            ).fetchone()[0]
            == 1
        )


def test_register_requires_session_and_rejects_duplicate(
    client, monkeypatch: pytest.MonkeyPatch
) -> None:
    anonymous = client.post(
        "/_warden/auth/register/begin",
        json={"name": "Phone"},
        headers={**SAME_ORIGIN},
    )
    assert anonymous.status_code == 401

    complete = client.post(
        "/_warden/auth/register/complete",
        json={"credential": {}},
        headers=SAME_ORIGIN,
    )
    assert complete.status_code == 401

    headers = {
        "host": "admin.home.lan",
        "origin": "http://admin.home.lan",
        "cookie": "warden_session=test-session-token",
    }
    begin = client.post(
        "/_warden/auth/register/begin", json={"name": ""}, headers=headers
    )
    assert begin.status_code == 200
    challenge = begin.cookies.get("warden_challenge")
    assert challenge

    monkeypatch.setattr(
        "warden.auth.passkeys.verify_registration_response",
        lambda **kwargs: fake_registration(b"c" * 32),
    )
    duplicate = client.post(
        "/_warden/auth/register/complete",
        json={"credential": {"rawId": b64(b"c" * 32)}},
        headers={
            "host": "admin.home.lan",
            "origin": "http://admin.home.lan",
            "cookie": f"warden_session=test-session-token; warden_challenge={challenge}",
        },
    )
    assert duplicate.status_code == 409
    assert "already registered" in duplicate.json()["detail"]
    assert count_rows(db_path(client), "credentials") == 2


def test_auth_pages_and_health(unclaimed_client) -> None:
    health = unclaimed_client.get("/_warden/health", headers=ADMIN)
    assert health.status_code == 200
    assert health.json()["setup_required"] is True

    login = unclaimed_client.get("/_warden/login", headers=ADMIN)
    assert login.status_code == 200
    assert "setup" in login.text.lower()

    setup = unclaimed_client.get("/_warden/setup", headers=ADMIN)
    assert setup.status_code == 200
    assert setup.headers["cache-control"] == "no-store"
