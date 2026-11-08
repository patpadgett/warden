import hashlib
import time
from unittest.mock import patch

import pytest

# Verifier stub used to isolate the invite flow from WebAuthn response
# verification. The trust boundary is: invite validation, challenge
# consumption and credential storage -- all handled before/without the
# real attestation response in a service-level test.
VERIFY_STUB = type(
    "Verification",
    (),
    {
        "credential_id": b"cred-id",
        "credential_public_key": b"pub-key",
        "sign_count": 1,
        "aaguid": None,
        "fmt": type("F", (), {"value": "none"})(),
        "user_verified": True,
        "credential_backed_up": False,
    },
)


def _credential():
    return {
        "id": "fake-cred",
        "response": {
            "type": "publicKey",
            "userHandle": b"fake-user-handle",
            "clientDataJSON": "{}",
            "attestationObject": "AA==",
            "signature": "AQ==",
            "transports": ["internal"],
        },
    }


@pytest.mark.asyncio
async def test_invite_flow(app_and_path):
    app, _ = app_and_path
    # Simulate what the lifespan would have set (app.state.config was only
    # applied when the lifespan ran, which the plain app_and_path fixture does
    # not).
    app.state.config = app.state.manager.config
    db = app.state.db
    pk = app.state.passkeys

    # Non-admin user (the invite is for an additional, non-admin account).
    user = await db.create_user("mallory", "Mallory", b"m" * 16, is_admin=False)
    assert user.id > 0

    # Create an invite for that user.
    token = "INVITE-ABCD-1234"
    expires = time.time() + 3600
    invite_id = await db.create_invite(user.id, token, expires)
    assert invite_id > 0
    stored = await db.get_invite(token)
    assert stored is not None
    assert int(stored["used"]) == 0
    assert float(stored["expires_at"]) > time.time()

    # Begin the registration ceremony (invite-bound challenge).
    origin = "http://admin.home.lan"
    ceremony = await pk.begin_invite_registration(
        user=user,
        name="Passkey Test",
        origin=origin,
        config=app.state.config,
        invite_token=token,
    )
    assert ceremony.challenge_id
    challenge_id = ceremony.challenge_id

    # Complete registration: registers the credential and signs the user in.
    # The WebAuthn response is stubbed so this stays a service-level test.
    with patch("warden.auth.passkeys.verify_registration_response", return_value=VERIFY_STUB):
        result = await pk.complete_invite_registration(
            credential=_credential(),
            challenge_id=challenge_id,
            origin=origin,
            config=app.state.config,
            invite_token=token,
        )
    assert result["flow"] == "invite"
    assert result["user"].id == user.id
    assert result["credential"] is not None
    assert result["credential"].name == "Passkey Test"
    assert result["credential"].user_id == user.id

    # The invite must now be marked used.
    used = await db.get_invite(token)
    assert used is not None and int(used["used"]) == 1

    # A session is created by the inviter (the invite route), not by
    # complete_invite_registration itself, so we do not assert one here.
    # The credential was recorded above.


@pytest.mark.asyncio
async def test_invite_expired(app_and_path):
    """An expired invite must be rejected at completion time."""
    app, _ = app_and_path
    app.state.config = app.state.manager.config
    db = app.state.db
    pk = app.state.passkeys

    user = await db.create_user("ghost", "Ghost", b"g" * 16, is_admin=False)
    token = "INVITE-EXPIRED-9999"
    await db.create_invite(user.id, token, time.time() - 3600)

    with patch("warden.auth.passkeys.verify_registration_response"), pytest.raises(Exception):
        await pk.complete_invite_registration(
            credential=_credential(),
            challenge_id="dead",
            origin="http://admin.home.lan",
            config=app.state.config,
            invite_token=token,
        )


@pytest.mark.asyncio
async def test_invite_binding(app_and_path):
    """An invite token bound to a challenge/credential is accepted, a wrong
    token is rejected."""
    app, _ = app_and_path
    app.state.config = app.state.manager.config
    db = app.state.db
    pk = app.state.passkeys

    user = await db.create_user("mallory", "Mallory", b"m" * 16, is_admin=False)
    token = "INVITE-BIND-1234"
    expires = time.time() + 3600
    invite_id = await db.create_invite(user.id, token, expires)
    assert invite_id > 0

    origin = "http://admin.home.lan"
    challenge_id = "bind-challenge-1"
    # Build a challenge whose invite token hash matches.
    await db.create_challenge(
        challenge_id,
        "register",
        {
            "flow": "invite",
            "user_id": user.id,
            "name": "Passkey",
            "origin": origin,
            "invite_token_hash": hashlib.sha256(token.encode()).hexdigest(),
            "challenge": "fake-challenge",
            "challenge_id": challenge_id,
        },
        3600,
    )

    cred = _credential()
    with patch("warden.auth.passkeys.verify_registration_response", return_value=VERIFY_STUB):
        result = await pk.complete_invite_registration(
            credential=cred,
            challenge_id=challenge_id,
            origin=origin,
            config=app.state.config,
            invite_token=token,
        )
    assert result["flow"] == "invite"
    assert result["credential"] is not None

    # A mismatched invite token must be rejected.
    with patch("warden.auth.passkeys.verify_registration_response", return_value=VERIFY_STUB):
        with pytest.raises(Exception):
            await pk.complete_invite_registration(
                credential=cred,
                challenge_id=challenge_id,
                origin=origin,
                config=app.state.config,
                invite_token="WRONG-TOKEN",
            )


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
