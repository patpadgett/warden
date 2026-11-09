"""WebAuthn ceremony orchestration on top of the ``webauthn`` library."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import bytes_to_base64url, options_to_json
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    AuthenticatorTransport,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from warden.config import WardenConfig
from warden.db import AlreadyExistsError, Credential, Database, User

logger = logging.getLogger("warden.auth")

USERNAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{1,31}$")
SETUP_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
SETUP_TTL_SECONDS = 24 * 3600
SETUP_HASH_KEY = "setup_code_hash"
SETUP_EXPIRY_KEY = "setup_code_expires_at"
_SETUP_TOKEN_RE = re.compile(r"[^A-Z0-9]")

DEFAULT_SETUP_HELP = (
    "The one-time setup code is printed in the Warden startup logs. "
    "Set WARDEN_SETUP_TOKEN to choose your own."
)


class AuthError(Exception):
    def __init__(self, message: str, status_code: int = 400, *, event: str | None = None) -> None:
        self.message = message
        self.status_code = status_code
        self.event = event
        super().__init__(message)


@dataclass(slots=True)
class Ceremony:
    options: dict[str, Any]
    challenge_id: str
    expires_in: int


def normalize_username(value: str) -> str:
    """Validate and normalise a username.

    * Strips surrounding whitespace.
    * Ensures the username matches ``USERNAME_RE`` (2‑32 alphanumeric characters, allowing ``._-``).
    * Raises ``AuthError`` if the validation fails.
    """
    value = value.strip()
    if not USERNAME_RE.match(value):
        raise AuthError(
            "Username must be 2–32 characters, start with a letter or number, and use "
            "only letters, numbers, dots, dashes, or underscores."
        )
    return value


def normalize_display_name(value: str | None, fallback: str) -> str:
    """Normalise a user‑display name.

    * Uses ``fallback`` if ``value`` is ``None`` or empty after stripping.
    * Enforces a maximum length of 80 characters, raising ``AuthError`` on overflow.
    """
    value = (value or "").strip() or fallback
    if len(value) > 80:
        raise AuthError("Display name must be 80 characters or fewer.")
    return value


def normalize_setup_code(value: str) -> str:
    """Normalise a setup code.

    * Upper‑cases the input and removes any characters not allowed by ``_SETUP_TOKEN_RE``.
    * Returns the cleaned token string (may be shorter than the original).
    """
    return _SETUP_TOKEN_RE.sub("", (value or "").upper())


def hash_setup_code(value: str) -> str:
    """Return a SHA‑256 hash of a normalised setup code.

    Used to store a non‑reversible representation of the setup token in the database.
    """
    return hashlib.sha256(normalize_setup_code(value).encode("utf-8")).hexdigest()


def hash_backup_code(value: str) -> str:
    """Return a SHA‑256 hash of a backup recovery code.

    Used to store a non‑reversible representation of the backup code in the database.
    """
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def generate_setup_code() -> str:
    """Generate a random 12‑character setup code.

    Returns a hyphen‑separated string like ``ABCD-EFGH-IJKL`` consisting of characters from
    ``SETUP_CODE_ALPHABET``. The code is suitable for one‑time admin setup.
    """
    raw = "".join(secrets.choice(SETUP_CODE_ALPHABET) for _ in range(12))
    return "-".join(raw[i : i + 4] for i in range(0, 12, 4))


def _base64url_decode(value: str) -> bytes:
    """Decode a base64url‑encoded string, adding padding as needed.

    ``value`` may omit the ``=`` padding; this function pads it to a multiple of
    four characters before decoding.
    """
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _descriptor(credential: Credential) -> PublicKeyCredentialDescriptor:
    """Convert a stored ``Credential`` into a ``PublicKeyCredentialDescriptor``.

    The descriptor includes the credential ID and a cleaned list of ``AuthenticatorTransport``
    values, filtering out any invalid entries.
    """
    transports: list[AuthenticatorTransport] = []
    for item in credential.transports:
        try:
            transports.append(AuthenticatorTransport(item))
        except ValueError:
            continue
    return PublicKeyCredentialDescriptor(id=credential.credential_id, transports=transports)


def _user_verification(config: WardenConfig) -> UserVerificationRequirement:
    """Determine the required user‑verification level for WebAuthn.

    Returns ``REQUIRED`` if ``config.webauthn.require_user_verification`` is true,
    otherwise ``PREFERRED``.
    """
    if config.webauthn.require_user_verification:
        return UserVerificationRequirement.REQUIRED
    return UserVerificationRequirement.PREFERRED


class PasskeyService:
    def __init__(self, db: Database) -> None:
        self.db = db

    # ------------------------------------------------------------- setup codes
    async def user_count(self) -> int:
        return await self.db.user_count()

    async def generate_backup_codes(self, user_id: int) -> list[str]:
        """Generate and store a new set of recovery codes for a user."""
        await self.db.clear_backup_codes(user_id)
        codes = []
        for _ in range(10):
            code = secrets.token_hex(8)  # 16 chars
            await self.db.add_backup_code(user_id, hash_backup_code(code))
            codes.append(code)
        return codes

    async def prepare_setup_code(self, env_token: str | None = None) -> tuple[str | None, float | None]:
        """Generate (or install) a first-run code. Returns the plaintext once."""
        if await self.db.user_count() > 0:
            await self.db.delete_setting(SETUP_HASH_KEY)
            await self.db.delete_setting(SETUP_EXPIRY_KEY)
            return None, None
        code = normalize_setup_code(env_token) if env_token else generate_setup_code()
        if len(code) < 12:
            if env_token:
                logger.warning("WARDEN_SETUP_TOKEN is too short; generating a random setup code instead.")
            code = generate_setup_code()
            env_token = None
        expires = time.time() + SETUP_TTL_SECONDS
        await self.db.set_setting(SETUP_HASH_KEY, hash_setup_code(code))
        await self.db.set_setting(SETUP_EXPIRY_KEY, str(expires))
        if env_token:
            return None, expires
        return code, expires

    async def setup_status(self) -> dict[str, Any]:
        required = (await self.db.user_count()) == 0
        expires_raw = await self.db.get_setting(SETUP_EXPIRY_KEY)
        expires = float(expires_raw) if expires_raw else None
        if required and (expires is None or expires <= time.time()):
            required = True
        return {
            "required": required,
            "expired": required and (expires is None or expires <= time.time()),
            "expires_at": expires,
            "has_code": bool(await self.db.get_setting(SETUP_HASH_KEY)),
        }

    async def _validate_setup_code(self, code: str) -> None:
        if await self.db.user_count() > 0:
            raise AuthError("This Warden instance has already been set up.", 409)
        stored = await self.db.get_setting(SETUP_HASH_KEY)
        expiry_raw = await self.db.get_setting(SETUP_EXPIRY_KEY)
        if not stored or not expiry_raw:
            raise AuthError(
                "No setup code is active. Restart Warden to generate a new one.", 400
            )
        try:
            expired = float(expiry_raw) <= time.time()
        except ValueError:
            expired = True
        if expired:
            raise AuthError("That setup code has expired. Restart Warden for a new one.", 400)
        provided = hash_setup_code(code)
        if not hmac.compare_digest(stored, provided):
            raise AuthError("That setup code isn't right.", 400, event="setup_bad_code")

    # ------------------------------------------------------------- ceremonies
    def _new_challenge_id(self) -> str:
        """Generate a secure random challenge identifier.

        Uses ``secrets.token_urlsafe`` to create a 32‑byte URL‑safe string.
        """
        return secrets.token_urlsafe(32)

    async def begin_setup(
        self,
        *,
        username: str,
        display_name: str | None,
        setup_code: str,
        origin: str,
        config: WardenConfig,
        next_path: str = "/",
    ) -> Ceremony:
        """Start the initial admin setup flow.

        * Normalises ``username`` and ``display_name``.
        * Validates the one‑time ``setup_code``.
        * Generates a new registration challenge using ``webauthn`` helpers.
        * Stores the challenge in the DB with a TTL based on ``config.webauthn``.
        * Returns a ``Ceremony`` containing the public‑key options, a challenge ID,
          and the expiration time in seconds.
        """
        username = normalize_username(username)
        display = normalize_display_name(display_name, username)
        await self._validate_setup_code(setup_code)
        if await self.db.get_user_by_username(username):
            raise AuthError("That username is already taken.")
        user_handle = secrets.token_bytes(16)
        options = generate_registration_options(
            rp_id=config.webauthn.rp_id,
            rp_name=config.webauthn.rp_name,
            user_name=username,
            user_id=user_handle,
            user_display_name=display,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=_user_verification(config),
            ),
            attestation=AttestationConveyancePreference.NONE,
            timeout=min(config.webauthn.challenge_ttl_seconds, 600) * 1000,
        )
        challenge = _base64url_decode(json.loads(options_to_json(options))["challenge"])
        challenge_id = self._new_challenge_id()
        await self.db.create_challenge(
            challenge_id,
            "register",
            {
                "flow": "setup",
                "username": username,
                "display_name": display,
                "user_handle": bytes_to_base64url(user_handle),
                "origin": origin,
                "next": next_path,
                "challenge": bytes_to_base64url(challenge),
                "challenge_id": challenge_id,
            },
            config.webauthn.challenge_ttl_seconds,
        )
        return Ceremony(
            options=json.loads(options_to_json(options)),
            challenge_id=challenge_id,
            expires_in=config.webauthn.challenge_ttl_seconds,
        )

    async def begin_add_passkey(
        self,
        *,
        user: User,
        name: str | None,
        origin: str,
        config: WardenConfig,
        flow: str = "add",
    ) -> Ceremony:
        credentials = await self.db.list_credentials(user.id)
        count = len(credentials) + 1
        passkey_name = (name or "").strip()[:60] or f"Passkey {count}"
        options = generate_registration_options(
            rp_id=config.webauthn.rp_id,
            rp_name=config.webauthn.rp_name,
            user_name=user.username,
            user_id=user.webauthn_user_id,
            user_display_name=user.display_name,
            exclude_credentials=[_descriptor(credential) for credential in credentials],
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=_user_verification(config),
            ),
            attestation=AttestationConveyancePreference.NONE,
            timeout=min(config.webauthn.challenge_ttl_seconds, 600) * 1000,
        )
        challenge = _base64url_decode(json.loads(options_to_json(options))["challenge"])
        challenge_id = self._new_challenge_id()
        await self.db.create_challenge(
            challenge_id,
            "register",
            {
                "flow": flow,
                "user_id": user.id,
                "name": passkey_name,
                "origin": origin,
                "challenge": bytes_to_base64url(challenge),
                "challenge_id": challenge_id,
            },
            config.webauthn.challenge_ttl_seconds,
        )
        return Ceremony(
            options=json.loads(options_to_json(options)),
            challenge_id=challenge_id,
            expires_in=config.webauthn.challenge_ttl_seconds,
        )

    async def complete_registration(
        self,
        *,
        credential: dict[str, Any],
        challenge_id: str,
        origin: str | None,
        config: WardenConfig,
        session_user: User | None,
    ) -> dict[str, Any]:
        challenge = await self.db.consume_challenge(challenge_id, "register")
        if challenge is None:
            raise AuthError("That registration attempt expired. Please start again.", 400)
        payload = challenge.payload
        expected_origin = str(payload.get("origin") or origin or "")
        if origin and origin.rstrip("/") != expected_origin.rstrip("/"):
            raise AuthError("The registration origin did not match. Please try again.", 403)
        challenge_bytes = _base64url_decode(payload["challenge"])
        try:
            verification = verify_registration_response(
                credential=credential,
                expected_challenge=challenge_bytes,
                expected_rp_id=config.webauthn.rp_id,
                expected_origin=expected_origin,
                require_user_verification=config.webauthn.require_user_verification,
            )
        except WebAuthnException as exc:
            logger.info("Registration verification failed: %s", exc)
            raise AuthError("The passkey could not be verified. Please try again.", 400) from exc
        except Exception as exc:  # malformed client payloads
            logger.info("Registration payload failed: %s", exc)
            raise AuthError("The passkey response was invalid. Please try again.", 400) from exc

        transports_raw = (credential.get("response") or {}).get("transports") or []
        transports = [str(item) for item in transports_raw if isinstance(item, str)][:8]
        flow = payload.get("flow")

        if flow == "setup":
            if session_user is not None:
                raise AuthError("This instance is already set up.", 409)
            handle = _base64url_decode(str(payload["user_handle"]))
            try:
                user, saved = await self.db.create_user_with_credential(
                    username=str(payload["username"]),
                    display_name=str(payload["display_name"]),
                    webauthn_user_id=handle,
                    credential_id=verification.credential_id,
                    public_key=verification.credential_public_key,
                    sign_count=verification.sign_count,
                    transports=transports,
                    credential_name="First passkey",
                    aaguid=str(verification.aaguid),
                    fmt=str(verification.fmt.value if hasattr(verification.fmt, "value") else verification.fmt),
                    user_verified=verification.user_verified,
                    backup_eligible=verification.credential_backed_up,
                    backup_state=verification.credential_backed_up,
                    setup_mode=True,
                )
            except AlreadyExistsError as exc:
                raise AuthError("This Warden instance has already been set up.", 409) from exc
            return {
                "flow": "setup",
                "user": user,
                "credential": saved,
                "next": safe_redirect(payload.get("next"), "/"),
            }

        if flow == "add":
            if session_user is None:
                raise AuthError("Sign in before adding a passkey.", 401)
            if int(payload.get("user_id", -1)) != session_user.id:
                raise AuthError("This registration belongs to a different session.", 403)
            user = await self.db.get_user(session_user.id)
            if user is None:
                raise AuthError("Your account no longer exists.", 401)
            if await self.db.get_credential_by_id(verification.credential_id):
                raise AuthError("That passkey is already registered.", 409)
            saved = await self.db.add_credential(
                user_id=user.id,
                credential_id=verification.credential_id,
                public_key=verification.credential_public_key,
                sign_count=verification.sign_count,
                transports=transports,
                name=str(payload.get("name") or "Passkey"),
                aaguid=str(verification.aaguid),
                fmt=str(verification.fmt.value if hasattr(verification.fmt, "value") else verification.fmt),
                user_verified=verification.user_verified,
                backup_eligible=verification.credential_backed_up,
                backup_state=verification.credential_backed_up,
            )
            return {"flow": "add", "user": user, "credential": saved, "next": "/passkeys"}

        raise AuthError("Unknown registration flow.", 400)

    async def begin_login(
        self,
        *,
        username: str | None,
        origin: str,
        config: WardenConfig,
        next_path: str = "/",
    ) -> Ceremony:
        """Start a login ceremony for a (optional) username.

        * If ``username`` is provided, looks up the user and restricts the credential
          list to the user's registered passkeys.
        * Generates a WebAuthn authentication challenge.
        * Stores the challenge in the DB and returns a ``Ceremony`` with the public
          key options.
        """
        allow_credentials = None
        selected_user: User | None = None
        if username and username.strip():
            selected_user = await self.db.get_user_by_username(username.strip())
            if selected_user is None:
                raise AuthError("No user with that username was found.", 404)
            credentials = await self.db.list_credentials(selected_user.id)
            if not credentials:
                raise AuthError("That account has no passkeys registered.", 404)
            allow_credentials = [_descriptor(credential) for credential in credentials]
        options = generate_authentication_options(
            rp_id=config.webauthn.rp_id,
            allow_credentials=allow_credentials,
            user_verification=_user_verification(config),
            timeout=min(config.webauthn.challenge_ttl_seconds, 600) * 1000,
        )
        serialized = json.loads(options_to_json(options))
        challenge = _base64url_decode(serialized["challenge"])
        challenge_id = self._new_challenge_id()
        await self.db.create_challenge(
            challenge_id,
            "authenticate",
            {
                "origin": origin,
                "next": next_path,
                "user_id": selected_user.id if selected_user else None,
                "challenge": bytes_to_base64url(challenge),
                "challenge_id": challenge_id,
            },
            config.webauthn.challenge_ttl_seconds,
        )
        return Ceremony(
            options=serialized,
            challenge_id=challenge_id,
            expires_in=config.webauthn.challenge_ttl_seconds,
        )

    async def complete_login(
        self,
        *,
        credential: dict[str, Any],
        challenge_id: str,
        origin: str | None,
        config: WardenConfig,
    ) -> tuple[User, str]:
        """Complete a login ceremony using a WebAuthn credential.

        * Consumes a pending authentication challenge.
        * Validates the credential against the stored public key and sign count.
        * Checks origin matching and prevents replay attacks via signature‑counter checks.
        * Returns the authenticated ``User`` and a safe redirect target.
        """
        challenge = await self.db.consume_challenge(challenge_id, "authenticate")
        if challenge is None:
            raise AuthError("That sign-in attempt expired. Please try again.", 400)
        payload = challenge.payload
        expected_origin = str(payload.get("origin") or origin or "")
        if origin and origin.rstrip("/") != expected_origin.rstrip("/"):
            raise AuthError("The sign-in origin did not match. Please try again.", 403)
        try:
            raw_id = _base64url_decode(str(credential.get("rawId", "")))
        except Exception as exc:
            raise AuthError("The passkey response was invalid. Please try again.", 400) from exc
        if not raw_id:
            raise AuthError("The passkey response was invalid. Please try again.", 400)
        stored = await self.db.get_credential_by_id(raw_id)
        if stored is None:
            raise AuthError("That passkey is not registered with Warden.", 404)
        selected_user_id = payload.get("user_id")
        if selected_user_id is not None and stored.user_id != int(selected_user_id):
            raise AuthError("That passkey belongs to a different account.", 403)
        user = await self.db.get_user(stored.user_id)
        if user is None:
            raise AuthError("Your account no longer exists.", 401)
        try:
            verification = verify_authentication_response(
                credential=credential,
                expected_challenge=_base64url_decode(payload["challenge"]),
                expected_rp_id=config.webauthn.rp_id,
                expected_origin=expected_origin,
                credential_public_key=stored.public_key,
                credential_current_sign_count=stored.sign_count,
                require_user_verification=config.webauthn.require_user_verification,
            )
        except WebAuthnException as exc:
            logger.info("Authentication verification failed: %s", exc)
            raise AuthError("That passkey could not be verified. Please try again.", 401) from exc
        except Exception as exc:
            logger.info("Authentication payload failed: %s", exc)
            raise AuthError("The passkey response was invalid. Please try again.", 400) from exc
        if verification.credential_id != stored.credential_id:
            raise AuthError("The passkey response did not match. Please try again.", 401)
        if (
            verification.new_sign_count
            and stored.sign_count
            and verification.new_sign_count <= stored.sign_count
            and not stored.backup_state
        ):
            raise AuthError(
                "This passkey's signature counter went backwards. It may be cloned.", 401
            )
        await self.db.update_credential_use(stored.id, verification.new_sign_count)
        return user, safe_redirect(payload.get("next"), "/")

    async def setup_code_help(self) -> str:
        return DEFAULT_SETUP_HELP


    async def begin_invite_registration(
        self,
        *,
        user: User,
        name: str | None,
        origin: str,
        config: WardenConfig,
        invite_token: str | None = None,
    ) -> Ceremony:
        credentials = await self.db.list_credentials(user.id)
        count = len(credentials) + 1
        passkey_name = (name or "").strip()[:60] or f"Passkey {count}"
        options = generate_registration_options(
            rp_id=config.webauthn.rp_id,
            rp_name=config.webauthn.rp_name,
            user_name=user.username,
            user_id=user.webauthn_user_id,
            user_display_name=user.display_name,
            exclude_credentials=[_descriptor(credential) for credential in credentials],
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=_user_verification(config),
            ),
            attestation=AttestationConveyancePreference.NONE,
            timeout=min(config.webauthn.challenge_ttl_seconds, 600) * 1000,
        )
        challenge = _base64url_decode(json.loads(options_to_json(options))["challenge"])
        challenge_id = self._new_challenge_id()
        await self.db.create_challenge(
            challenge_id,
            "register",
            {
                "flow": "invite",
                "user_id": user.id,
                "name": passkey_name,
                "origin": origin,
                "invite_token_hash": hashlib.sha256(invite_token.encode("utf-8")).hexdigest() if invite_token else None,
                "challenge": bytes_to_base64url(challenge),
                "challenge_id": challenge_id,
            },
            config.webauthn.challenge_ttl_seconds,
        )
        return Ceremony(
            options=json.loads(options_to_json(options)),
            challenge_id=challenge_id,
            expires_in=config.webauthn.challenge_ttl_seconds,
        )

    async def complete_invite_registration(
        self,
        *,
        credential: dict[str, Any],
        challenge_id: str,
        origin: str | None,
        config: WardenConfig,
        invite_token: str,
    ) -> dict[str, Any]:
        if not isinstance(invite_token, str) or not invite_token.strip():
            raise AuthError("Missing invite token.", 400)
        invite_token = invite_token.strip()
        invite_token_hash = hashlib.sha256(invite_token.encode("utf-8")).hexdigest()
        invite = await self.db.get_invite(invite_token)
        if invite is None or int(invite["used"]) == 1:
            raise AuthError("That invite is invalid or has already been used.", 400, event="invite_invalid")
        if float(invite["expires_at"]) < time.time():
            raise AuthError("That invite has expired.", 400, event="invite_expired")
        user = await self.db.get_user(invite["user_id"])
        if user is None:
            raise AuthError("That invite no longer matches an account.")

        # Consume the challenge and bind the invite token to it so the token
        # cannot be replayed against a different ceremony.
        challenge = await self.db.consume_challenge(challenge_id, "register")
        if challenge is None:
            raise AuthError("That registration attempt expired. Please start again.", 400)
        payload = challenge.payload
        expected_origin = str(payload.get("origin") or origin or "")
        if origin and origin.rstrip("/") != expected_origin.rstrip("/"):
            raise AuthError("The registration origin did not match. Please try again.", 403)
        if payload.get("invite_token_hash") != invite_token_hash:
            raise AuthError("This registration does not match the supplied invite.", 400)
        if int(payload.get("user_id", -1)) != user.id:
            raise AuthError("This registration belongs to a different account.", 403)

        challenge_bytes = _base64url_decode(payload["challenge"])
        try:
            verification = verify_registration_response(
                credential=credential,
                expected_challenge=challenge_bytes,
                expected_rp_id=config.webauthn.rp_id,
                expected_origin=expected_origin,
                require_user_verification=config.webauthn.require_user_verification,
            )
        except WebAuthnException as exc:
            logger.info("Registration verification failed: %s", exc)
            raise AuthError("The passkey could not be verified. Please try again.", 400) from exc
        except Exception as exc:  # malformed client payloads
            logger.info("Registration payload failed: %s", exc)
            raise AuthError("The passkey response was invalid. Please try again.", 400) from exc

        transports_raw = (credential.get("response") or {}).get("transports") or []
        transports = [str(item) for item in transports_raw if isinstance(item, str)][:8]

        saved = await self.db.add_credential(
            user_id=user.id,
            credential_id=verification.credential_id,
            public_key=verification.credential_public_key,
            sign_count=verification.sign_count,
            transports=transports,
            name=str(payload.get("name") or "Passkey"),
            aaguid=str(verification.aaguid),
            fmt=str(verification.fmt.value if hasattr(verification.fmt, "value") else verification.fmt),
            user_verified=verification.user_verified,
            backup_eligible=verification.credential_backed_up,
            backup_state=verification.credential_backed_up,
        )
        await self.db.mark_invite_used(int(invite["id"]))
        return {"flow": "invite", "user": user, "credential": saved}



def safe_redirect(value: Any, fallback: str) -> str:
    """Return a safe redirect target.

    * Only allows absolute paths (no scheme or host).
    * Rejects paths containing backslashes, NUL bytes, excessively long URLs, or ``..`` traversal.
    * Returns ``fallback`` for any unsafe value.
    """
    if not isinstance(value, str):
        return fallback
    if not value.startswith("/") or value.startswith("//"):
        return fallback
    if "\\" in value or "\x00" in value or len(value) > 2048:
        return fallback
    # Reject path traversal components
    if any(part == ".." for part in value.split("/")):
        return fallback
    return value
