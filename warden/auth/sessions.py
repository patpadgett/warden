"""Native passkey sessions and cookie helpers."""

from __future__ import annotations

import hashlib
import secrets
import time
from collections.abc import MutableMapping
from typing import Any

from starlette.responses import Response

from warden.config import WardenConfig
from warden.db import Database, Session, User
from warden.utils import (
    CHALLENGE_COOKIE,
    client_ip,
    cookie_domain,
    get_cookie,
    is_secure_request,
    session_cookie_name,
    user_agent,
)

CHALLENGE_PATH = "/_warden"


def hash_token(token: str) -> str:
    """Compute a SHA‑256 hash of an authentication token.

    Used for storing token hashes in the session table.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_token() -> str:
    """Generate a new, URL‑safe session token.

    Returns a 32‑byte random token encoded with ``secrets.token_urlsafe``.
    """
    return secrets.token_urlsafe(32)


async def create_session(
    db: Database, user: User, scope: MutableMapping[str, Any], config: WardenConfig
) -> tuple[str, Session]:
    """Create a new session for ``user``.

    * Generates a token via :func:`new_token`.
    * Stores a hashed version of the token in the ``sessions`` table.
    * Sets the expiry based on ``config.server.session_ttl_hours``.
    * Returns the raw token and the created ``Session`` object.
    """
    token = new_token()
    expires_at = time.time() + config.server.session_ttl_hours * 3600
    await db.create_session(
        hash_token(token),
        user.id,
        expires_at,
        ip=client_ip(scope),
        user_agent=user_agent(scope),
    )
    session = await db.get_session(hash_token(token))
    if session is None:
        raise RuntimeError("Session was not persisted")
    return token, session


async def authenticate_scope(
    scope: MutableMapping[str, Any], db: Database
) -> Session | None:
    """Authenticate a request using the ``warden_session`` cookie.

    * Retrieves the session token from cookies.
    * Looks up the session by its hash and returns the ``Session`` object if valid,
      otherwise ``None``.
    """
    token = get_cookie(scope, session_cookie_name(db.config, scope))
    if not token:
        return None
    return await db.get_session(hash_token(token))


async def authenticate_request(request: Any, db: Database) -> Session | None:
    """Convenient wrapper to authenticate a Starlette ``Request``.

    Extracts the ASGI scope from the request and delegates to ``authenticate_scope``.
    """
    return await authenticate_scope(request.scope, db)


def set_session_cookie(
    response: Response,
    token: str,
    scope: MutableMapping[str, Any],
    config: WardenConfig,
) -> None:
    """Set a session cookie on the outgoing response.

    * Uses ``SESSION_COOKIE`` name.
    * Sets ``max_age`` based on the configured session TTL.
    * Applies appropriate security flags (secure, HttpOnly, SameSite).
    """
    cookie_name = session_cookie_name(config, scope)
    response.set_cookie(
        cookie_name,
        token,
        max_age=config.server.session_ttl_hours * 3600,
        path="/",
        domain=cookie_domain(config),
        secure=is_secure_request(scope, config),
        httponly=True,
        samesite="lax",
    )


def clear_session_cookie(
    response: Response, scope: MutableMapping[str, Any], config: WardenConfig
) -> None:
    """Delete the session cookie from the response.

    Mirrors the settings used in :func:`set_session_cookie`.
    """
    cookie_name = session_cookie_name(config, scope)
    response.delete_cookie(
        cookie_name,
        path="/",
        domain=cookie_domain(config),
        secure=is_secure_request(scope, config),
        httponly=True,
        samesite="lax",
    )


def set_challenge_cookie(
    response: Response,
    challenge_id: str,
    scope: MutableMapping[str, Any],
    config: WardenConfig,
    ttl_seconds: int,
) -> None:
    """Set a short‑lived challenge cookie.

    Used for storing the WebAuthn challenge ID during the registration/login
    flow. The cookie expires after ``ttl_seconds``.
    """
    response.set_cookie(
        CHALLENGE_COOKIE,
        challenge_id,
        max_age=ttl_seconds,
        path=CHALLENGE_PATH,
        secure=is_secure_request(scope, config),
        httponly=True,
        samesite="lax",
    )


def clear_challenge_cookie(
    response: Response, scope: MutableMapping[str, Any], config: WardenConfig
) -> None:
    """Delete the WebAuthn challenge cookie.

    Mirrors the settings used by :func:`set_challenge_cookie`.
    """
    response.delete_cookie(
        CHALLENGE_COOKIE,
        path=CHALLENGE_PATH,
        secure=is_secure_request(scope, config),
        httponly=True,
        samesite="lax",
    )


def challenge_from_scope(scope: MutableMapping[str, Any]) -> str | None:
    """Retrieve the ``warden_challenge`` cookie value from an ASGI scope.

    Returns ``None`` if the cookie is not present.
    """
    return get_cookie(scope, CHALLENGE_COOKIE)
