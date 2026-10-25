"""Login, setup, registration, and logout routes with enhanced CSRF protection and documentation."""

from __future__ import annotations

import logging
import time
from typing import Any
from functools import wraps
from uuid import uuid4

from fastapi import APIRouter, Request
from pydantic import BaseModel, ValidationError
from starlette.responses import JSONResponse, Response

from warden import __version__
from warden.auth.passkeys import AuthError, PasskeyService, normalize_username
from warden.auth.sessions import (
    authenticate_scope,
    challenge_from_scope,
    clear_challenge_cookie,
    clear_session_cookie,
    create_session,
    set_challenge_cookie,
    set_session_cookie,
)
from warden.config import WardenConfig
from warden.templating import templates
from warden.utils import (
    INTERNAL_PREFIX,
    add_page_headers,
    admin_url,
    check_origin,
    client_ip,
    current_origin,
    get_host,
    json_error,
    login_url,
    redirect,
    safe_next,
    user_agent,
)
from fastapi import HTTPException
from warden.db import Session, User, AlreadyExistsError
from warden.admin.routes import _guard_host

logger = logging.getLogger("warden.auth")
router = APIRouter()

# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class SetupBeginBody(BaseModel):
    username: str
    display_name: str | None = None
    setup_code: str
    next: str | None = None

class LoginBeginBody(BaseModel):
    username: str | None = None
    next: str | None = None

class RegisterBeginBody(BaseModel):
    name: str | None = None

class BackupCodeBody(BaseModel):
    code: str

class OTPSetupPayload(BaseModel):
    """Placeholder model for OTP setup payload.

    Currently not used – the OTP setup endpoint does not require additional
    request data beyond the CSRF protection and authentication handled by the
    surrounding view. This class exists to keep the OpenAPI schema stable.
    """

# ---------------------------------------------------------------------------
# CSRF protection decorator (used for state‑changing admin endpoints)
# ---------------------------------------------------------------------------

def csrf_protected(func):
    """Enforce same‑origin and ``X-Warden-Request: 1`` header.

    Returns a ``JSONResponse`` with a 403 status if the request fails.
    """

    @wraps(func)
    async def wrapper(request: Request, *args, **kwargs):
        if not _origin_ok(request):
            return _error("Cross-origin request blocked.", 403)
        if request.headers.get("x-warden-request") != "1":
            return _error("Missing X-Warden-Request header.", 403)
        return await func(request, *args, **kwargs)

    return wrapper

# ---------------------------------------------------------------------------
# Internal helpers – documented for clarity
# ---------------------------------------------------------------------------

def _config(request: Request) -> WardenConfig:
    """Retrieve the active Warden configuration from the app state."""
    return request.app.state.manager.config

def _session(request: Request) -> Session:
    """Return the authenticated session or raise ``401``.

    The middleware stores the session on ``request.state.session``.
    """
    session = getattr(request.state, "session", None)
    if session is None:
        raise HTTPException(401, "Sign in to continue.")
    return session

def _user(request: Request) -> User:
    """Convenient shortcut to the logged‑in ``User``.

    Relies on ``_session`` above.
    """
    return _session(request).user

class CredentialBody(BaseModel):
    credential: dict[str, Any]

def _db(request: Request):
    """Shortcut to the SQLite ``Database`` instance attached to the app."""
    return request.app.state.db

def _passkeys(request: Request) -> PasskeyService:
    return request.app.state.passkeys

def _json_response(payload: dict[str, Any], status_code: int = 200) -> JSONResponse:
    response = JSONResponse(payload, status_code=status_code)
    response.headers["Cache-Control"] = "no-store"
    return response

def _error(message: str, status_code: int = 400) -> JSONResponse:
    return json_error(message, status_code)

async def _body(request: Request, model: type[BaseModel]) -> BaseModel:
    content_type = request.headers.get("content-type", "")
    if not content_type.lower().startswith("application/json"):
        raise AuthError("Expected an application/json request.", 415)
    try:
        raw = await request.json()
    except Exception as exc:
        raise AuthError("The request body was not valid JSON.") from exc
    try:
        return model.model_validate(raw)
    except ValidationError as exc:
        first = exc.errors()[0] if exc.errors() else None
        message = first.get("msg", "Invalid request.") if first else "Invalid request."
        raise AuthError(str(message)) from exc

def _origin_ok(request: Request) -> bool:
    return check_origin(request.scope, _config(request))

def _limited(request: Request, action: str, limit: int, window: float = 60.0) -> bool:
    limiter = request.app.state.rate_limiter
    allowed = limiter.allow(f"{client_ip(request.scope)}:{action}", limit, window)
    if allowed:
        request.app.state.stats.inc_rate_limit_allowed()
    else:
        request.app.state.stats.inc_rate_limit_blocked()
    return allowed

async def _audit_failure(
    request: Request,
    event: str,
    detail: str,
    *,
    username: str | None = None,
) -> None:
    try:
        await _db(request).audit(
            event,
            username=username,
            ip=client_ip(request.scope),
            user_agent=user_agent(request.scope),
            detail=detail[:300],
        )
    except Exception:
        logger.exception("Could not write audit event")

async def _handle_auth_error(request: Request, exc: AuthError, *, audit: str | None = None) -> JSONResponse:
    if audit:
        await _audit_failure(request, audit, exc.message)
    request.app.state.stats.inc_auth_failure()
    return _error(exc.message, exc.status_code)

# ---------------------------------------------------------------------------
# OTP endpoints – now CSRF protected
# ---------------------------------------------------------------------------

@router.post("/_warden/auth/otp/setup")
@csrf_protected
async def otp_setup(request: Request) -> JSONResponse:
    """Generate a new TOTP secret for the authenticated user.

    * Requires an authenticated session (enforced by ``@csrf_protected`` which checks
      same‑origin and the ``X‑Warden‑Request: 1`` header).
    * Returns a 16‑character Base32 secret and an ``otpauth://`` URL which can be
      scanned by any standard TOTP app (Google Authenticator, Authy, etc.).
    * The secret is stored in the database via ``set_otp_secret``.
    * Increments the ``warden_otp_success_total`` metric on successful setup.
    """
    # Requires an authenticated session (enforced by csrf_protected -> _origin_ok + header)
    user = _user(request)
    # Generate a random base32 secret (16 chars ≈ 80‑bit entropy)
    import os, base64
    raw = os.urandom(10)
    secret = base64.b32encode(raw).decode("utf-8").replace("=", "")
    await _db(request).set_otp_secret(user.id, secret)
    otpauth = f"otpauth://totp/Warden:{user.username}?secret={secret}&issuer=Warden"
    return JSONResponse({"ok": True, "secret": secret, "otpauth_url": otpauth})

class OTPVerifyPayload(BaseModel):
    code: str

@router.post("/_warden/auth/otp/verify")
async def otp_verify(request: Request, payload: OTPVerifyPayload) -> JSONResponse:
    """Validate a TOTP code for the authenticated user.

    * Rate‑limited to 30 attempts per minute per IP.
    * Checks same‑origin via ``_origin_ok``.
    * On success increments ``warden_otp_success_total``; on failure increments
      ``warden_otp_failure_total``.
    * Returns ``{"ok": True}`` on success, otherwise a 401 response with
      ``{"ok": False, "detail": "Invalid OTP"}``.
    """
    if not _limited(request, "otp-verify", 30):
        return _error("Too many OTP attempts. Wait a minute and try again.", 429)
    if not _origin_ok(request):
        return _error("Cross-origin request blocked.", 403)
    user = _user(request)
    ok = await _db(request).verify_otp(user.id, payload.code)
    if ok:
        request.app.state.stats.inc_otp_success()
        return JSONResponse({"ok": True})
    else:
        request.app.state.stats.inc_otp_failure()
        await _audit_failure(request, "otp_failed", "Invalid OTP code")
        return JSONResponse({"ok": False, "detail": "Invalid OTP"}, status_code=401)

# ---------------------------------------------------------------------------
# Authentication flow (login, register, logout)
# ---------------------------------------------------------------------------

@router.get("/_warden/login")
async def login_page(request: Request) -> Response:
    """Render the login page, handling optional next redirect and session checks.
    """
    config = _config(request)
    next_path = safe_next(request.query_params.get("next"), "/")
    session = None
    if request.cookies.get("warden_session"):
        session = await authenticate_scope(request.scope, _db(request))
    if session is not None:
        target = next_path if next_path != "/" else (
            "/" if get_host(request.scope) == config.server.admin_host else "/"
        )
        return redirect(target)
    status = await _passkeys(request).setup_status()
    response = templates.TemplateResponse(
        request,
        "login.html",
        {
            "page": "login",
            "host": get_host(request.scope),
            "next_path": next_path,
            "setup_required": status["required"],
            "setup_expired": status["expired"],
            "page_title": "Sign in",
        },
    )
    return add_page_headers(response)

@router.get("/_warden/setup")
async def setup_page(request: Request) -> Response:
    """Render the setup page for initial admin registration.
    
    * Checks if setup is required; if not, redirects to the login page.
    * Provides the setup template with host, expiration status, and next path.
    """
    config = _config(request)
    status = await _passkeys(request).setup_status()
    if not status["required"]:
        return redirect(login_url(request.scope, config, "/"))
    response = templates.TemplateResponse(
        request,
        "setup.html",
        {
            "page": "setup",
            "host": get_host(request.scope),
            "setup_expired": status["expired"],
            "next_path": safe_next(request.query_params.get("next"), "/"),
            "page_title": "Claim this Warden",
        },
    )
    return add_page_headers(response)

@router.get("/_warden/health")
async def health(request: Request) -> JSONResponse:
    """Return a minimal health check JSON payload.
    
    * Includes basic status, version, and whether the initial setup is required.
    """
    status = await _passkeys(request).setup_status()
    return _json_response(
        {
            "status": "ok",
            "name": "warden",
            "version": __version__,
            "setup_required": status["required"],
        }
    )

# ---------------------------------------------------------------------------
# Setup flow (initial admin registration)
# ---------------------------------------------------------------------------

@router.post("/_warden/auth/setup/begin")
async def setup_begin(request: Request) -> JSONResponse:
    """Begin the admin setup flow by creating a new user passkey registration ceremony.
    
    * Rate‑limited to mitigate abuse.
    * Enforces same‑origin request.
    * Returns a JSON payload with the publicKey ceremony options.
    """
    if not _limited(request, "setup-begin", 8, 600):
        return _error("Too many setup attempts. Wait a few minutes and try again.", 429)
    if not _origin_ok(request):
        await _audit_failure(request, "setup_blocked", "cross-origin request")
        return _error("Cross-origin request blocked.", 403)
    config = _config(request)
    try:
        body = await _body(request, SetupBeginBody)
        assert isinstance(body, SetupBeginBody)
        ceremony = await _passkeys(request).begin_setup(
            username=body.username,
            display_name=body.display_name,
            setup_code=body.setup_code,
            origin=current_origin(request.scope, config),
            config=config,
            next_path=safe_next(body.next, "/"),
        )
    except AuthError as exc:
        return await _handle_auth_error(request, exc, audit="setup_failed")
    response = _json_response({"publicKey": ceremony.options, "expiresIn": ceremony.expires_in})
    set_challenge_cookie(
        response, ceremony.challenge_id, request.scope, config, config.webauthn.challenge_ttl_seconds
    )
    return response

@router.post("/_warden/auth/setup/complete")
async def setup_complete(request: Request) -> JSONResponse:
    """Complete the admin setup flow by finalising passkey registration.
    
    * Consumes the challenge, creates user and session, audits the event.
    * Returns JSON with redirect target for post‑setup navigation.
    """
    if not _limited(request, "setup-complete", 12, 600):
        return _error("Too many setup attempts. Wait a minute and try again.", 429)
    if not _origin_ok(request):
        return _error("Cross-origin request blocked.", 403)
    config = _config(request)
    challenge_id = challenge_from_scope(request.scope)
    if not challenge_id:
        return _error("Your setup attempt expired. Reload the page and try again.", 400)
    try:
        body = await _body(request, CredentialBody)
        assert isinstance(body, CredentialBody)
        result = await _passkeys(request).complete_registration(
            credential=body.credential,
            challenge_id=challenge_id,
            origin=current_origin(request.scope, config),
            config=config,
            session_user=None,
        )
    except AuthError as exc:
        return await _handle_auth_error(request, exc, audit="setup_failed")
    user = result["user"]
    token, session = await create_session(_db(request), user, request.scope, config)
    await _db(request).audit(
        "setup_completed",
        user_id=user.id,
        username=user.username,
        ip=client_ip(request.scope),
        user_agent=user_agent(request.scope),
        detail="First passkey registered",
    )
    target = safe_next(result.get("next"), "/") if get_host(request.scope) == config.server.admin_host else safe_next(result.get("next"), admin_url(request.scope, config))
    response = _json_response({"ok": True, "redirect": target})
    set_session_cookie(response, token, request.scope, config)
    clear_challenge_cookie(response, request.scope, config)
    return response

# ---------------------------------------------------------------------------
# Login flow
# ---------------------------------------------------------------------------

@router.post("/_warden/auth/login/begin")
async def login_begin(request: Request) -> JSONResponse:
    """Begin the login ceremony for a user.
    
    * Rate‑limited to prevent brute‑force login attempts.
    * Enforces same‑origin request.
    * Returns a JSON payload with the publicKey ceremony options.
    """
    if not _limited(request, "login-begin", 30):
        return _error("Too many sign-in attempts. Wait a minute and try again.", 429)
    if not _origin_ok(request):
        await _audit_failure(request, "login_blocked", "cross-origin request")
        return _error("Cross-origin request blocked.", 403)
    config = _config(request)
    try:
        body = await _body(request, LoginBeginBody)
        assert isinstance(body, LoginBeginBody)
        ceremony = await _passkeys(request).begin_login(
            username=body.username,
            origin=current_origin(request.scope, config),
            config=config,
            next_path=safe_next(body.next, "/"),
        )
    except AuthError as exc:
        return await _handle_auth_error(request, exc, audit="login_failed")
    response = _json_response({"publicKey": ceremony.options, "expiresIn": ceremony.expires_in})
    set_challenge_cookie(
        response, ceremony.challenge_id, request.scope, config, config.webauthn.challenge_ttl_seconds
    )
    return response

@router.post("/_warden/auth/login/backup")
async def login_backup(request: Request) -> JSONResponse:
    """Authenticate using a backup recovery code.
    
    * Rate‑limited and same‑origin enforced.
    * Validates the provided backup code and establishes a session.
    * Returns a JSON response with redirect target on success.
    """
    if not _limited(request, "login-backup", 15):
        return _error("Too many recovery attempts. Wait a minute and try again.", 429)
    if not _origin_ok(request):
        return _error("Cross-origin request blocked.", 403)
    config = _config(request)
    try:
        body = await _body(request, BackupCodeBody)
        assert isinstance(body, BackupCodeBody)
        user_id = await _db(request).use_backup_code(body.code)
        if user_id is None:
            raise AuthError("Invalid or already used recovery code.", 401)
        user = await _db(request).get_user(user_id)
        if user is None:
            raise AuthError("Account not found.", 401)
    except AuthError as exc:
        return await _handle_auth_error(request, exc, audit="backup_failed")
    token, session = await create_session(_db(request), user, request.scope, config)
    await _db(request).audit(
        "login_backup_succeeded",
        user_id=user.id,
        username=user.username,
        ip=client_ip(request.scope),
        user_agent=user_agent(request.scope),
        detail="Recovery code sign‑in",
    )
    response = _json_response({"ok": True, "redirect": safe_next("/", "/")})
    request.app.state.stats.inc_backup_code_used()
    set_session_cookie(response, token, request.scope, config)
    return response

@router.post("/_warden/auth/login/complete")
async def login_complete(request: Request) -> JSONResponse:
    """Complete the login flow after the WebAuthn ceremony.
    
    * Checks rate‑limit and origin.
    * Validates the credential, creates a session, and audits success.
    * Returns JSON with redirect target.
    """
    if not _limited(request, "login-complete", 30):
        return _error("Too many sign-in attempts. Wait a minute and try again.", 429)
    if not _origin_ok(request):
        await _audit_failure(request, "login_blocked", "cross-origin request")
        return _error("Cross-origin request blocked.", 403)
    config = _config(request)
    challenge_id = challenge_from_scope(request.scope)
    if not challenge_id:
        return _error("Your sign-in attempt expired. Reload the page and try again.", 400)
    try:
        body = await _body(request, CredentialBody)
        assert isinstance(body, CredentialBody)
        user, target = await _passkeys(request).complete_login(
            credential=body.credential,
            challenge_id=challenge_id,
            origin=current_origin(request.scope, config),
            config=config,
        )
    except AuthError as exc:
        return await _handle_auth_error(request, exc, audit="login_failed")
    token, session = await create_session(_db(request), user, request.scope, config)
    await _db(request).audit(
        "login_succeeded",
        user_id=user.id,
        username=user.username,
        ip=client_ip(request.scope),
        user_agent=user_agent(request.scope),
        detail="Passkey sign‑in",
    )
    request.app.state.stats.inc_auth_success()
    response = _json_response({"ok": True, "redirect": safe_next(target, "/")})
    set_session_cookie(response, token, request.scope, config)
    clear_challenge_cookie(response, request.scope, config)
    return response

# ---------------------------------------------------------------------------
# Passkey management (add / remove)
# ---------------------------------------------------------------------------

@router.post("/_warden/auth/register/begin")
async def register_begin(request: Request) -> JSONResponse:
    """Begin the registration ceremony for a new passkey.
    
    * Rate‑limited and same‑origin enforced.
    * Requires the user to be signed in (session required).
    * Returns a JSON payload with the publicKey ceremony options.
    """
    if not _limited(request, "register-begin", 12):
        return _error("Too many registration attempts. Wait a minute and try again.", 429)
    if not _origin_ok(request):
        return _error("Cross-origin request blocked.", 403)
    config = _config(request)
    session = await authenticate_scope(request.scope, _db(request))
    if session is None:
        return _error("Sign in before adding a passkey.", 401)
    try:
        body = await _body(request, RegisterBeginBody)
        assert isinstance(body, RegisterBeginBody)
        ceremony = await _passkeys(request).begin_add_passkey(
            user=session.user,
            name=body.name,
            origin=current_origin(request.scope, config),
            config=config,
        )
    except AuthError as exc:
        return await _handle_auth_error(request, exc, audit="passkey_failed")
    response = _json_response({"publicKey": ceremony.options, "expiresIn": ceremony.expires_in})
    set_challenge_cookie(
        response, ceremony.challenge_id, request.scope, config, config.webauthn.challenge_ttl_seconds
    )
    return response

@router.post("/_warden/auth/register/complete")
async def register_complete(request: Request) -> JSONResponse:
    """Complete the passkey registration flow.
    
    * Validates the credential and creates a new passkey entry for the user.
    * Audits the registration event and redirects to the passkeys page.
    """
    if not _limited(request, "register-complete", 12):
        return _error("Too many registration attempts. Wait a minute and try again.", 429)
    if not _origin_ok(request):
        return _error("Cross-origin request blocked.", 403)
    config = _config(request)
    session = await authenticate_scope(request.scope, _db(request))
    if session is None:
        return _error("Sign in before adding a passkey.", 401)
    challenge_id = challenge_from_scope(request.scope)
    if not challenge_id:
        return _error("Your registration attempt expired. Reload and try again.", 400)
    try:
        body = await _body(request, CredentialBody)
        assert isinstance(body, CredentialBody)
        result = await _passkeys(request).complete_registration(
            credential=body.credential,
            challenge_id=challenge_id,
            origin=current_origin(request.scope, config),
            config=config,
            session_user=session.user,
        )
    except AuthError as exc:
        return await _handle_auth_error(request, exc, audit="passkey_failed")
    credential = result["credential"]
    await _db(request).audit(
        "passkey_registered",
        user_id=session.user_id,
        username=session.user.username,
        ip=client_ip(request.scope),
        user_agent=user_agent(request.scope),
        detail=f"Added {credential.name}",
    )
    response = _json_response({"ok": True, "redirect": "/passkeys?added=1"})
    clear_challenge_cookie(response, request.scope, config)
    return response

# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------

@router.post("/_warden/auth/logout")
async def logout(request: Request) -> JSONResponse:
    """Terminate the current session and clear authentication cookies.
    
    * Enforces same‑origin request.
    * Revokes the session token, audits logout, and redirects to the login page.
    """
    if not _origin_ok(request):
        return _error("Cross-origin request blocked.", 403)
    config = _config(request)
    token = request.cookies.get("warden_session")
    session = await authenticate_scope(request.scope, _db(request))
    if token:
        from warden.auth.sessions import hash_token
        await _db(request).revoke_session_by_hash(hash_token(token))
    if session:
        await _db(request).audit(
            "logout",
            user_id=session.user_id,
            username=session.user.username,
            ip=client_ip(request.scope),
            user_agent=user_agent(request.scope),
        )
    response = _json_response({"ok": True, "redirect": f"{INTERNAL_PREFIX}/login"})
    clear_session_cookie(response, request.scope, config)
    return response

# ---------------------------------------------------------------------------
# Misc error endpoints
# ---------------------------------------------------------------------------

@router.get("/_warden/auth/unsupported")
async def unsupported() -> JSONResponse:
    """Return an error for browsers lacking necessary WebAuthn support.
    
    * Indicates the need for a modern browser or secure context.
    """
    return _error(
        "Passkeys require a modern browser and a secure (HTTPS or localhost) context.", 400
    )
