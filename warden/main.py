"""FastAPI application factory and process lifecycle for Warden.

This module defines :func:`create_app`, which builds the FastAPI instance,
initialises the database, health monitor, ACME manager and other core components.
It also contains helper functions for configuration loading, banner printing,
error handling, and request utilities.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import re
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse

try:
    from redis.exceptions import RedisError
except ImportError:
    RedisError = Exception  # type: ignore[misc,assignment]
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import Response
from starlette.staticfiles import StaticFiles

from warden import __version__
from warden.admin.routes import router as admin_router
from warden.auth.passkeys import PasskeyService
from warden.auth.routes import router as auth_router
from warden.config import ConfigManager, WardenConfig
from warden.db import Database
from warden.health_adapter import HealthMonitor
from warden.mesh import MeshManager
from warden.middleware import WardenMiddleware
from warden.proxy import ProxyEngine
from warden.stats import MetricsModule
from warden.templating import templates
from warden.tls import ACMEManager, TLSError, renewal_loop, validate_runtime_files
from warden.utils import (
    INTERNAL_PREFIX,
    RateLimiter,
    RedisRateLimiter,
    add_page_headers,
    get_host,
    request_wants_json,
)

logger = logging.getLogger("warden")

DEFAULT_CONFIG_NAME = "warden.yaml"
_ACME_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_CLEANUP_INTERVAL = 3600.0


def _default_config_path() -> Path:
    """Return the configuration file path from the ``WARDEN_CONFIG`` env variable or default.
    """
    return Path(os.environ.get("WARDEN_CONFIG", DEFAULT_CONFIG_NAME)).expanduser()


def _manager_for(
    config_path: str | Path | None, config: WardenConfig | None
) -> ConfigManager:
    """Create or load a ``ConfigManager`` for the given path or config.
    
    * If a ``config`` object is provided, it is used directly with an optional path.
    * Otherwise, the configuration is loaded from ``config_path`` or the default.
    """
    if config is not None:
        path = Path(config_path).expanduser().resolve() if config_path else None
        return ConfigManager(config, path)
    path = Path(config_path).expanduser() if config_path else _default_config_path()
    return ConfigManager.from_file(path)


async def _cleanup_loop(
    app: FastAPI, config: WardenConfig, database: Database
) -> None:
    """Delete expired sessions/challenges and checkpoint SQLite once an hour."""
    await asyncio.sleep(45)
    interval = config.server.cleanup_interval_seconds
    while True:
        try:
            await app.state.db.delete_expired_sessions()
            await app.state.db.delete_expired_challenges()
            if config.server.vacuum_enabled:
                logger.debug("Running database vacuum")
                await app.state.db.vacuum()
            else:
                logger.debug("VACUUM skipped (vacuum_enabled=false)")
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Background cleanup failed")
        await asyncio.sleep(interval)


def _public_base_url(config: WardenConfig) -> str:
    """Construct the base URL for external links based on the configuration.
    
    * Uses ``public_url`` if set, otherwise builds ``scheme://host[:port]``.
    """
    if config.server.public_url:
        return config.server.public_url
    scheme = "https" if config.server.tls.enabled else "http"
    port = (
        config.server.https_port
        if config.server.tls.enabled
        else config.server.http_port
    )
    host = config.server.admin_host
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    suffix = "" if port in {80, 443} else f":{port}"
    return f"{scheme}://{host}{suffix}"


def _print_banner(
    manager: ConfigManager,
    setup_code: str | None,
    setup_expires: float | None,
) -> None:
    """Print a startup banner with version, address, and setup instructions.
    """
    config = manager.config
    base = _public_base_url(config)
    lines = [
        "",
        "  WARDEN",
        f"  v{__version__} · {base}",
    ]
    if manager.path:
        lines.append(f"  config · {manager.path}")
    lines.append("  " + "─" * 58)
    if setup_code:
        lines.extend(
            [
                "  FIRST RUN · this Warden has not been claimed",
                f"  Setup code · {setup_code}",
                f"  Open       · {base}{INTERNAL_PREFIX}/setup",
            ]
        )
        if setup_expires:
            lines.append(
                "  Expires    · "
                + time.strftime("%Y-%m-%d %H:%M", time.localtime(setup_expires))
            )
        lines.append("  Set WARDEN_SETUP_TOKEN to choose your own code next time.")
    elif os.environ.get("WARDEN_SETUP_TOKEN"):
        lines.append(
            f"  First-run setup is available at {base}{INTERNAL_PREFIX}/setup"
        )
        lines.append("  The code is taken from WARDEN_SETUP_TOKEN.")
    else:
        lines.append("  Ready. Sign in with your passkey.")
    lines.append("  " + "─" * 58)
    lines.append("")
    print("\n".join(lines), flush=True)


def _error_response(request: Request, status: int, title: str, message: str) -> Response:
    """Render the Warden error page, or JSON for API clients."""
    if request_wants_json(request.scope):
        body = JSONResponse({"detail": message}, status_code=status)
        body.headers["Cache-Control"] = "no-store"
        return body
    config = request.app.state.manager.config
    host = get_host(request.scope)
    admin = host == config.server.admin_host
    response = templates.TemplateResponse(
        request,
        "error.html",
        {
            "page_title": title,
            "code": str(status),
            "title": title,
            "message": message,
            "detail": "",
            "host": host,
            "retry_url": request.url.path,
            "admin_url": "/" if admin else None,
        },
        status_code=status,
    )
    return add_page_headers(response)


_STATUS_COPY: dict[int, tuple[str, str]] = {
    400: ("That request didn't look right", "Warden could not understand the request. Check the address and try again."),
    401: ("Sign in required", "This page needs a passkey before it will open."),
    403: ("Not allowed", "Warden blocked that request for security reasons."),
    404: ("Not found", "That Warden URL does not exist."),
    405: ("Not allowed", "That method is not available here."),
    409: ("Already exists", "That resource is already in use."),
    413: ("Too large", "That request body is larger than Warden accepts."),
    422: ("That request didn't look right", "Some of the submitted values were invalid."),
    429: ("Slow down", "Too many requests. Wait a moment and try again."),
    500: ("Something broke", "Warden hit an unexpected error while handling that request."),
    502: ("The service is out of reach", "The service behind this address is not responding."),
    503: ("Not available", "Warden is not ready to serve that request yet."),
    504: ("The service is taking too long", "The upstream service did not answer in time."),
}


def create_app(
    config_path: str | Path | None = None,
    *,
    config: WardenConfig | None = None,
    db: Database | None = None,
    proxy: ProxyEngine | None = None,
    stats: MetricsModule | None = None,
) -> FastAPI:
    """Build the Warden ASGI application.

    Tests can inject an in-memory database, a prepared config, and shared
    stats/proxy instances. In production all arguments default from the YAML
    file named by ``WARDEN_CONFIG`` (or ``warden.yaml``).
    """
    manager = _manager_for(config_path, config)
    active_config = manager.config
    if db is not None:
        database = db
    elif active_config.database.type == "postgres":
        from warden.db_postgres import PostgresDatabase
        url = active_config.database.url or "postgresql+asyncpg://localhost/warden"
        database = PostgresDatabase(url)
    else:
        database = Database(active_config.database_path)
    # Store the config on the database instance so vacuum() can read the
    # size threshold at runtime.
    database.config = active_config.server
    metrics = stats or MetricsModule()
    engine = proxy or ProxyEngine(manager, metrics)
    passkeys = PasskeyService(database)
    acme_manager = ACMEManager(manager)
    # Attach to engine for token bridging (challenge responses)
    mesh = MeshManager(database, manager)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        await database.init()
        try:
            validate_runtime_files(manager.config)
        except TLSError:
            await database.close()
            raise
        setup_code, setup_expires = await passkeys.prepare_setup_code(
            os.environ.get("WARDEN_SETUP_TOKEN")
        )
        _print_banner(manager, setup_code, setup_expires)

        app.state.config = manager.config
        monitor = HealthMonitor(metrics, manager)
        app.state.health_monitor = monitor
        await monitor.start()
        tasks: list[asyncio.Task[Any]] = [
            asyncio.create_task(
                _cleanup_loop(app, manager.config, database), name="warden-cleanup"
            )
        ]
        renewal_task: asyncio.Task[Any] | None = None
        if manager.config.server.tls.enabled and manager.config.server.tls.renew_command:
            renewal_task = asyncio.create_task(renewal_loop(app), name="warden-tls-renewal")
            app.state.renewal_task = renewal_task
        app.state.background_tasks = tasks
        app.state.started_at = time.time()
        try:
            yield
        finally:
            for task in [*tasks, renewal_task]:
                if task is None:
                    continue
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task
            await monitor.stop()
            await engine.close()
            await database.close()
            app.state.background_tasks = []
            app.state.renewal_task = None

    app = FastAPI(
        title="Warden",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.manager = manager
    app.state.db = database
    app.state.stats = metrics
    app.state.proxy = engine
    app.state.passkeys = passkeys
    app.state.mesh = mesh
    app.state.cert_renewal = None
    app.state.started_at = time.time()
    app.state.background_tasks = []
    app.state.renewal_task = None
    app.state.acme_manager = acme_manager
    app.state.config_path = manager.path
    # Initialize request rate limiter based on configuration
    rate_cfg = manager.config.server.rate_limiter
    if rate_cfg and rate_cfg.backend == "redis":
        redis_url = rate_cfg.redis_url or "redis://localhost"
        ttl = rate_cfg.ttl
        try:
            app.state.rate_limiter = RedisRateLimiter(redis_url, ttl=ttl)
        except RedisError:
            logger.warning("Failed to configure RedisRateLimiter, falling back to in‑process RateLimiter")
            app.state.rate_limiter = RateLimiter()
    else:
        # Default to in‑process limiter (memory backend)
        app.state.rate_limiter = RateLimiter()



    static_dir = Path(__file__).parent / "templates" / "static"
    app.mount("/_warden/static", StaticFiles(directory=static_dir), name="static")
    # Add authentication and admin routers
    app.include_router(auth_router)
    app.include_router(admin_router)


    @app.get("/.well-known/acme-challenge/{token}", include_in_schema=False)
    async def acme_challenge(token: str) -> Response:
        root = manager.config.acme_webroot_path
        if root is None or not _ACME_TOKEN_RE.match(token):
            raise HTTPException(404, "Not found")
        try:
            resolved_root = root.resolve()
            target = (resolved_root / token).resolve()
        except OSError:
            raise HTTPException(404, "Not found") from None
        if resolved_root not in target.parents:
            raise HTTPException(404, "Not found")
        try:
            content = target.read_text(encoding="utf-8").strip()
        except OSError:
            raise HTTPException(404, "Not found") from None
        response = PlainTextResponse(content)
        response.headers["Cache-Control"] = "no-store"
        return response

    app.add_middleware(
        WardenMiddleware,
        manager=manager,
        db=database,
        proxy=engine,
        stats=metrics,
    )

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> Response:
        title, message = _STATUS_COPY.get(
            exc.status_code, ("Request failed", "Warden could not complete that request.")
        )
        if isinstance(exc.detail, str) and exc.detail and exc.detail != "Not Found":
            message = exc.detail
        response = _error_response(request, exc.status_code, title, message)
        if exc.headers:
            for key, value in exc.headers.items():
                response.headers.setdefault(key, value)
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> Response:
        if request.url.path.startswith(f"{INTERNAL_PREFIX}/api/") or request_wants_json(
            request.scope
        ):
            response = JSONResponse({"detail": exc.errors()}, status_code=422)
            response.headers["Cache-Control"] = "no-store"
            return response
        return _error_response(
            request,
            422,
            "That request didn't look right",
            "Some of the submitted values were invalid. Go back and check the form.",
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> Response:
        logger.exception("Unhandled request error on %s %s", request.method, request.url.path)
        return _error_response(
            request,
            500,
            "Something broke",
            "Warden hit an unexpected error. Check the service log for details.",
        )

    return app


__all__ = ["DEFAULT_CONFIG_NAME", "create_app"]
