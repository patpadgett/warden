"""Typed configuration, validation, and safe YAML round‑tripping for Warden.

This module defines the pydantic models representing the Warden configuration file,
including server, TLS, WebAuthn, routing, and mesh settings. It also provides the
:class:`ConfigManager` class which loads, validates, and writes configuration files,
handling atomic saves and preserving restart‑only fields.
"""

from __future__ import annotations

import ipaddress
import os
import re
import tempfile
import threading
from collections.abc import Iterable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, field_validator, model_validator
from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq
from ruamel.yaml.error import YAMLError

HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}

_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOST_RE = re.compile(rf"^(?:{_LABEL}\.)*{_LABEL}$")
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


class ConfigError(Exception):
    """Raised when a configuration file cannot be loaded or validated."""

    def __init__(self, message: str, errors: Iterable[str] | None = None) -> None:
        self.message = message
        self.errors = list(errors or [])
        super().__init__(self.pretty())

    def pretty(self) -> str:
        if not self.errors:
            return self.message
        lines = [self.message, ""]
        lines.extend(f"  • {error}" for error in self.errors)
        return "\n".join(lines)


def normalize_host(value: str, *, allow_wildcard: bool = False) -> str:
    """Normalize and validate a hostname used for routing or WebAuthn."""
    if not isinstance(value, str):
        raise TypeError("must be a hostname")
    host = value.strip().lower().rstrip(".")
    if host.startswith(("http://", "https://")):
        raise ValueError("use a hostname, not a URL")
    if "/" in host or "?" in host or "#" in host or "@" in host:
        raise ValueError("must be a hostname without a path")
    if host.startswith("*."):
        if not allow_wildcard:
            raise ValueError("wildcards are only allowed for route hosts")
        suffix = host[2:]
        if not suffix or not _HOST_RE.match(suffix):
            raise ValueError(f"invalid wildcard hostname: {value!r}")
        return f"*.{suffix}"
    if "*" in host:
        raise ValueError("only a leading '*.' wildcard is supported")
    if ":" in host:
        raise ValueError("ports are not allowed; configure the listening port separately")
    if not host or not _HOST_RE.match(host):
        raise ValueError(f"invalid hostname: {value!r}")
    return host


def _host_under(host: str, parent: str) -> bool:
    base = host.removeprefix("*.")
    return base == parent or base.endswith("." + parent)


def _normalize_origin(value: str) -> str:
    value = value.strip().rstrip("/")
    parts = urlsplit(value)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ValueError("must be an origin like https://admin.home.lan")
    if parts.path not in {"", "/"} or parts.query or parts.fragment:
        raise ValueError("origins cannot include a path, query, or fragment")
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("invalid port in origin") from exc
    host = parts.hostname.lower()
    default = 443 if parts.scheme == "https" else 80
    return f"{parts.scheme}://{host}" + (f":{port}" if port and port != default else "")


def _validate_header_value(value: str) -> str:
    if "\r" in value or "\n" in value or "\x00" in value:
        raise ValueError("header values cannot contain control characters")
    return value


class RateLimiterConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    
    backend: str = Field(default="memory", description="Backend for rate limiting: \"memory\" or \"redis\"")
    redis_url: str | None = Field(default=None, description="Redis connection URL (e.g., redis://localhost)")
    ttl: int = Field(default=86400, ge=1, description="TTL for Redis rate‑limiter entries (seconds)")
    
    @field_validator("backend")
    @classmethod
    def _validate_backend(cls, value: str) -> str:
        if value not in {"memory", "redis"}:
            raise ValueError("rate_limiter.backend must be 'memory' or 'redis'")
        return value


class TLSConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    certfile: str | None = None
    keyfile: str | None = None
    #: Directory served at /.well-known/acme-challenge/ for certbot webroot renewals.
    acme_webroot: str | None = None
    #: Shell command run when the certificate is close to expiry (admin-defined).
    renew_command: str | None = None
    renew_days_before: int = Field(default=30, ge=1, le=90)
    check_interval_hours: int = Field(default=12, ge=1, le=168)

    @model_validator(mode="after")
    def _check_tls(self) -> TLSConfig:
        if self.renew_command and not self.acme_webroot:
            # A renewal hook without webroot is allowed for DNS-01 challenges.
            pass
        return self


class WebAuthnConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rp_id: str = "localhost"
    rp_name: str = "Warden"
    require_user_verification: bool = False
    challenge_ttl_seconds: int = Field(default=300, ge=30, le=1800)
    #: Additional browser origins allowed to complete passkey ceremonies.
    allowed_origins: list[str] = Field(default_factory=list)

    @field_validator("rp_id")
    @classmethod
    def _validate_rp_id(cls, value: str) -> str:
        host = normalize_host(value)
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return host
        if host not in {"127.0.0.1", "::1"}:
            raise ValueError("WebAuthn RP IDs cannot be bare IP addresses")
        return host

    @field_validator("allowed_origins")
    @classmethod
    def _validate_origins(cls, value: list[str]) -> list[str]:
        return [_normalize_origin(origin) for origin in value]

    @field_validator("rp_name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("rp_name cannot be empty")
        return value


class DatabaseConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = "warden.db"
    type: str = "sqlite"
    url: str | None = None


class ServerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Rate limiter configuration – optional; if omitted, in‑process limiter is used.
    rate_limiter: RateLimiterConfig | None = None
    admin_host: str = "localhost"
    bind: str = "0.0.0.0"
    http_port: int = Field(default=8080, ge=1, le=65535)
    https_port: int = Field(default=8443, ge=1, le=65535)
    tls: TLSConfig = Field(default_factory=TLSConfig)
    #: Optional parent domain for the session cookie, e.g. "home.lan" for SSO.
    cookie_domain: str | None = None
    #: None means "secure when the incoming request is HTTPS".
    secure_cookies: bool | None = None
    session_ttl_hours: int = Field(default=168, ge=1, le=720)
    trust_proxy_headers: bool = False
    #: Header injected into upstream requests for authenticated users (null disables).
    forward_user_header: str | None = "X-Warden-User"
    #: Force the scheme used for absolute redirects (useful behind a TLS terminator).
    external_scheme: str | None = None
    #: Optional canonical admin origin, e.g. https://admin.home.lan.
    public_url: str | None = None
    request_timeout_seconds: float = Field(default=60.0, ge=1, le=3600)
    health_interval_seconds: int = Field(default=30, ge=10, le=3600)
    #: How often the cleanup loop runs (seconds). The loop runs once an hour by
    #: default; set to 0 to disable the periodic cleanup task entirely.
    cleanup_interval_seconds: float = Field(default=3600.0, ge=0)
    #: If true, the cleanup loop also runs ``VACUUM`` on the database after the
    #: per-table deletes. PostgreSQL relies on ``autovacuum`` for this and must
    #: not be vacuumed manually on a pooled connection, so it defaults to
    #: ``False`` on Postgres and ``True`` on SQLite.
    vacuum_enabled: bool = True
    #: Only runs regular (non-FULL) VACUUM on SQLite when the database file is
    #: larger than this many megabytes, to avoid a long-running exclusive lock
    #: on a small database.
    max_vacuum_bytes: int = Field(default=100 * 1024 * 1024, ge=0)
    #: Maximum request body size in MB (deprecated in favor of max_vacuum_bytes).
    max_body_size_mb: int = Field(default=10, ge=1, le=1024)
    log_level: str = "info"
    #: Maximum concurrent sessions per user. ``None`` disables the limit.
    max_sessions_per_user: int | None = Field(default=None, ge=1)

    @field_validator("admin_host")
    @classmethod
    def _validate_admin_host(cls, value: str) -> str:
        return normalize_host(value)

    @field_validator("bind")
    @classmethod
    def _validate_bind(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("bind address cannot be empty")
        return value

    @field_validator("cookie_domain")
    @classmethod
    def _validate_cookie_domain(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        return normalize_host(value.lstrip("."))

    @field_validator("forward_user_header", mode="before")
    @classmethod
    def _validate_user_header(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = str(value).strip()
        if not value:
            return None
        if not _HEADER_NAME_RE.match(value):
            raise ValueError("forward_user_header is not a valid HTTP header name")
        if value.lower() in HOP_BY_HOP or value.lower() in {"host", "content-length", "cookie"}:
            raise ValueError("forward_user_header cannot be a reserved header")
        return value

    @field_validator("external_scheme")
    @classmethod
    def _validate_external_scheme(cls, value: str | None) -> str | None:
        if value is not None and value not in {"http", "https"}:
            raise ValueError("external_scheme must be http or https")
        return value

    @field_validator("public_url")
    @classmethod
    def _validate_public_url(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        return _normalize_origin(value)

    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, value: str) -> str:
        value = value.lower()
        if value not in {"debug", "info", "warning", "error", "critical"}:
            raise ValueError("log_level must be debug, info, warning, error, or critical")
        return value


class RouteConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host: str
    upstream: str
    name: str | None = None
    auth: bool = True
    enabled: bool = True
    websocket: bool = True
    websocket_subprotocols: list[str] = Field(default_factory=list)
    websocket_max_size: int = 16 * 1024 * 1024
    preserve_host: bool = False
    verify_tls: bool = True
    rewrite_redirects: bool = True
    rewrite_cookies: bool = True
    health_path: str = "/"
    timeout_seconds: float | None = Field(default=None, ge=1, le=3600)
    public_paths: list[str] = Field(default_factory=list)
    headers: dict[str, str] = Field(default_factory=dict)
    icon: str | None = None
    #: List of CIDR networks allowed to access this route.
    allowed_ips: list[str] = Field(default_factory=list)
    #: List of CIDR networks denied access to this route.
    denied_ips: list[str] = Field(default_factory=list)
    #: Per-route rate limit in requests per minute. ``None`` disables per-route
    #: limiting (falls back to the global limiter).
    rate_limit: int | None = Field(default=None, ge=1)

    @field_validator("host")
    @classmethod
    def _validate_host(cls, value: str) -> str:
        return normalize_host(value, allow_wildcard=True)

    @field_validator("upstream")
    @classmethod
    def _validate_upstream(cls, value: str) -> str:
        value = value.strip()
        parts = urlsplit(value)
        if parts.scheme not in {"http", "https"}:
            raise ValueError("upstream must start with http:// or https://")
        if not parts.hostname:
            raise ValueError("upstream must include a hostname")
        if parts.query or parts.fragment:
            raise ValueError("upstream cannot include a query string or fragment")
        try:
            parts.port  # noqa: B018 - force port validation
        except ValueError as exc:
            raise ValueError("upstream has an invalid port") from exc
        if parts.path in {"", "/"}:
            return value.rstrip("/")
        return value.rstrip("/")

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if len(value) > 60:
            raise ValueError("name must be 60 characters or fewer")
        return value or None

    @field_validator("health_path")
    @classmethod
    def _validate_health_path(cls, value: str) -> str:
        value = value.strip() or "/"
        if not value.startswith("/"):
            raise ValueError("health_path must start with /")
        return value

    @field_validator("public_paths")
    @classmethod
    def _validate_public_paths(cls, value: list[str]) -> list[str]:
        cleaned: list[str] = []
        for path in value:
            path = path.strip()
            if not path.startswith("/"):
                raise ValueError("public_paths entries must start with /")
            cleaned.append(path)
        return cleaned

    @field_validator("headers")
    @classmethod
    def _validate_headers(cls, value: dict[str, str]) -> dict[str, str]:
        result: dict[str, str] = {}
        for key, item in value.items():
            if not _HEADER_NAME_RE.match(key):
                raise ValueError(f"invalid header name: {key!r}")
            if key.lower() in HOP_BY_HOP or key.lower() in {"host", "content-length"}:
                raise ValueError(f"reserved header cannot be overridden: {key!r}")
            result[key] = _validate_header_value(str(item))
        return result

    @field_validator("allowed_ips")
    @classmethod
    def _validate_allowed_ips(cls, value: list[str]) -> list[str]:
        cleaned: list[str] = []
        for ip in value:
            try:
                ipaddress.ip_network(ip, strict=False)
                cleaned.append(ip)
            except ValueError:
                raise ValueError(f"invalid CIDR in allowed_ips: {ip!r}")
        return cleaned

    @field_validator("denied_ips")
    @classmethod
    def _validate_denied_ips(cls, value: list[str]) -> list[str]:
        cleaned: list[str] = []
        for ip in value:
            try:
                ipaddress.ip_network(ip, strict=False)
                cleaned.append(ip)
            except ValueError:
                raise ValueError(f"invalid CIDR in denied_ips: {ip!r}")
        return cleaned

    @property
    def display_name(self) -> str:
        if self.name:
            return self.name
        if self.host.startswith("*."):
            label = self.host[2:].split(".")[0]
        else:
            label = self.host.split(".")[0]
        return label.replace("-", " ").replace("_", " ").title()

    @property
    def scheme(self) -> str:
        return urlsplit(self.upstream).scheme

    @property
    def upstream_host(self) -> str:
        return urlsplit(self.upstream).netloc

    def matches_host(self, host: str) -> bool:
        if self.host == host:
            return True
        if self.host.startswith("*."):
            base = self.host[2:]
            return host.endswith("." + base) and host != base
        return False

    def is_public_path(self, path: str) -> bool:
        from fnmatch import fnmatch

        return any(fnmatch(path, pattern) for pattern in self.public_paths)


class MeshConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    interface: str = "wg0"
    address: str = "10.44.0.1/24"
    listen_port: int = Field(default=51820, ge=1, le=65535)
    endpoint: str | None = None
    dns: str | None = None
    client_allowed_ips: str = "10.44.0.0/24"
    config_path: str | None = None

    @field_validator("interface")
    @classmethod
    def _validate_interface(cls, value: str) -> str:
        value = value.strip()
        if not re.match(r"^[A-Za-z0-9_=+.-]{1,15}$", value):
            raise ValueError("invalid WireGuard interface name")
        return value

    @field_validator("address")
    @classmethod
    def _validate_address(cls, value: str) -> str:
        try:
            interface = ipaddress.ip_interface(value)
        except ValueError as exc:
            raise ValueError("address must be a CIDR like 10.44.0.1/24") from exc
        return str(interface)

    @field_validator("client_allowed_ips")
    @classmethod
    def _validate_allowed_ips(cls, value: str) -> str:
        parts = [part.strip() for part in value.split(",") if part.strip()]
        if not parts:
            raise ValueError("client_allowed_ips cannot be empty")
        for part in parts:
            try:
                ipaddress.ip_network(part, strict=False)
            except ValueError as exc:
                raise ValueError(f"invalid network in client_allowed_ips: {part}") from exc
        return ", ".join(parts)

    @field_validator("endpoint")
    @classmethod
    def _validate_endpoint(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        value = value.strip()
        if ":" not in value:
            raise ValueError("endpoint must be host:port")
        host, port = value.rsplit(":", 1)
        if not host:
            raise ValueError("endpoint must include a host")
        if not port.isdigit() or not (1 <= int(port) <= 65535):
            raise ValueError("endpoint has an invalid port")
        return value

    @field_validator("dns")
    @classmethod
    def _validate_dns(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        try:
            ipaddress.ip_address(value.strip())
        except ValueError as exc:
            raise ValueError("mesh.dns must be an IP address") from exc
        return value.strip()


class WardenConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = 1
    server: ServerConfig = Field(default_factory=ServerConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    webauthn: WebAuthnConfig = Field(default_factory=WebAuthnConfig)
    mesh: MeshConfig = Field(default_factory=MeshConfig)
    routes: list[RouteConfig] = Field(default_factory=list)

    _base_dir: Path = PrivateAttr(default_factory=Path.cwd)

    @model_validator(mode="after")
    def _validate_cross_fields(self) -> WardenConfig:
        errors: list[str] = []
        rp_id = self.webauthn.rp_id
        admin_host = self.server.admin_host
        cookie_domain = self.server.cookie_domain

        if admin_host == rp_id or admin_host.endswith("." + rp_id):
            # admin host is valid
            pass
        else:
            errors.append(
                f"server.admin_host ({admin_host}) must be {rp_id} or a subdomain of it "
                "so passkeys can be used on the dashboard"
            )

        if cookie_domain and not _host_under(admin_host, cookie_domain):
            errors.append(
                f"server.cookie_domain ({cookie_domain}) must be a parent domain of "
                f"server.admin_host ({admin_host})"
            )

        seen: dict[str, int] = {}
        for index, route in enumerate(self.routes):
            if route.host in seen:
                errors.append(
                    f"routes[{index}].host duplicates routes[{seen[route.host]}].host "
                    f"({route.host})"
                )
            seen[route.host] = index
            if route.host == admin_host:
                errors.append(
                    f"routes[{index}].host ({route.host}) conflicts with server.admin_host"
                )
            if route.host.startswith("*.") and _host_under(admin_host, route.host[2:]):
                errors.append(
                    f"routes[{index}] wildcard ({route.host}) would capture the admin host "
                    f"({admin_host})"
                )
            if route.auth:
                if not _host_under(route.host, rp_id):
                    errors.append(
                        f"routes[{index}].host ({route.host}) is outside the WebAuthn RP ID "
                        f"({rp_id}); set auth: false or use a host under {rp_id}"
                    )
                if cookie_domain and not _host_under(route.host, cookie_domain):
                    errors.append(
                        f"routes[{index}].host ({route.host}) is outside "
                        f"server.cookie_domain ({cookie_domain})"
                    )

        if self.server.public_url:
            origin = urlsplit(self.server.public_url)
            if origin.scheme not in {"http", "https"}:
                errors.append("server.public_url must use http or https")
            if origin.hostname and not _host_under(origin.hostname, rp_id):
                errors.append(
                    "server.public_url host must be the admin host or a subdomain of the RP ID"
                )
            if origin.hostname and origin.hostname != admin_host:
                errors.append("server.public_url host must match server.admin_host")

        if self.server.tls.enabled:
            # certfile/keyfile presence is validated at runtime by
            # validate_runtime_files(); allow TLS to be enabled pre-provisioning
            # (e.g. ACME) so certificate_status can report it gracefully.
            pass

        if errors:
            raise ValueError("; ".join(errors))
        return self

    @property
    def admin_origin(self) -> str | None:
        return self.server.public_url

    def base_dir(self) -> Path:
        return Path(self._base_dir)

    def resolve_path(self, value: str) -> Path:
        path = Path(value).expanduser()
        if not path.is_absolute():
            path = self.base_dir() / path
        return path.resolve()

    @property
    def database_path(self) -> Path:
        return self.resolve_path(self.database.path)

    @property
    def certfile_path(self) -> Path | None:
        if not self.server.tls.certfile:
            return None
        return self.resolve_path(self.server.tls.certfile)

    @property
    def keyfile_path(self) -> Path | None:
        if not self.server.tls.keyfile:
            return None
        return self.resolve_path(self.server.tls.keyfile)

    @property
    def acme_webroot_path(self) -> Path | None:
        if not self.server.tls.acme_webroot:
            return None
        return self.resolve_path(self.server.tls.acme_webroot)

    @property
    def mesh_config_path(self) -> Path | None:
        if not self.mesh.config_path:
            return None
        return self.resolve_path(self.mesh.config_path)

    def match_route(self, host: str) -> RouteConfig | None:
        """Match exact hosts first, then the longest wildcard suffix."""
        exact = next((route for route in self.routes if route.host == host), None)
        if exact:
            return exact
        candidates = [route for route in self.routes if route.host.startswith("*.") and route.matches_host(host)]
        if not candidates:
            return None
        return max(candidates, key=lambda route: len(route.host))

    def enabled_routes(self) -> list[RouteConfig]:
        return [route for route in self.routes if route.enabled]

    def origin_allowed(self, origin: str) -> bool:
        try:
            normalized = _normalize_origin(origin)
        except ValueError:
            return False
        if normalized in self.webauthn.allowed_origins:
            return True
        parts = urlsplit(normalized)
        host = (parts.hostname or "").lower()
        if host in {"localhost", "127.0.0.1", "::1"}:
            return self.webauthn.rp_id in {"localhost", "127.0.0.1", "::1"} or host == self.webauthn.rp_id
        return _host_under(host, self.webauthn.rp_id)


def format_validation_errors(exc: Exception) -> list[str]:
    errors = getattr(exc, "errors", None)
    if callable(errors):
        messages: list[str] = []
        for error in errors():
            location = ".".join(str(part) for part in error.get("loc", ()))
            message = error.get("msg", "invalid value")
            messages.append(f"{location}: {message}" if location else message)
        return messages
    return [str(exc)]


def env_substitute(value: Any) -> Any:
    """Recursively replace ``${VAR}`` and ``$VAR`` with environment variables."""
    if isinstance(value, dict):
        return {key: env_substitute(val) for key, val in value.items()}
    if isinstance(value, list):
        return [env_substitute(item) for item in value]
    if isinstance(value, str):
        def _replace(match: re.Match[str]) -> str:
            var_name = match.group(1) or match.group(2)
            return os.environ.get(var_name, match.group(0))
        return re.sub(r"\$\{(\w+)\}|\$(\w+)", _replace, value)
    return value


def parse_config_text(text: str, *, base_dir: Path, source: str = "config") -> WardenConfig:
    yaml = YAML(typ="safe", pure=True)
    yaml.allow_duplicate_keys = False
    try:
        data = yaml.load(text)
    except YAMLError as exc:
        raise ConfigError(f"Could not parse {source} as YAML.", [str(exc)]) from exc
    if data is None:
        raise ConfigError(f"{source} is empty.")
    if not isinstance(data, dict):
        raise ConfigError(f"{source} must contain a YAML mapping at the top level.")
    data = env_substitute(data)
    try:
        config = WardenConfig.model_validate(data)
    except Exception as exc:  # pydantic.ValidationError and ValueErrors
        raise ConfigError(f"Invalid configuration in {source}.", format_validation_errors(exc)) from exc
    config._base_dir = Path(base_dir).resolve()
    return config


def load_config(path: str | Path) -> WardenConfig:
    config_path = Path(path).expanduser().resolve()
    if not config_path.exists():
        raise ConfigError(
            f"Configuration file not found: {config_path}",
            ["Run 'warden init' to generate one, or pass --config."],
        )
    try:
        text = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Could not read {config_path}: {exc}") from exc
    return parse_config_text(text, base_dir=config_path.parent, source=str(config_path))


def _to_commented(value: Any) -> Any:
    if isinstance(value, dict):
        result = CommentedMap()
        for key, item in value.items():
            result[key] = _to_commented(item)
        return result
    if isinstance(value, list):
        result = CommentedSeq()
        for item in value:
            result.append(_to_commented(item))
        return result
    return value


class ConfigManager:
    """Manage loading, validation, and persistence of the Warden YAML configuration.

    * ``from_file`` loads the configuration from disk, applying schema validation.
    * ``save_text`` writes a new configuration atomically, preserving fields that
      require a process restart.
    * ``validate_text`` validates a configuration string without persisting it.
    * Provides helper methods for reading and writing the raw YAML file.
    """

    def __init__(self, config: WardenConfig, path: Path | None = None) -> None:
        self._config = config
        self.path = Path(path).resolve() if path else None
        self._lock = threading.RLock()

    @classmethod
    def from_file(cls, path: str | Path) -> ConfigManager:
        resolved = Path(path).expanduser().resolve()
        return cls(load_config(resolved), resolved)

    @property
    def config(self) -> WardenConfig:
        return self._config

    @property
    def base_dir(self) -> Path:
        return self._config.base_dir()

    def read_text(self) -> str:
        if not self.path or not self.path.exists():
            raise ConfigError("This Warden instance is not running from a YAML file.")
        return self.path.read_text(encoding="utf-8")

    def validate_text(self, text: str) -> WardenConfig:
        base = self.path.parent if self.path else self.base_dir
        return parse_config_text(text, base_dir=base, source=str(self.path or "config"))

    def validate_startup(self) -> None:
        """Validate runtime dependencies before the server accepts traffic.

        Checks:
        * TLS certificate/key files exist when TLS is enabled.
        * ACME webroot directory exists when ACME challenges are configured.
        * Mesh config file exists when mesh is enabled.
        """
        config = self.config
        if config.server.tls.enabled:
            certfile = config.certfile_path
            keyfile = config.keyfile_path
            if not certfile or not keyfile:
                raise ConfigError("TLS is enabled but certfile/keyfile are not configured.")
            if not certfile.exists():
                raise ConfigError(f"TLS certificate not found: {certfile}")
            if not keyfile.exists():
                raise ConfigError(f"TLS private key not found: {keyfile}")
        if config.server.tls.acme_webroot:
            webroot = config.acme_webroot_path
            if webroot and not webroot.exists():
                raise ConfigError(f"ACME webroot not found: {webroot}")
        if config.mesh.enabled and config.mesh.config_path:
            mesh_path = config.mesh_config_path
            if mesh_path and not mesh_path.exists():
                raise ConfigError(f"Mesh config not found: {mesh_path}")

    def _backup_config(self) -> Path | None:
        """Create a timestamped backup of the current config file."""
        if not self.path or not self.path.exists():
            return None
        backup = self.path.with_suffix(f".{self.path.suffix}.bak")
        try:
            backup.write_bytes(self.path.read_bytes())
            return backup
        except OSError:
            return None

    def _write_text(self, text: str) -> None:
        if not self.path:
            raise ConfigError("This Warden instance is not running from a YAML file.")
        if not text.endswith("\n"):
            text += "\n"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(prefix=".warden-", suffix=".yaml", dir=self.path.parent)
        temp = Path(temp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp, 0o600)
            os.replace(temp, self.path)
        except Exception:
            temp.unlink(missing_ok=True)
            raise

    def save_text(self, text: str) -> tuple[WardenConfig, list[str]]:
        with self._lock:
            config = self.validate_text(text)
            previous = self._config
            changes = restart_required(previous, config)
            self._backup_config()
            self._write_text(text)
            # Route changes take effect immediately. Listener, TLS, database,
            # WebAuthn RP ID, and mesh changes are persisted but held back
            # until the process restarts, matching the dashboard warning and
            # avoiding a half-applied runtime state.
            self._config = _preserve_restart_fields(previous, config)
            return config, changes

    def save_raw(self, text: str) -> tuple[WardenConfig, list[str]]:
        """Alias used by the config editor API."""
        return self.save_text(text)

    def _load_document(self) -> Any:
        """Load the YAML configuration file into a ``CommentedMap``.

        Used internally by ``add_route``, ``update_route`` and ``delete_route``.
        """
        if not self.path or not self.path.exists():
            raise ConfigError("This Warden instance is not running from a YAML file.")
        yaml = YAML()
        yaml.allow_duplicate_keys = False
        yaml.indent(mapping=2, sequence=4, offset=2)
        yaml.preserve_quotes = True
        try:
            document = yaml.load(self.path.read_text(encoding="utf-8"))
        except YAMLError as exc:
            raise ConfigError("Could not parse the existing YAML file.", [str(exc)]) from exc
        if not isinstance(document, CommentedMap):
            raise ConfigError("The YAML file must contain a mapping at the top level.")
        return document

    def _save_document(self, document: Any) -> tuple[WardenConfig, list[str]]:
        """Save a possibly-modified ``document`` back to disk.

        Performs validation, writes the file atomically, and returns the new config
        and any restart‑required changes.
        """
        yaml = YAML()
        yaml.indent(mapping=2, sequence=4, offset=2)
        yaml.preserve_quotes = True
        yaml.width = 100
        from io import StringIO

        buffer = StringIO()
        yaml.dump(document, buffer)
        return self.save_text(buffer.getvalue())

    def _route_sequence(self, document: Any, create: bool = True) -> CommentedSeq:
        routes = document.get("routes")
        if routes is None:
            if not create:
                raise ConfigError("No routes are configured.")
            routes = CommentedSeq()
            document["routes"] = routes
        if not isinstance(routes, CommentedSeq):
            raise ConfigError("The 'routes' key in the YAML file must be a list.")
        return routes

    def add_route(self, route: RouteConfig) -> tuple[WardenConfig, list[str]]:
        """Append a new ``RouteConfig`` to the configuration file.

        Raises ``ConfigError`` if a route with the same host already exists.
        """
        with self._lock:
            document = self._load_document()
            routes = self._route_sequence(document)
            for item in routes:
                if isinstance(item, dict) and normalize_host(str(item.get("host", "")), allow_wildcard=True) == route.host:
                    raise ConfigError(f"A route for {route.host} already exists.")
            routes.append(
                _to_commented(
                    route.model_dump(exclude_none=True, exclude_defaults=True, mode="json")
                )
            )
            return self._save_document(document)

    def update_route(self, original_host: str, route: RouteConfig) -> tuple[WardenConfig, list[str]]:
        """Replace an existing route identified by ``original_host`` with ``route``.

        Preserves advanced fields (headers, timeout, rewrite settings) that are not
        exposed in the UI.
        """
        with self._lock:
            document = self._load_document()
            routes = self._route_sequence(document, create=False)
            for item in routes:
                if isinstance(item, dict) and str(item.get("host", "")).lower() == original_host.lower():
                    if route.host != original_host:
                        for other in routes:
                            if isinstance(other, dict) and str(other.get("host", "")).lower() == route.host.lower():
                                raise ConfigError(f"A route for {route.host} already exists.")
                    # The dashboard form does not expose every routing knob.
                    # Keep advanced fields from the YAML file instead of
                    # resetting them to model defaults on each UI edit.
                    preserved = {
                        key: item[key]
                        for key in (
                            "headers",
                            "timeout_seconds",
                            "rewrite_redirects",
                            "rewrite_cookies",
                        )
                        if key in item
                    }
                    replacement = _to_commented(
                        route.model_dump(exclude_none=True, exclude_defaults=True, mode="json")
                    )
                    for key, value in preserved.items():
                        replacement[key] = value
                    for key in [key for key in item if key not in replacement]:
                        del item[key]
                    for key, value in replacement.items():
                        item[key] = value
                    return self._save_document(document)
            raise ConfigError(f"No route found for {original_host}.")

    def delete_route(self, host: str) -> tuple[WardenConfig, list[str]]:
        """Remove a route from the configuration file.

        Raises ``ConfigError`` if the host does not exist.
        """
        with self._lock:
            document = self._load_document()
            routes = self._route_sequence(document, create=False)
            for index, item in enumerate(routes):
                if isinstance(item, dict) and str(item.get("host", "")).lower() == host.lower():
                    del routes[index]
                    return self._save_document(document)
            raise ConfigError(f"No route found for {host}.")


_RESTART_FIELDS = (
    "server.admin_host",
    "server.bind",
    "server.http_port",
    "server.https_port",
    "server.tls",
    "server.cookie_domain",
    "server.secure_cookies",
    "server.trust_proxy_headers",
    "server.external_scheme",
    "server.public_url",
    "database",
    "webauthn.rp_id",
    "mesh.enabled",
    "mesh.interface",
    "mesh.address",
    "mesh.listen_port",
    "mesh.config_path",
)


def _nested(data: dict[str, Any], dotted: str) -> Any:
    current: Any = data
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _nested_object(value: Any, dotted: str) -> Any:
    current = value
    for part in dotted.split("."):
        current = getattr(current, part)
    return current


def _set_nested_object(value: Any, dotted: str, replacement: Any) -> None:
    parts = dotted.split(".")
    current = value
    for part in parts[:-1]:
        current = getattr(current, part)
    setattr(current, parts[-1], replacement)


def _preserve_restart_fields(previous: WardenConfig, incoming: WardenConfig) -> WardenConfig:
    """Copy restart‑only fields from ``previous`` into ``incoming``.

    Fields listed in ``_RESTART_FIELDS`` require a process restart to take effect;
    this helper ensures those values are not unintentionally overwritten by a UI
    edit.
    """
    """Build the live config, holding restart-only values at their old state."""
    old_data = previous.model_dump(mode="json")
    new_data = incoming.model_dump(mode="json")
    runtime = incoming.model_copy(deep=True)
    for field in _RESTART_FIELDS:
        if _nested(old_data, field) != _nested(new_data, field):
            replacement = _nested_object(previous, field)
            _set_nested_object(runtime, field, replacement.model_copy(deep=True) if isinstance(replacement, BaseModel) else replacement)
    return runtime


def restart_required(old: WardenConfig, new: WardenConfig) -> list[str]:
    """Return a list of config fields whose changes require a process restart.

    Used by ``ConfigManager.save_text`` to determine whether a reload is necessary.
    """
    old_data = old.model_dump(mode="json")
    new_data = new.model_dump(mode="json")
    changes = []
    for field in _RESTART_FIELDS:
        if _nested(old_data, field) != _nested(new_data, field):
            changes.append(field)
    if "webauthn.rp_id" in changes:
        changes.append("webauthn.rp_id changes invalidate existing passkeys")
    return changes



