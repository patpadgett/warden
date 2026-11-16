from __future__ import annotations

from pathlib import Path

import pytest

from warden.config import (
    ConfigError,
    ConfigManager,
    RouteConfig,
    env_substitute,
    load_config,
    normalize_host,
    parse_config_text,
    restart_required,
)

from .conftest import config_dict, dump_yaml, write_config


def test_load_and_match_routes(tmp_path: Path) -> None:
    data = config_dict(
        tmp_path,
        routes=[
            {"host": "app.home.lan", "upstream": "http://127.0.0.1:3000", "name": "App"},
            {"host": "*.apps.home.lan", "upstream": "http://127.0.0.1:3001"},
            {"host": "*.media.home.lan", "upstream": "http://127.0.0.1:3002"},
        ],
        admin_host="admin.home.lan",
    )
    config = parse_config_text(dump_yaml(data), base_dir=tmp_path)

    assert config.match_route("app.home.lan").name == "App"
    assert config.match_route("media.apps.home.lan").host == "*.apps.home.lan"
    assert config.match_route("video.media.home.lan").host == "*.media.home.lan"
    assert config.match_route("home.lan") is None
    assert config.match_route("unknown.example") is None
    assert config.database_path == (tmp_path / "warden.db").resolve()


def test_validate_startup_allows_missing_mesh_config(tmp_path: Path) -> None:
    data = config_dict(
        tmp_path, mesh={"enabled": True, "config_path": str(tmp_path / "wg0.conf")}
    )
    path = write_config(tmp_path, data)
    manager = ConfigManager.from_file(path)
    # The file is written by the first "apply to host"; startup only needs the
    # directory to be usable.
    manager.validate_startup()
    assert not (tmp_path / "wg0.conf").exists()


def test_wildcard_route_under_rp_id_is_allowed(tmp_path: Path) -> None:
    data = config_dict(
        tmp_path,
        routes=[{"host": "*.apps.home.lan", "upstream": "http://127.0.0.1:3000"}],
    )
    config = parse_config_text(dump_yaml(data), base_dir=tmp_path)
    assert config.routes[0].host == "*.apps.home.lan"


def test_route_outside_rp_id_requires_public(tmp_path: Path) -> None:
    data = config_dict(
        tmp_path,
        routes=[{"host": "outside.example", "upstream": "http://127.0.0.1:3000"}],
    )
    with pytest.raises(ConfigError) as excinfo:
        parse_config_text(dump_yaml(data), base_dir=tmp_path)
    assert "outside the WebAuthn RP ID" in excinfo.value.pretty()

    data["routes"][0]["auth"] = False
    config = parse_config_text(dump_yaml(data), base_dir=tmp_path)
    assert config.routes[0].auth is False


def test_admin_host_must_share_rp_id(tmp_path: Path) -> None:
    data = config_dict(tmp_path, admin_host="warden.example.com")
    with pytest.raises(ConfigError) as excinfo:
        parse_config_text(dump_yaml(data), base_dir=tmp_path)
    assert "must be home.lan or a subdomain" in excinfo.value.pretty()


def test_wildcard_cannot_capture_admin(tmp_path: Path) -> None:
    data = config_dict(
        tmp_path,
        routes=[{"host": "*.home.lan", "upstream": "http://127.0.0.1:3000"}],
    )
    with pytest.raises(ConfigError) as excinfo:
        parse_config_text(dump_yaml(data), base_dir=tmp_path)
    assert "would capture the admin host" in excinfo.value.pretty()


def test_duplicate_routes_rejected(tmp_path: Path) -> None:
    data = config_dict(
        tmp_path,
        routes=[
            {"host": "app.home.lan", "upstream": "http://127.0.0.1:3000"},
            {"host": "app.home.lan", "upstream": "http://127.0.0.1:3001"},
        ],
    )
    with pytest.raises(ConfigError) as excinfo:
        parse_config_text(dump_yaml(data), base_dir=tmp_path)
    assert "duplicates" in excinfo.value.pretty()


def test_cookie_domain_validation(tmp_path: Path) -> None:
    data = config_dict(tmp_path, cookie_domain="home.lan")
    config = parse_config_text(dump_yaml(data), base_dir=tmp_path)
    assert config.server.cookie_domain == "home.lan"

    data["server"]["cookie_domain"] = "example.com"
    with pytest.raises(ConfigError):
        parse_config_text(dump_yaml(data), base_dir=tmp_path)


def test_normalize_host() -> None:
    assert normalize_host("App.Home.LAN.") == "app.home.lan"
    assert normalize_host("*.home.lan", allow_wildcard=True) == "*.home.lan"
    with pytest.raises(ValueError):
        normalize_host("*.home.lan")
    with pytest.raises(ValueError):
        normalize_host("http://app.home.lan")
    with pytest.raises(ValueError):
        normalize_host("app.home.lan:8080")
    with pytest.raises(ValueError):
        normalize_host("*foo.home.lan", allow_wildcard=True)


def test_config_manager_add_update_delete(tmp_path: Path) -> None:
    data = config_dict(
        tmp_path,
        routes=[
            {
                "host": "app.home.lan",
                "upstream": "http://127.0.0.1:9",
                "name": "App",
                "headers": {"X-Test": "kept"},
                "timeout_seconds": 12,
            }
        ],
    )
    path = write_config(tmp_path, data)
    path.write_text("# keep this comment\n" + path.read_text())
    manager = ConfigManager.from_file(path)

    manager.add_route(
        RouteConfig(
            host="new.home.lan",
            upstream="http://127.0.0.1:4000",
            name="New",
        )
    )
    assert manager.config.match_route("new.home.lan") is not None
    assert path.read_text().startswith("# keep this comment")

    manager.update_route(
        "app.home.lan",
        RouteConfig(
            host="app.home.lan",
            upstream="http://127.0.0.1:5000",
            name="Renamed",
        ),
    )
    updated = manager.config.match_route("app.home.lan")
    assert updated is not None
    assert updated.upstream == "http://127.0.0.1:5000"
    assert updated.headers == {"X-Test": "kept"}
    assert updated.timeout_seconds == 12

    manager.delete_route("new.home.lan")
    assert manager.config.match_route("new.home.lan") is None
    assert "new.home.lan" not in path.read_text()


def test_route_changes_apply_live_but_server_changes_wait(tmp_path: Path) -> None:
    data = config_dict(tmp_path)
    path = write_config(tmp_path, data)
    manager = ConfigManager.from_file(path)

    manager.add_route(
        RouteConfig(host="live.home.lan", upstream="http://127.0.0.1:3000")
    )
    assert manager.config.match_route("live.home.lan") is not None

    changed = config_dict(tmp_path, admin_host="console.home.lan")
    new_config, restart = manager.save_text(dump_yaml(changed))

    assert "server.admin_host" in restart
    assert changed["server"]["admin_host"] == new_config.server.admin_host
    # The running app keeps the old value until it restarts.
    assert manager.config.server.admin_host == "admin.home.lan"
    assert load_config(path).server.admin_host == "console.home.lan"
    # Route changes from the same save are live.
    assert manager.config.match_route("app.home.lan") is not None


def test_restart_required_lists_rp_id_consequence(tmp_path: Path) -> None:
    old = parse_config_text(dump_yaml(config_dict(tmp_path)), base_dir=tmp_path)
    data = config_dict(tmp_path)
    data["webauthn"]["rp_id"] = "lan"
    new = parse_config_text(dump_yaml(data), base_dir=tmp_path)
    changes = restart_required(old, new)
    assert "webauthn.rp_id" in changes
    assert any("invalidate existing passkeys" in item for item in changes)


def test_invalid_yaml_reports_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError) as excinfo:
        parse_config_text("routes: [\n", base_dir=tmp_path)
    assert "Could not parse" in excinfo.value.message

    with pytest.raises(ConfigError) as excinfo:
        parse_config_text("[]", base_dir=tmp_path)
    assert "mapping" in excinfo.value.message


def test_config_manager_without_file_rejects_writes(tmp_path: Path) -> None:
    config = parse_config_text(dump_yaml(config_dict(tmp_path)), base_dir=tmp_path)
    manager = ConfigManager(config, None)
    with pytest.raises(ConfigError):
        manager.read_text()
    with pytest.raises(ConfigError):
        manager.save_text(dump_yaml(config_dict(tmp_path)))


def test_env_var_substitution_strings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WARDEN_TEST_UPSTREAM", "http://127.0.0.1:9000")
    data = {
        "server": {
            "bind": "0.0.0.0",
            "http_port": 8080,
            "https_port": 8443,
        },
        "routes": [
            {
                "host": "test.home.lan",
                "upstream": "${WARDEN_TEST_UPSTREAM}",
                "name": "Test",
                "auth": False,
            },
        ],
    }
    config = parse_config_text(dump_yaml(data), base_dir=tmp_path)
    assert config.routes[0].upstream == "http://127.0.0.1:9000"


def test_env_var_substitution_missing_keeps_placeholder(tmp_path: Path) -> None:
    data = {
        "server": {
            "bind": "0.0.0.0",
            "http_port": 8080,
            "https_port": 8443,
        },
        "routes": [
            {
                "host": "test.home.lan",
                "upstream": "http://localhost:9000",
                "name": "Test",
                "auth": False,
            },
        ],
    }
    config = parse_config_text(dump_yaml(data), base_dir=tmp_path)
    assert config.routes[0].upstream == "http://localhost:9000"


def test_env_substitute_replaces_var() -> None:
    import os

    os.environ["WARDEN_TEST_VAR"] = "replaced"
    assert env_substitute("hello ${WARDEN_TEST_VAR} world") == "hello replaced world"
    assert env_substitute("hello $WARDEN_TEST_VAR world") == "hello replaced world"
    assert env_substitute("hello ${MISSING} world") == "hello ${MISSING} world"
    del os.environ["WARDEN_TEST_VAR"]
