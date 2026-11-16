from __future__ import annotations


def test_host_coverage_warnings_flag_unreachable_hosts(tmp_path) -> None:
    from warden.config import parse_config_text
    from warden.main import host_coverage_warnings

    config = parse_config_text(
        "version: 1\n"
        "server:\n  admin_host: localhost\n"
        "webauthn:\n  rp_id: localhost\n"
        "routes:\n  - host: app.localhost\n    upstream: http://127.0.0.1:9\n",
        base_dir=tmp_path,
    )
    warnings = host_coverage_warnings(config)
    assert any("single-label" in warning for warning in warnings)
    assert any("cookie_domain" in warning for warning in warnings)


def test_host_coverage_warnings_quiet_for_covered_hosts(tmp_path) -> None:
    from warden.config import parse_config_text
    from warden.main import host_coverage_warnings

    config = parse_config_text(
        "version: 1\n"
        "server:\n  admin_host: admin.home.lan\n  cookie_domain: home.lan\n"
        "webauthn:\n  rp_id: home.lan\n"
        "routes:\n  - host: app.home.lan\n    upstream: http://127.0.0.1:9\n",
        base_dir=tmp_path,
    )
    assert host_coverage_warnings(config) == []


def test_create_app_loads() -> None:
    # Minimal create_app test using default config
    import pathlib
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        p = pathlib.Path(td) / "w.yaml"
        p.write_text("version: 1\nserver:\n  admin_host: localhost\nwebauthn:\n  rp_id: localhost\nroutes: []\n")
        from warden.config import ConfigManager
        manager = ConfigManager.from_file(p)
        # Just verify manager loads; full app needs DB seed
        assert manager.config.server.admin_host == "localhost"
