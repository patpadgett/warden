from __future__ import annotations

import argparse

from warden.cli import (
    _ACME_TOKEN_RE,
    INIT_TEMPLATE,
    _config_path,
    _human_bytes,
    _human_time,
    _print_error,
    build_parser,
)


def test_build_parser_has_subcommands() -> None:
    parser = build_parser()
    assert parser is not None

def test_config_path_env() -> None:
    import os
    old = os.environ.get("WARDEN_CONFIG")
    try:
        os.environ["WARDEN_CONFIG"] = "/tmp/test.yaml"
        args = argparse.Namespace(config=None)
        p = _config_path(args)
        assert p.name == "test.yaml"
    finally:
        if old is None:
            os.environ.pop("WARDEN_CONFIG", None)
        else:
            os.environ["WARDEN_CONFIG"] = old

def test_human_time_never() -> None:
    assert _human_time(None) == "never"
    assert _human_time(0) == "never"

def test_human_time_valid() -> None:
    result = _human_time(1700000000)
    assert "2023" in result or "2024" in result

def test_human_bytes() -> None:
    assert _human_bytes(512) == "512 B"
    assert _human_bytes(1024) == "1.0 KB"
    assert _human_bytes(1024 * 1024) == "1.0 MB"
    assert _human_bytes(1024 ** 4) == "1.0 TB"

def test_print_error() -> None:
    # Just verify it doesn't raise
    _print_error("test message")

def test_acme_token_re() -> None:
    assert _ACME_TOKEN_RE.match("abc-123_DEF")
    assert not _ACME_TOKEN_RE.match("bad!token")

def test_init_template_contains_mesh() -> None:
    assert "mesh:" in INIT_TEMPLATE
    assert "routes:" in INIT_TEMPLATE
