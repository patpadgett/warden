from __future__ import annotations
import pytest
from warden.auth.passkeys import (
    normalize_display_name, normalize_setup_code, hash_setup_code,
    generate_setup_code, USERNAME_RE, AuthError, DEFAULT_SETUP_HELP,
)

def test_normalize_display_name_fallback() -> None:
    assert normalize_display_name(None, "Alice") == "Alice"
    assert normalize_display_name("  ", "Bob") == "Bob"

def test_normalize_display_name_trunc() -> None:
    with pytest.raises(AuthError, match="80 characters"):
        normalize_display_name("A" * 81, "Alice")

def test_normalize_setup_code() -> None:
    result = normalize_setup_code("abcd-efgh-ijkl!")
    assert "-" not in result  # hyphens removed by regex
    assert result == "ABCDEFGHIJKL"

def test_normalize_setup_code_uppercase() -> None:
    result = normalize_setup_code("abcd-efgh-ijkl")
    assert result.replace("-", "") == "ABCDEFGHIJKL"

def test_hash_setup_code() -> None:
    h = hash_setup_code("test")
    assert len(h) == 64  # sha256 hex length

def test_generate_setup_code_format() -> None:
    code = generate_setup_code()
    parts = code.split("-")
    assert len(parts) == 3
    assert all(len(p) == 4 for p in parts)

def test_default_setup_help_contains_text() -> None:
    assert "WARDEN_SETUP_TOKEN" in DEFAULT_SETUP_HELP

def test_username_re() -> None:
    assert USERNAME_RE.match("alice")
    assert USERNAME_RE.match("alice_1")
    assert not USERNAME_RE.match("alice!")
    assert not USERNAME_RE.match("")
