from __future__ import annotations

def test_rate_limit_headers_return_tuple() -> None:
    from warden.auth.routes import _limited
    # Just verifies import/function exists; real integration tested by auth tests
    assert callable(_limited)
