from __future__ import annotations

from warden.config import RouteConfig, normalize_path


def _route(**overrides: object) -> RouteConfig:
    data: dict[str, object] = {"host": "app.home.lan", "upstream": "http://127.0.0.1:9"}
    data.update(overrides)
    return RouteConfig(**data)


def test_normalize_path_collapses_dot_segments_and_slashes() -> None:
    assert normalize_path("/") == "/"
    assert normalize_path("") == "/"
    assert normalize_path("public/app.js") == "/public/app.js"
    assert normalize_path("/public//app.js") == "/public/app.js"
    assert normalize_path("/public/./app.js") == "/public/app.js"
    assert normalize_path("/public/../secret") == "/secret"
    assert normalize_path("/../../secret") == "/secret"
    assert normalize_path("/secret/") == "/secret"


def test_public_paths_match_the_normalised_path() -> None:
    route = _route(public_paths=["/public", "/public/*", "/assets/*"])

    assert route.is_public_path("/public")
    assert route.is_public_path("/public/app.js")
    assert route.is_public_path("/assets//logo.png")
    assert route.is_public_path("/public/./app.js")

    assert not route.is_public_path("/private")
    assert not route.is_public_path("/public/../private")
    assert not route.is_public_path("/../private")

    # Case-insensitive: an upstream that ignores case must not turn a bypass
    # into an auth hole just because the browser capitalised the path.
    assert route.is_public_path("/PUBLIC/app.js")
    assert route.is_public_path("/Assets/logo.png")


def test_public_prefix_cannot_be_escaped_with_dot_segments() -> None:
    """A ``/webhooks/*`` bypass must not expose ``/admin``.

    Warden forwards the raw path and the upstream collapses ``.``/``..``, so a
    check on the raw path is an authentication hole.
    """
    route = _route(public_paths=["/webhooks/*"])

    assert route.is_public_path("/webhooks/github")
    for path in (
        "/webhooks/../admin",
        "/webhooks/./../admin",
        "//webhooks/../admin",
        "/webhooks/github/../../admin",
    ):
        assert not route.is_public_path(path), path
