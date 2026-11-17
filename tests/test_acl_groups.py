"""Per-route ACL groups: default membership, opt-in routes, and enforcement."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import pytest
from pydantic import ValidationError
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from warden.auth.sessions import hash_token
from warden.config import RouteConfig
from warden.db import DEFAULT_ACL_GROUP, AlreadyExistsError, Database, User
from warden.main import create_app
from warden.proxy import ProxyEngine

from .conftest import admin_headers, config_dict, write_config


@pytest.fixture
async def db(tmp_path: Path):
    database = Database(tmp_path / "warden.db")
    await database.init()
    try:
        yield database
    finally:
        await database.close()


def _user(**overrides) -> User:
    values = {
        "id": 1,
        "username": "pat",
        "display_name": "Pat",
        "webauthn_user_id": b"u" * 16,
        "is_admin": False,
        "created_at": 0.0,
    }
    values.update(overrides)
    return User(**values)


def _route(**overrides) -> RouteConfig:
    values = {"host": "app.home.lan", "upstream": "http://127.0.0.1:9"}
    values.update(overrides)
    return RouteConfig(**values)


# ------------------------------------------------------------------ persistence
async def test_default_group_exists_and_create_user_joins_it(db: Database) -> None:
    groups = {group.name: group for group in await db.list_acl_groups()}
    assert DEFAULT_ACL_GROUP in groups

    user = await db.create_user("pat", "Pat", b"u" * 16, is_admin=False)
    assert user.groups == (DEFAULT_ACL_GROUP,)
    assert await db.list_user_acl_groups(user.id) == [DEFAULT_ACL_GROUP]
    assert (await db.get_acl_group_by_name(DEFAULT_ACL_GROUP)).member_count == 1


async def test_setup_and_invite_creation_path_also_joins_default_group(db: Database) -> None:
    user, _credential = await db.create_user_with_credential(
        username="robin",
        display_name="Robin",
        webauthn_user_id=b"r" * 16,
        credential_id=b"c" * 32,
        public_key=b"p" * 64,
        sign_count=1,
        transports=["internal"],
        credential_name="Laptop",
        aaguid=None,
        fmt="none",
        user_verified=True,
        backup_eligible=False,
        backup_state=False,
    )
    assert user.groups == (DEFAULT_ACL_GROUP,)


async def test_group_membership_cannot_drop_default_or_name_unknown_groups(
    db: Database,
) -> None:
    user = await db.create_user("pat", "Pat", b"u" * 16, is_admin=False)
    family = await db.create_acl_group("Family")

    with pytest.raises(AlreadyExistsError):
        await db.create_acl_group("family")

    assert await db.set_user_acl_groups(user.id, ["Family"]) == ["Family", "Users"]
    assert await db.remove_user_from_acl_group(user.id, family.id) is True
    default = await db.get_acl_group_by_name(DEFAULT_ACL_GROUP)
    assert await db.remove_user_from_acl_group(user.id, default.id) is False
    assert await db.delete_acl_group(default.id) is False

    with pytest.raises(ValueError):
        await db.set_user_acl_groups(user.id, ["Missing"])

    memberships = await db.acl_memberships()
    assert memberships[user.id] == [DEFAULT_ACL_GROUP]


# ----------------------------------------------------------------------- routes
def test_route_without_acl_is_open_to_everyone() -> None:
    route = _route()
    assert route.allowed_groups == []
    assert route.allows_user(None) is True
    assert route.allows_user(_user(groups=())) is True
    assert ProxyEngine._group_denial(route, None) is None


def test_route_acl_admits_members_and_admins_only() -> None:
    route = _route(allowed_groups=["Family"])
    member = _user(groups=("family",))
    outsider = _user(groups=(DEFAULT_ACL_GROUP,))
    admin = _user(is_admin=True, groups=())

    assert route.allows_user(member) is True
    assert route.allows_user(outsider) is False
    assert route.allows_user(admin) is True
    assert "not in a group" in (ProxyEngine._group_denial(route, outsider) or "")
    assert ProxyEngine._group_denial(route, None) is not None


def test_group_acl_requires_authentication() -> None:
    with pytest.raises(ValidationError):
        _route(auth=False, allowed_groups=["Family"])


def test_service_api_round_trips_allowed_groups(client, app_and_path) -> None:
    """The dashboard's add/edit service payload carries the route ACL."""
    app, _path = app_and_path
    headers = admin_headers(**{"X-Warden-Request": "1"})
    created = client.post(
        "/_warden/api/services",
        json={
            "host": "acl.home.lan",
            "upstream": "http://127.0.0.1:9",
            "allowed_groups": ["Users", "Family"],
        },
        headers=headers,
    )
    assert created.status_code == 200, created.text
    route = app.state.manager.config.match_route("acl.home.lan")
    assert route is not None
    assert route.allowed_groups == ["Users", "Family"]


# ------------------------------------------------------------------- end to end
def _seed_acl_users(db_path: Path) -> None:
    async def _seed() -> None:
        database = Database(db_path)
        await database.init()
        try:
            family = await database.create_acl_group("Family")
            member = await database.create_user(
                "member", "Member", b"m" * 16, is_admin=False
            )
            outsider = await database.create_user(
                "outsider", "Outsider", b"o" * 16, is_admin=False
            )
            await database.set_user_acl_groups(member.id, [family.name])
            for token, user in (("member-token", member), ("outsider-token", outsider)):
                await database.create_session(
                    hash_token(token), user.id, time.time() + 3600
                )
        finally:
            await database.close()

    asyncio.run(_seed())


def test_acl_route_enforced_for_http_portal_and_websocket(
    tmp_path: Path, upstream_server
) -> None:
    _server, upstream = upstream_server
    data = config_dict(
        tmp_path,
        routes=[
            {"host": "open.home.lan", "upstream": upstream, "name": "Open"},
            {
                "host": "family.home.lan",
                "upstream": upstream,
                "name": "Family",
                "allowed_groups": ["Family"],
            },
        ],
    )
    path = write_config(tmp_path, data)
    _seed_acl_users(tmp_path / "warden.db")

    app = create_app(path)
    with TestClient(app, base_url="http://admin.home.lan") as client:
        def headers(host: str, token: str) -> dict[str, str]:
            return {"host": host, "cookie": f"warden_session={token}"}

        # The route without an ACL keeps letting every signed-in user through.
        open_response = client.get("/", headers=headers("open.home.lan", "outsider-token"))
        assert open_response.status_code == 200
        assert "path=/" in open_response.text

        denied = client.get("/", headers=headers("family.home.lan", "outsider-token"))
        assert denied.status_code == 403
        assert "not in a group" in denied.text

        allowed = client.get("/", headers=headers("family.home.lan", "member-token"))
        assert allowed.status_code == 200
        assert "path=/" in allowed.text

        # The portal hides routes the user cannot open.
        portal_headers = {
            "host": "admin.home.lan",
            "cookie": "warden_session=outsider-token",
            "accept": "text/html",
        }
        portal = client.get("/portal", headers=portal_headers)
        assert portal.status_code == 200
        assert "open.home.lan" in portal.text
        assert "family.home.lan" not in portal.text

        # WebSockets use the same ACL, so they cannot be used to skip it.
        with (
            pytest.raises(WebSocketDisconnect) as closed,
            client.websocket_connect(
                "/", headers=headers("family.home.lan", "outsider-token")
            ) as websocket,
        ):
            websocket.receive_text()
        assert closed.value.code == 4403
