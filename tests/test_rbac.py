import pytest
from pathlib import Path
from warden.db import Database, Role
from .test_db import make_user

@pytest.fixture
async def db(tmp_path: Path):
    database = Database(tmp_path / "warden.db")
    await database.init()
    try:
        yield database
    finally:
        await database.close()

@pytest.mark.asyncio
async def test_rbac_flow(db):
    # Create a role
    role = await db.create_role("admin", "Administrator role")
    assert isinstance(role, Role)
    assert role.name == "admin"

    # Create a user
    user, _ = await make_user(db)

    # Assign role to user
    await db.assign_role(user.id, role.id)

    # Verify role assignment
    has_role = await db.user_has_role(user.id, "admin")
    assert has_role is True

    # List user roles
    roles = await db.list_user_roles(user.id)
    assert any(r.name == "admin" for r in roles)

    # Assign same role again should be idempotent (no duplicate error)
    await db.assign_role(user.id, role.id)

    # Remove role from user
    await db.remove_role(user.id, role.id)
    has_role = await db.user_has_role(user.id, "admin")
    assert has_role is False

    # Delete role
    await db.delete_role(role.id)
    assert await db.get_role(role.id) is None
