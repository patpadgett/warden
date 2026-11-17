"""Tests for invite auth route error paths."""

from __future__ import annotations

import time

import pytest


class TestInviteBeginRoute:
    """Exercise error branches in POST /_warden/auth/invite/begin."""

    def test_missing_token(self, client):
        """A missing invite token is rejected."""
        response = client.post(
            "/_warden/auth/invite/begin",
            headers={"origin": "http://admin.home.lan"},
            json={},
        )
        assert response.status_code == 400
        assert "field required" in response.json()["detail"].lower()

    def test_empty_token(self, client):
        """An empty invite token is rejected."""
        response = client.post(
            "/_warden/auth/invite/begin",
            headers={"origin": "http://admin.home.lan"},
            json={"token": "   "},
        )
        assert response.status_code == 400
        assert "invite token" in response.json()["detail"].lower()

    def test_invalid_token(self, client):
        """A token that does not match any invite is rejected."""
        response = client.post(
            "/_warden/auth/invite/begin",
            headers={"origin": "http://admin.home.lan"},
            json={"token": "NONEXISTENT-TOKEN"},
        )
        assert response.status_code == 400
        assert "invalid" in response.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_expired_invite(self, app_and_path, client):
        """An expired invite is rejected."""
        app, _ = app_and_path
        db = app.state.db

        user = await db.create_user("expired", "Expired", b"e" * 16, is_admin=False)
        token = "EXPIRED-INVITE-123"
        await db.create_invite(user.id, token, time.time() - 3600)

        response = client.post(
            "/_warden/auth/invite/begin",
            headers={"origin": "http://admin.home.lan"},
            json={"token": token},
        )
        assert response.status_code == 400
        assert "invalid" in response.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_used_invite(self, app_and_path, client):
        """A used invite is rejected."""
        app, _ = app_and_path
        db = app.state.db

        username = f"used-invite-{int(time.time() * 1000)}"
        user = await db.create_user(username, "Used", b"U" * 16, is_admin=False)
        token = f"USED-INVITE-{user.id}"
        invite_id = await db.create_invite(user.id, token, time.time() + 3600)
        await db.mark_invite_used(invite_id)

        response = client.post(
            "/_warden/auth/invite/begin",
            headers={"origin": "http://admin.home.lan"},
            json={"token": token},
        )
        assert response.status_code == 400
        assert "invalid" in response.json()["detail"].lower()

    def test_origin_check_failure(self, client):
        """Cross-origin requests are rejected."""
        response = client.post(
            "/_warden/auth/invite/begin",
            headers={"origin": "http://evil.example.com"},
            json={"token": "any-token"},
        )
        assert response.status_code == 403
        assert "cross-origin" in response.json()["detail"].lower()
