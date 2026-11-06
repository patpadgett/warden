"""Tests for the first-login completion UI route."""

import pytest


class TestInviteCompleteRoute:
    """Verify the first-login completion page renders and carries the invite token."""

    def test_completion_page_renders(self, client):
        """GET /_warden/invite/complete?token=... returns the completion page."""
        response = client.get("/_warden/invite/complete?token=TEST-TOKEN-123")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        # The page is rendered through the auth shell with invite_complete content
        assert "Complete your account" in response.text
        assert "First login" in response.text
        assert "Register passkey" in response.text

    def test_completion_page_includes_token_field(self, client):
        """The completion page includes a token display field."""
        response = client.get("/_warden/invite/complete?token=D392-...-K9P1Q")
        assert response.status_code == 200
        assert 'id="invite-token"' in response.text
        assert "Name this passkey" in response.text

    def test_completion_page_without_token(self, client):
        """A completion page without a token still renders."""
        response = client.get("/_warden/invite/complete")
        assert response.status_code == 200
        assert "Complete your account" in response.text
        # The page should still show the token field, empty.
        assert 'id="invite-token"' in response.text

    def test_completion_page_uses_auth_base(self, client):
        """The completion page is served through the auth base layout."""
        response = client.get("/_warden/invite/complete?token=TEST-ABC")
        assert response.status_code == 200
        assert "Complete your account" in response.text
        assert "First login" in response.text
