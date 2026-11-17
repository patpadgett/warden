"""Tests for the warden.mail SMTP sender."""

from __future__ import annotations

import smtplib
from email.message import EmailMessage
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from warden.config import EmailConfig
from warden.mail import send_email


def _config(**kwargs):
    defaults: dict = {
        "enabled": True,
        "host": "smtp.example.com",
        "port": 587,
        "user": "user",
        "password": "pass",
        "starttls": True,
        "from_address": "noreply@example.com",
        "subject_prefix": "Test",
    }
    defaults.update(kwargs)
    return EmailConfig(**defaults)


def test_send_email_delivers_message_with_starttls():
    cfg = _config()
    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)
    with (
        patch("warden.mail.smtplib.SMTP", return_value=mock_client) as mock_smtp,
        patch("warden.mail.ssl.create_default_context") as mock_ctx,
    ):
        send_email(cfg, "to@example.com", "Hello", "Body")

    mock_smtp.assert_called_once_with(cfg.host, cfg.port, timeout=10.0)
    mock_ctx.assert_called_once()
    mock_client.starttls.assert_called_once_with(context=mock_ctx.return_value)
    mock_client.login.assert_called_once_with(cfg.user, cfg.password)
    mock_client.send_message.assert_called_once()
    msg = mock_client.send_message.call_args[0][0]
    assert isinstance(msg, EmailMessage)
    assert msg["From"] == cfg.from_address
    assert msg["To"] == "to@example.com"
    assert msg["Subject"] == "Hello"
    assert msg.get_content() == "Body\n"


def test_send_email_without_starttls():
    cfg = _config(starttls=False)
    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)
    with patch("warden.mail.smtplib.SMTP", return_value=mock_client):
        send_email(cfg, "to@example.com", "Hello", "Body")

    mock_client.starttls.assert_not_called()
    mock_client.login.assert_called_once_with(cfg.user, cfg.password)


def test_send_email_uses_implicit_tls_when_configured():
    cfg = _config(starttls=False, ssl=True, port=465)
    mock_client = MagicMock()
    with (
        patch("warden.mail.smtplib.SMTP_SSL", return_value=mock_client) as mock_smtp,
        patch("warden.mail.ssl.create_default_context") as mock_ctx,
    ):
        send_email(cfg, "to@example.com", "Hello", "Body")

    mock_smtp.assert_called_once_with(
        cfg.host, cfg.port, timeout=10.0, context=mock_ctx.return_value
    )
    mock_client.starttls.assert_not_called()
    mock_client.login.assert_called_once_with(cfg.user, cfg.password)
    mock_client.send_message.assert_called_once()


def test_email_tls_modes_cannot_be_combined():
    with pytest.raises(ValidationError, match="cannot both be true"):
        EmailConfig(enabled=True, ssl=True, starttls=True)


def test_send_email_without_auth():
    cfg = _config(user=None, password=None)
    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)
    with patch("warden.mail.smtplib.SMTP", return_value=mock_client):
        send_email(cfg, "to@example.com", "Hello", "Body")

    mock_client.login.assert_not_called()


def test_send_email_raises_when_disabled():
    cfg = _config(enabled=False)
    with pytest.raises(RuntimeError, match="Email is not enabled"):
        send_email(cfg, "to@example.com", "Hello", "Body")


def test_send_email_propagates_smtp_failures():
    cfg = _config()
    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)
    mock_client.send_message.side_effect = smtplib.SMTPException("boom")
    with (
        patch("warden.mail.smtplib.SMTP", return_value=mock_client),
        pytest.raises(smtplib.SMTPException, match="boom"),
    ):
        send_email(cfg, "to@example.com", "Hello", "Body")

    mock_client.send_message.assert_called_once()


def test_send_email_with_special_characters():
    cfg = _config()
    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)
    with patch("warden.mail.smtplib.SMTP", return_value=mock_client):
        send_email(cfg, "to@example.com", "Subj: émojis 🎉", "Body\nwith\nnewlines")

    msg = mock_client.send_message.call_args[0][0]
    assert msg["Subject"] == "Subj: émojis 🎉"
    assert msg.get_content() == "Body\nwith\nnewlines\n"
