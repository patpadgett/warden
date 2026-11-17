"""Minimal SMTP email sender for Warden.

Provides ``send_email`` which wraps a lightweight SMTP client for delivering
invite tokens and other transactional mail. The module is intentionally small:
it uses stdlib ``smtplib`` and ``email.message`` only, and all SMTP details
(recipient, subject, body) are supplied by the caller. SMTP configuration is
taken from the ``EmailConfig`` model in ``config.py``.

Usage::

    from warden.mail import send_email
    from warden.config import EmailConfig

    email = EmailConfig(enabled=True, host="smtp.example.com", port=587,
                        user="user", password="pass", from_address="noreply@example.com")
    send_email(email, to="user@example.com", subject="Hello", body="World")
"""

from __future__ import annotations

import logging
import smtplib
import ssl
from email.message import EmailMessage

from warden.config import EmailConfig

logger = logging.getLogger("warden.mail")


def _build_message(email: EmailConfig, to: str, subject: str, body: str) -> EmailMessage:
    """Construct a plaintext email message with the given sender details."""
    msg = EmailMessage()
    msg["From"] = email.from_address
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    return msg


def _connect(email: EmailConfig):
    """Open an SMTP connection and authenticate, returning the SMTP client."""
    if email.ssl:
        # Implicit TLS (port 465): the connection is wrapped before the SMTP
        # greeting, so STARTTLS must not be attempted on top of it.
        client = smtplib.SMTP_SSL(
            email.host, email.port, timeout=10.0, context=ssl.create_default_context()
        )
    elif email.starttls:
        client = smtplib.SMTP(email.host, email.port, timeout=10.0)
        context = ssl.create_default_context()
        client.starttls(context=context)
    else:
        client = smtplib.SMTP(email.host, email.port, timeout=10.0)
    if email.user and email.password:
        client.login(email.user, email.password)
    return client


def send_email(email: EmailConfig, to: str, subject: str, body: str) -> None:
    """Send a single email to ``to`` using the configured SMTP server.

    Raises ``RuntimeError`` if email is not enabled or if the SMTP operation
    fails. The connection is closed after the message is sent.
    """
    if not email.enabled:
        raise RuntimeError("Email is not enabled in the configuration.")
    if not to or not to.strip():
        raise ValueError("A recipient address is required.")
    msg = _build_message(email, to, subject, body)
    client = _connect(email)
    try:
        client.send_message(msg)
    finally:
        try:
            client.quit()
        except Exception:  # noqa: BLE001
            try:
                client.close()
            except Exception as exc:  # noqa: BLE001
                logger.debug("Could not close SMTP connection: %s", exc)
