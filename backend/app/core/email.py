"""Pluggable email delivery.

Two backends share one ``EmailBackend`` interface:

* ``ConsoleEmailBackend`` — logs the full message (subject, recipient, and body,
  including any invite link) instead of sending it. The default for local dev
  and tests, so no real mail server is required to exercise the invite flow.
* ``SmtpEmailBackend`` — sends over SMTP with optional STARTTLS. Configured for
  Gmail out of the box (smtp.gmail.com:587, STARTTLS, an app password as
  ``EMAIL_SMTP_PASSWORD``).

``get_email_backend()`` selects one from ``BackendSettings`` and caches it.
"""

from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage
from functools import lru_cache

from app.config import BackendSettings, get_settings

logger = logging.getLogger(__name__)


class EmailBackend:
    """Interface for sending a single email."""

    def send(self, *, to: str, subject: str, body_text: str, body_html: str | None = None) -> None:
        raise NotImplementedError


class ConsoleEmailBackend(EmailBackend):
    """Log the message rather than sending it — for local dev and tests."""

    def __init__(self, from_address: str) -> None:
        self._from = from_address

    def send(self, *, to: str, subject: str, body_text: str, body_html: str | None = None) -> None:
        logger.info(
            "[console-email] from=%s to=%s subject=%s\n%s",
            self._from,
            to,
            subject,
            body_text,
        )


class SmtpEmailBackend(EmailBackend):
    """Send over SMTP with optional STARTTLS and authentication."""

    def __init__(self, settings: BackendSettings) -> None:
        self._settings = settings

    def send(self, *, to: str, subject: str, body_text: str, body_html: str | None = None) -> None:
        settings = self._settings
        message = EmailMessage()
        message["From"] = settings.email_from
        message["To"] = to
        message["Subject"] = subject
        message.set_content(body_text)
        if body_html:
            message.add_alternative(body_html, subtype="html")

        with smtplib.SMTP(settings.email_smtp_host, settings.email_smtp_port, timeout=30) as client:
            client.ehlo()
            if settings.email_smtp_starttls:
                client.starttls()
                client.ehlo()
            if settings.email_smtp_user and settings.email_smtp_password:
                client.login(settings.email_smtp_user, settings.email_smtp_password)
            client.send_message(message)
        logger.info("Sent email to %s (subject=%s)", to, subject)


def _build_backend(settings: BackendSettings) -> EmailBackend:
    if settings.email_backend == "smtp":
        return SmtpEmailBackend(settings)
    return ConsoleEmailBackend(settings.email_from)


@lru_cache
def get_email_backend() -> EmailBackend:
    """Return the configured email backend (cached singleton)."""
    return _build_backend(get_settings())
