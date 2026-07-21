"""Email backend selection and behavior."""

import logging

from app.config import BackendSettings
from app.core.email import ConsoleEmailBackend, SmtpEmailBackend, _build_backend


def test_console_backend_logs_message_including_body(caplog) -> None:
    backend = ConsoleEmailBackend("SentryStrike <no-reply@example.test>")
    with caplog.at_level(logging.INFO):
        backend.send(
            to="invitee@example.test",
            subject="You're invited",
            body_text="Accept here: https://sentry.example.com/signup?invite=tok",
        )

    logged = caplog.text
    assert "invitee@example.test" in logged
    assert "You're invited" in logged
    # The invite link must be visible so a dev can complete the flow without SMTP.
    assert "https://sentry.example.com/signup?invite=tok" in logged


def test_build_backend_selects_console_by_default() -> None:
    settings = BackendSettings(_env_file=None, EMAIL_BACKEND="console")
    assert isinstance(_build_backend(settings), ConsoleEmailBackend)


def test_build_backend_selects_smtp_when_configured() -> None:
    settings = BackendSettings(_env_file=None, EMAIL_BACKEND="smtp")
    assert isinstance(_build_backend(settings), SmtpEmailBackend)
