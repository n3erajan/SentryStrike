"""SMTP email behavior and configuration validation."""

import pytest

from app.config import BackendSettings
from app.core import email as email_module
from app.core.email import SmtpEmailBackend, render_workspace_invite_email


def test_smtp_backend_reports_server_acceptance_without_exposing_password(monkeypatch) -> None:
    calls = {}

    class FakeSmtp:
        def __init__(self, host, port, timeout):
            calls.update(host=host, port=port, timeout=timeout)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def ehlo(self):
            calls["ehlo"] = calls.get("ehlo", 0) + 1

        def starttls(self):
            calls["starttls"] = True

        def login(self, user, password):
            calls.update(user=user, password=password)

        def send_message(self, message):
            calls["message"] = message
            return {}

    monkeypatch.setattr(email_module.smtplib, "SMTP", FakeSmtp)
    settings = BackendSettings(
        _env_file=None,
        EMAIL_SMTP_USER="sender@example.test",
        EMAIL_SMTP_PASSWORD="app-password",
    )

    result = SmtpEmailBackend(settings).send(
        to="recipient@example.test",
        subject="Diagnostic",
        body_text="test",
        body_html="<strong>test</strong>",
    )

    assert result is None
    assert calls["user"] == "sender@example.test"
    assert calls["password"] == "app-password"
    assert calls["message"]["From"] == "sender@example.test"
    assert calls["message"].get_body(preferencelist=("plain",)).get_content().strip() == "test"
    assert (
        calls["message"].get_body(preferencelist=("html",)).get_content().strip()
        == "<strong>test</strong>"
    )


def test_workspace_invite_email_is_branded_and_escapes_dynamic_values() -> None:
    subject, body_text, body_html = render_workspace_invite_email(
        org_name="Acme <Security>",
        role="security_analyst",
        link='https://app.example.test/register?invite=a&next="<home>"',
        token="unused",
    )

    assert subject == "You're invited to join the Acme <Security> workspace on SentryStrike"
    assert "Acme <Security>" in body_text
    assert "https://app.example.test/register?invite=" in body_html
    assert "Acme &lt;Security&gt;" in body_html
    assert "Acme <Security>" not in body_html
    assert "Security Analyst" in body_html
    assert "a&amp;next=&quot;&lt;home&gt;&quot;" in body_html
    assert "#2864D7" in body_html
    assert "Accept invitation" in body_html


def test_owner_invite_email_has_token_fallback_when_no_public_link() -> None:
    _, body_text, body_html = render_workspace_invite_email(
        org_name="Acme",
        role="owner",
        link=None,
        token="raw-<token>",
        owns_workspace=True,
    )

    assert "raw-<token>" in body_text
    assert "raw-&lt;token&gt;" in body_html
    assert "Workspace owner" in body_html
    assert "Set up workspace" not in body_html


def test_smtp_configuration_rejects_only_one_credential() -> None:
    with pytest.raises(ValueError, match="must either both be set"):
        BackendSettings(
            _env_file=None,
            EMAIL_SMTP_USER="sender@example.test",
        )
