"""Regression tests for evidence-snippet secret redaction.

Focus: session/credential cookies must be masked across frameworks, while
benign cookie crumbs (language, theme, feature flags) stay visible so evidence
remains readable.
"""

import pytest

from app.utils.redaction import REDACTED, redact_secrets


@pytest.mark.parametrize(
    "cookie_name",
    [
        # framework session cookies whose marker is concatenated (no word
        # boundary) — the historic \b-anchored regex missed all of these.
        "PHPSESSID",
        "JSESSIONID",
        "ASPSESSIONIDABCD",
        "ASP.NET_SessionId",
        "laravel_session",
        "ci_session",
        "connect.sid",
        "sails.sid",
        "CFID",
        "CFTOKEN",
        # generic session / auth / csrf / secret identifiers
        "session",
        "sessionid",
        "sid",
        "XSRF-TOKEN",
        "csrftoken",
        "access_token",
        "refresh_token",
        "remember_me",
        "__Host-session",
        "api_key",
        "apikey",
        "JWT",
    ],
)
def test_session_cookie_value_is_masked(cookie_name):
    line = f"Cookie: {cookie_name}=s3cr3tv4lue123456"
    out = redact_secrets(line)
    assert "s3cr3tv4lue123456" not in out
    assert out == f"Cookie: {cookie_name}={REDACTED}"


@pytest.mark.parametrize(
    "cookie_name",
    [
        "language",
        "theme",
        "security",  # e.g. a difficulty/feature-level flag — not a secret
        "lang",
        "currency",
        "timezone",
        "consent",
        "locale",
        "country",
        "ab_test",
        "darkmode",
    ],
)
def test_benign_cookie_value_stays_visible(cookie_name):
    line = f"Cookie: {cookie_name}=somevalue"
    assert redact_secrets(line) == line


def test_mixed_cookie_masks_only_sensitive_crumbs():
    line = "Cookie: security=low; PHPSESSID=2klr2isjk06a912m96as; theme=dark"
    out = redact_secrets(line)
    assert "2klr2isjk06a912m96as" not in out
    assert out == f"Cookie: security=low; PHPSESSID={REDACTED}; theme=dark"


def test_set_cookie_attributes_are_preserved():
    line = "Set-Cookie: JSESSIONID=ABC123XYZ; Path=/; HttpOnly; Secure"
    out = redact_secrets(line)
    assert "ABC123XYZ" not in out
    assert out == f"Set-Cookie: JSESSIONID={REDACTED}; Path=/; HttpOnly; Secure"


def test_redaction_is_idempotent():
    line = "Cookie: PHPSESSID=abcdef123456"
    once = redact_secrets(line)
    assert redact_secrets(once) == once


@pytest.mark.parametrize(
    "text",
    [
        (
            "Extension-filter bypass: "
            "http://target.test/ftp/package.json.bak is forbidden"
        ),
        "SQLITE_ERROR: unrecognized token: 'sentry_probe'",
        "Navigation compass: north",
    ],
)
def test_prose_labels_are_not_treated_as_credential_fields(text):
    assert redact_secrets(text) == text


@pytest.mark.parametrize(
    "text",
    [
        '{"password":"hunter2"}',
        "password=hunter2&user=test",
        "password: hunter2",
        "{password: hunter2}",
    ],
)
def test_structured_credential_fields_remain_redacted(text):
    output = redact_secrets(text)

    assert "hunter2" not in output
    assert REDACTED in output
