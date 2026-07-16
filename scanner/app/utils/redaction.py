"""Secret redaction for evidence snippets.

The scanner authenticates to the target with real credentials (session tokens,
cookies, and the user-submitted account password). Those values are echoed back
into request/response evidence snippets and would otherwise be persisted in the
stored report and PDF verbatim — a durable credential leak that outlives the
scan session and cannot be undone by logging the session out.

``redact_secrets`` masks secret *values* while preserving surrounding structure
(header names, field keys, JSON shape) so the evidence stays readable and human
reviewers can still see *what kind* of secret was present. Redaction is purely
structural/pattern-based, so it holds for any target framework — nothing here is
specific to a particular application, header, or token format.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

REDACTED = "[REDACTED]"

# Header lines whose entire value is a credential. The header NAME is kept (so
# reviewers and auth-context classification still see "Authorization:"/"Cookie:")
# and only the value after the colon is masked.
_SENSITIVE_HEADER_RE = re.compile(
    r"(?im)^([ \t]*(?:authorization|proxy-authorization|www-authenticate|"
    r"x-api-key|api-key|x-auth-token|x-access-token|x-amz-security-token|"
    r"authentication|x-csrf-token|x-xsrf-token)[ \t]*:[ \t]*)(.+)$"
)

# Cookie / Set-Cookie lines: mask only the crumbs whose name looks like a
# session/credential token, leaving benign crumbs (e.g. ``language=en``) intact.
_COOKIE_HEADER_RE = re.compile(r"(?im)^([ \t]*(?:set-)?cookie[ \t]*:[ \t]*)(.+)$")
_SENSITIVE_COOKIE_NAME_RE = re.compile(
    r"(?i)\b(token|session|sess|jwt|auth|sid|csrf|xsrf|access|refresh|bearer|"
    r"secret|api[_-]?key|connect\.sid|remember)\b"
)

# JWT: three base64url segments. The JOSE header is base64 of ``{"...`` so real
# JWTs begin with ``eyJ`` — precise enough to avoid masking ordinary dotted text.
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]+")

# Credential-labeled fields in JSON / form / query bodies. Framework-agnostic:
# keys are the near-universal credential field names, not any app's schema. Only
# scalar-valued keys are listed (never ``auth``/``credentials`` which commonly
# hold nested objects) so a match is always a leaf value. The key and its quoting
# are preserved; only the value is replaced.
_CRED_FIELD_RE = re.compile(
    r"""(?ix)
    (                                   # group 1: key + separator (kept)
        ["']?
        (?:password|passwd|pwd|pass|secret|token|api[_-]?key|apikey|
           client_secret|access_token|refresh_token|otp|totp)
        ["']?
        \s* [:=] \s*
    )
    (                                   # group 2: value (masked)
        "(?:[^"\\]|\\.)*"               #   "double-quoted"
        | '(?:[^'\\]|\\.)*'             #   'single-quoted'
        | [^\s,&}\]]+                   #   bare token
    )
    """
)


def _mask_cred_field(match: re.Match) -> str:
    # Idempotent: never re-mask a value already redacted (e.g. a cookie crumb
    # this pass would otherwise re-match and corrupt with a trailing bracket).
    # The value class stops before ``]`` so an already-masked value arrives here
    # as ``[REDACTED`` — match on the bare marker word, not the bracketed form.
    if "REDACTED" in match.group(2):
        return match.group(0)
    return match.group(1) + REDACTED


def _mask_cookie_value(match: re.Match) -> str:
    prefix, value = match.group(1), match.group(2)
    crumbs = value.split(";")
    out: list[str] = []
    for crumb in crumbs:
        name, sep, _val = crumb.partition("=")
        if sep and _SENSITIVE_COOKIE_NAME_RE.search(name):
            out.append(f"{name}={REDACTED}")
        else:
            out.append(crumb)
    return prefix + ";".join(out)


def redact_secrets(text: str | None, extra_secrets: Iterable[str] = ()) -> str | None:
    """Return *text* with credential values masked.

    ``extra_secrets`` are exact literal values (e.g. the account password the
    scan used) masked wherever they appear — this catches secrets in oddly-named
    fields that the generic patterns would miss. Values shorter than 3 chars are
    ignored to avoid masking incidental substrings.
    """
    if not text:
        return text

    redacted = _SENSITIVE_HEADER_RE.sub(lambda m: m.group(1) + REDACTED, text)
    redacted = _COOKIE_HEADER_RE.sub(_mask_cookie_value, redacted)
    redacted = _JWT_RE.sub(REDACTED, redacted)
    redacted = _CRED_FIELD_RE.sub(_mask_cred_field, redacted)

    for secret in extra_secrets:
        if secret and len(str(secret)) >= 3:
            redacted = redacted.replace(str(secret), REDACTED)

    return redacted
