"""Request-snippet rendering: the canonical HTTP request line + Host + headers
+ body shape produced by ``build_observed_request_snippet`` and the
``build_httpx_evidence_snippets`` fallback. These guard against the
divergence/missing-snippet regressions where verified HTTP findings rendered
bare stubs or ``None`` in the report.
"""

import httpx
import pytest

from app.core.verification.verification_framework import HttpVerifier
from app.utils.scan_http import build_httpx_evidence_snippets, build_observed_request_snippet


class _FakeResponse:
    """Minimal stand-in for an httpx.Response with no captured ``.request``.

    Mirrors the mock responses used in unit tests (and real responses whose
    ``.request`` was lost): ``status_code``/``headers``/``text`` present, but
    ``request`` is None, so the request snippet must come from a caller-supplied
    fallback or be ``None``.
    """

    def __init__(self, *, status_code: int = 200, body: str = "", headers=None):
        self.status_code = status_code
        self.reason_phrase = ""
        self.headers = headers or {"content-type": "application/json"}
        self.text = body
        self.request = None


def test_build_observed_request_snippet_renders_full_shape() -> None:
    snippet = build_observed_request_snippet(
        url="http://localhost:3000/api/Users/",
        method="POST",
        headers={
            "Authorization": "Bearer secret",
            "content-type": "application/json",
            "origin": "http://localhost:3000",
        },
        body={"email": "a@b.com", "password": "p"},
    )
    assert snippet is not None
    # Canonical request line + Host, then header lines, then blank line + body.
    assert snippet.startswith("POST /api/Users/ HTTP/1.1\nHost: localhost:3000\n")
    assert "Authorization: Bearer secret" in snippet
    assert "Content-Type: application/json" in snippet
    assert "Origin: http://localhost:3000" in snippet
    assert '"email":"a@b.com"' in snippet  # JSON body, compact separators


def test_build_observed_request_snippet_deduplicates_headers_and_adds_cookies() -> None:
    snippet = build_observed_request_snippet(
        url="http://localhost:3000/search?q=test",
        headers={
            "Host": "stale.example",
            "host": "other.example",
            "User-Agent": "SentryStrikeScanner/1.0",
            "user-agent": "Mozilla/5.0 HeadlessChrome/140",
            "Authorization": "Bearer stale",
            "authorization": "Bearer current",
        },
        cookies={"session": "abc", "language": "en"},
    )

    assert snippet is not None
    assert snippet.lower().count("\nhost:") == 1
    assert snippet.lower().count("\nuser-agent:") == 1
    assert "User-Agent: Mozilla/5.0 HeadlessChrome/140" in snippet
    assert snippet.lower().count("\nauthorization:") == 1
    assert "Authorization: Bearer current" in snippet
    assert "Cookie: session=abc; language=en" in snippet


def test_build_observed_request_snippet_returns_none_without_url() -> None:
    assert build_observed_request_snippet(url="", method="GET") is None
    assert build_observed_request_snippet(url=None, method="GET") is None  # type: ignore[arg-type]


def test_build_observed_request_snippet_emits_request_line_even_if_body_fails() -> None:
    # A non-serialisable body must not collapse the whole snippet to None.
    snippet = build_observed_request_snippet(
        url="http://localhost:3000/api/Feedbacks/",
        method="POST",
        headers={"User-Agent": "Sentry/2.0"},
        body=object(),  # not dict/list/str -> str() works, but proves resilience
    )
    assert snippet is not None
    assert snippet.startswith("POST /api/Feedbacks/ HTTP/1.1\nHost: localhost:3000\n")
    assert "User-Agent: Sentry/2.0" in snippet


def test_build_httpx_evidence_snippets_falls_back_when_request_missing() -> None:
    response = _FakeResponse(body='{"ok": true}')
    req, resp = build_httpx_evidence_snippets(
        response,
        payload="sentry_xxe.xml",
        fallback_url="http://localhost:3000/file-upload",
        fallback_method="POST",
        fallback_headers={"User-Agent": "SentryStrikeScanner/1.0"},
        fallback_body="sentry_xxe.xml",
    )
    # No more silent None on the request side when the caller supplied parts.
    assert req is not None
    assert req.startswith("POST /file-upload HTTP/1.1\nHost: localhost:3000\n")
    assert "sentry_xxe.xml" in req
    # Response side still rendered.
    assert resp is not None
    assert "200" in resp


def test_build_httpx_evidence_snippets_returns_none_request_when_no_fallback() -> None:
    response = _FakeResponse(body='{"ok": true}')
    req, resp = build_httpx_evidence_snippets(response, payload="x")
    # Mock response with request=None and no fallback -> request side None,
    # response side still present (preserves existing mock-test behavior).
    assert req is None
    assert resp is not None


class _BrokenRequestResponse:
    """A response whose ``.request`` exists but raises when rendered (e.g.
    ``request.content`` decoding or header iteration throws). This is the
    silent-None failure mode that previously dropped real upload/XXE probes
    from the report even though a fallback was supplied."""

    def __init__(self, *, status_code: int = 200, body: str = "", headers=None):
        self.status_code = status_code
        self.reason_phrase = ""
        self.headers = headers or {"content-type": "application/json"}
        self.text = body
        # A request object whose .content raises, simulating a real httpx
        # response whose captured request can't be rendered.
        self.request = _BrokenRequest()


class _BrokenRequest:
    url = "http://localhost:3000/file-upload"
    method = "POST"

    @property
    def content(self):  # type: ignore[override]
        raise ValueError("content unavailable")

    @property
    def headers(self):  # type: ignore[override]
        raise ValueError("headers unavailable")


def test_build_httpx_evidence_snippets_falls_back_when_request_render_fails() -> None:
    response = _BrokenRequestResponse(body='{"ok": true}')
    req, resp = build_httpx_evidence_snippets(
        response,
        payload="sentry_xxe.xml",
        fallback_url="http://localhost:3000/file-upload",
        fallback_method="POST",
        fallback_headers={"User-Agent": "SentryStrikeScanner/1.0"},
        fallback_body="sentry_xxe.xml",
    )
    # The captured .request failed to render, but the caller-supplied fallback
    # keeps the request evidence in the report instead of silently dropping it.
    assert req is not None
    assert req.startswith("POST /file-upload HTTP/1.1\nHost: localhost:3000\n")
    assert "sentry_xxe.xml" in req
    assert resp is not None


@pytest.mark.asyncio
async def test_http_verifier_evidence_uses_effective_wire_headers_and_cookies() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True}, request=request)

    verifier = HttpVerifier(
        headers={
            "User-Agent": "SentryStrikeScanner/1.0",
            "Authorization": "Bearer scanner-default",
        },
        cookies={"session": "abc"},
    )
    verifier._client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        headers=verifier.headers,
        cookies=verifier.cookies,
    )
    try:
        response = await verifier.send_request(
            "http://localhost:3000/api/profile",
            headers={
                "user-agent": "Mozilla/5.0 HeadlessChrome/140",
                "authorization": "Bearer observed",
            },
        )
    finally:
        await verifier.close()

    snippet = response.request_snippet
    assert snippet is not None
    assert snippet.lower().count("\nhost:") == 1
    assert snippet.lower().count("\nuser-agent:") == 1
    assert "User-Agent: Mozilla/5.0 HeadlessChrome/140" in snippet
    assert snippet.lower().count("\nauthorization:") == 1
    assert "Authorization: Bearer observed" in snippet
    assert "Cookie: session=abc" in snippet
