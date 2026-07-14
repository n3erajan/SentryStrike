"""Shared httpx client factory for outbound scan traffic."""

from __future__ import annotations

from typing import Mapping
from urllib.parse import urljoin, urlparse

import httpx

from app.config import get_settings
from app.utils.scan_throttle import get_scan_http_semaphore


DEFAULT_SCAN_HEADERS = {"User-Agent": "SentryStrikeScanner/1.0"}


def build_httpx_evidence_snippets(
    response: httpx.Response,
    *,
    payload: str = "",
    extra_markers: list[str] | None = None,
    include_response_body: bool = True,
    max_request_body_chars: int = 2000,
) -> tuple[str | None, str | None]:
    """Reconstruct ``(request_snippet, response_snippet)`` evidence from a
    completed ``httpx.Response``.

    Detectors that call ``create_scan_client``/``httpx.AsyncClient`` directly
    (rather than going through ``HttpVerifier.send_request``) get a real
    response back but historically discarded it when building a ``Finding`` -
    the request/response evidence was left ``None`` even though a real HTTP
    exchange happened. This reads the request httpx actually sent from
    ``response.request`` (so headers/body reflect what was really
    transmitted) and reuses ``ResponseAnalyzer.build_evidence_response_snippet``
    for the response side, matching the same evidence shape ``HttpVerifier``
    produces.

    Defensive against fake/mock response objects (as used in unit tests)
    that don't carry a real ``.request``: falls back to a response-only
    snippet (or ``(None, None)``) rather than raising.
    """
    # Local import: response_analyzer lives in app.core.verification and this
    # module is imported very early (app.config / app.utils.scan_throttle);
    # importing it at module scope risks a circular import during app startup.
    from app.core.verification.response_analyzer import ResponseAnalyzer

    status_code = getattr(response, "status_code", 0)
    headers = dict(getattr(response, "headers", {}) or {})
    response_body = ""
    if include_response_body:
        try:
            response_body = response.text
        except Exception:
            response_body = ""

    response_snippet = ResponseAnalyzer.build_evidence_response_snippet(
        status_code=status_code,
        reason_phrase=getattr(response, "reason_phrase", ""),
        headers=headers,
        body=response_body,
        payload=payload,
        extra_markers=extra_markers or [],
        include_headers=True,
    )

    request = getattr(response, "request", None)
    if request is None:
        return None, response_snippet

    try:
        parsed = urlparse(str(request.url))
        req_path = parsed.path or "/"
        if parsed.query:
            req_path += f"?{parsed.query}"

        headers_str = "\n".join(f"{k}: {v}" for k, v in request.headers.items())

        body = ""
        content = request.content
        if content:
            body = content.decode("utf-8", "replace")
        if len(body) > max_request_body_chars:
            body = body[:max_request_body_chars] + "\n[...snip...]"

        request_snippet = f"{request.method} {req_path} HTTP/1.1\nHost: {parsed.netloc}\n{headers_str}\n\n{body}"
    except Exception:
        request_snippet = None

    return request_snippet, response_snippet


def build_scan_headers(auth_headers: Mapping[str, object] | None = None) -> dict[str, str]:
    """Return scanner default headers with safe auth headers layered on top."""
    headers = dict(DEFAULT_SCAN_HEADERS)
    for key, value in (auth_headers or {}).items():
        if not key or value is None:
            continue
        if str(key).lower() in {"content-length", "host", "cookie"}:
            continue
        headers[str(key)] = str(value)
    return headers


def scan_http_timeout(total: float | None = None) -> httpx.Timeout:
    settings = get_settings()
    total = total if total is not None else settings.request_timeout_seconds
    return httpx.Timeout(
        connect=min(5.0, total),
        read=total,
        write=total,
        pool=min(5.0, total),
    )


def scan_http_limits() -> httpx.Limits:
    pool_size = max(1, get_settings().scanner_concurrency)
    return httpx.Limits(
        max_connections=pool_size,
        max_keepalive_connections=pool_size,
    )


def same_origin_url(left: str, right: str) -> bool:
    try:
        left_parsed = urlparse(str(left))
        right_parsed = urlparse(str(right))
    except Exception:
        return False

    def port(parsed) -> int | None:
        if parsed.port is not None:
            return parsed.port
        if parsed.scheme in {"http", "ws"}:
            return 80
        if parsed.scheme in {"https", "wss"}:
            return 443
        return None

    return (
        left_parsed.scheme == right_parsed.scheme
        and left_parsed.hostname == right_parsed.hostname
        and port(left_parsed) == port(right_parsed)
    )


def create_scan_client(**kwargs) -> httpx.AsyncClient:
    """Create an AsyncClient that respects global scan concurrency limits."""
    default_follow_redirects = bool(kwargs.pop("follow_redirects", False))
    kwargs.setdefault("timeout", scan_http_timeout())
    kwargs.setdefault("limits", scan_http_limits())
    kwargs["follow_redirects"] = False
    client = httpx.AsyncClient(**kwargs)
    try:
        original_request = client.request
    except AttributeError:
        return client

    async def throttled_request(*args, **req_kwargs):
        follow_redirects = bool(req_kwargs.pop("follow_redirects", default_follow_redirects))
        async with get_scan_http_semaphore():
            response = await original_request(*args, **req_kwargs)
            if not follow_redirects:
                return response
            redirects_followed = 0
            while response.status_code in {301, 302, 303, 307, 308} and redirects_followed < 10:
                location = response.headers.get("location")
                if not location:
                    break
                next_url = urljoin(str(response.url), location)
                if not same_origin_url(str(response.url), next_url):
                    break
                redirects_followed += 1
                next_method = str(req_kwargs.get("method", args[0] if args else "GET")).upper()
                next_kwargs = dict(req_kwargs)
                if response.status_code == 303 or (
                    response.status_code in {301, 302} and next_method not in {"GET", "HEAD"}
                ):
                    next_method = "GET"
                    next_kwargs.pop("data", None)
                    next_kwargs.pop("json", None)
                    next_kwargs.pop("content", None)
                    next_kwargs.pop("files", None)
                next_kwargs["method"] = next_method
                next_kwargs["url"] = next_url
                response = await original_request(**next_kwargs)
            return response

    client.request = throttled_request  # type: ignore[method-assign]
    return client
