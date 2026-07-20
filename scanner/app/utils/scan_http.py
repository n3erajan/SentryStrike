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
    fallback_url: str | None = None,
    fallback_method: str | None = None,
    fallback_headers: Mapping[str, object] | None = None,
    fallback_body: object = None,
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
    that don't carry a real ``.request``: when a caller supplies the
    ``fallback_*`` parts (the url/method/headers/body it used to build the
    request), the request snippet is reconstructed from those via
    :func:`build_observed_request_snippet` so a real probe never loses its
    request evidence; with no fallback, the request side falls back to
    ``None`` (and the response side is still returned) rather than raising.
    """
    # Local import: response_analyzer lives in app.core.verification and this
    # module is imported very early by scanner configuration/throttle helpers;
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

    try:
        request = response.request
    except Exception:
        request = None
    if request is None:
        # No captured httpx request (mock response, or a response object that
        # lost its .request). If the caller supplied the request parts it
        # built the probe from, render the snippet from those so a real HTTP
        # exchange doesn't vanish from the report. Otherwise the request side
        # genuinely isn't reconstructable -> None.
        if fallback_url:
            fallback_snippet = build_observed_request_snippet(
                url=fallback_url,
                method=fallback_method or "GET",
                headers=fallback_headers,
                body=fallback_body,
                max_body_chars=max_request_body_chars,
            )
            return fallback_snippet, response_snippet
        return None, response_snippet

    try:
        request_snippet = build_httpx_request_snippet(
            request,
            max_body_chars=max_request_body_chars,
        )
    except Exception:
        # Rendering the captured .request failed. Fall back to the caller-
        # supplied parts (if any) before dropping to None, so a real HTTP
        # exchange doesn't silently lose its request evidence.
        if fallback_url:
            request_snippet = build_observed_request_snippet(
                url=fallback_url,
                method=fallback_method or "GET",
                headers=fallback_headers,
                body=fallback_body,
                max_body_chars=max_request_body_chars,
            )
        else:
            request_snippet = None

    return request_snippet, response_snippet


def build_httpx_request_snippet(
    request: object,
    *,
    max_body_chars: int = 2000,
) -> str | None:
    """Render the effective request prepared/sent by httpx."""
    content = getattr(request, "content", b"")
    body = content.decode("utf-8", "replace") if content else ""
    return build_observed_request_snippet(
        url=str(request.url),
        method=str(request.method),
        headers=dict(request.headers),
        body=body,
        max_body_chars=max_body_chars,
    )


def build_observed_request_snippet(
    *,
    url: str,
    method: str = "GET",
    headers: Mapping[str, object] | None = None,
    cookies: Mapping[str, object] | None = None,
    body: object = None,
    max_body_chars: int = 2000,
) -> str | None:
    """Reconstruct a request-snippet from an OBSERVED request's parts.

    Some findings are derived from a request the browser/crawler already sent
    (an observed XHR, a mined API endpoint, a recorded login recipe) rather than
    from a live ``httpx.Response`` the detector holds. Those detectors have the
    url/method/headers/body on hand but historically left
    ``verification_request_snippet`` empty, so a genuine request-backed finding
    rendered with no request evidence. This produces the same
    ``{METHOD} {path} HTTP/1.1`` shape ``HttpVerifier.send_request`` emits, so
    the report's request evidence is consistent regardless of source.

    Returns ``None`` only when there is no usable URL. Any other render
    failure (an unparseable body/header shape) still yields at least the
    request line + Host, so a real observed request never collapses to
    ``None`` and leaves the report with no request evidence. Secret
    redaction is applied downstream at report-build time, so raw values
    may be passed here.
    """
    import json as _json

    if not url:
        return None
    try:
        parsed = urlparse(str(url))
        req_path = parsed.path or "/"
        if parsed.query:
            req_path += f"?{parsed.query}"
        method_str = (str(method) or "GET").upper()
        # The request line + Host is the irreducible minimum; always emit it
        # so the snippet is non-None whenever a URL exists, even if the body
        # or headers can't be rendered.
        snippet = f"{method_str} {req_path} HTTP/1.1\nHost: {parsed.netloc}"
    except Exception:
        return None

    try:
        # Header names are case-insensitive.  Collapse differently-cased
        # duplicates (for example ``Host``/``host`` or two User-Agent values)
        # before rendering; Host is emitted from the URL exactly once.
        normalized_headers: dict[str, tuple[str, str]] = {}
        for key, value in (headers or {}).items():
            if not key:
                continue
            lower_key = str(key).lower()
            if lower_key == "host":
                continue
            normalized_headers[lower_key] = (str(key).title(), str(value))

        if cookies and "cookie" not in normalized_headers:
            cookie_value = "; ".join(
                f"{name}={value}" for name, value in cookies.items() if name
            )
            if cookie_value:
                normalized_headers["cookie"] = ("Cookie", cookie_value)

        header_lines = "\n".join(
            f"{key}: {value}" for key, value in normalized_headers.values()
        )
        if header_lines:
            snippet += f"\n{header_lines}"

        body_str = ""
        if body is not None and body != "":
            if isinstance(body, (dict, list)):
                body_str = _json.dumps(body, separators=(",", ":"), default=str)
            else:
                body_str = str(body)
        if len(body_str) > max_body_chars:
            body_str = body_str[:max_body_chars] + "\n[...snip...]"

        snippet += f"\n\n{body_str}"
    except Exception:
        # Headers/body failed to render, but the request line + Host above
        # already stand. Keep that rather than dropping the snippet entirely.
        pass
    return snippet


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
    """Build an httpx.Timeout from the global scanner config, with a
    conservative connect-timeout cap of 5 s to avoid long aggregation waits."""
    settings = get_settings()
    total = total if total is not None else settings.request_timeout_seconds
    return httpx.Timeout(
        connect=min(5.0, total),
        read=total,
        write=total,
        pool=min(5.0, total),
    )


def scan_http_limits() -> httpx.Limits:
    """Build an httpx.Limits matching the configured scanner concurrency."""
    pool_size = max(1, get_settings().scanner_concurrency)
    return httpx.Limits(
        max_connections=pool_size,
        max_keepalive_connections=pool_size,
    )


def same_origin_url(left: str, right: str) -> bool:
    """Return True when two URLs share scheme, hostname, and port."""
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
