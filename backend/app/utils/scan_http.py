"""Shared httpx client factory for outbound scan traffic."""

from __future__ import annotations

from typing import Mapping
from urllib.parse import urljoin, urlparse

import httpx

from app.config import get_settings
from app.utils.scan_throttle import get_scan_http_semaphore


DEFAULT_SCAN_HEADERS = {"User-Agent": "SentryStrikeScanner/1.0"}


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
