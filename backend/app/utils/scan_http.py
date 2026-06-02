"""Shared httpx client factory for outbound scan traffic."""

from __future__ import annotations

import httpx

from app.config import get_settings
from app.utils.scan_throttle import get_scan_http_semaphore


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


def create_scan_client(**kwargs) -> httpx.AsyncClient:
    """Create an AsyncClient that respects global scan concurrency limits."""
    kwargs.setdefault("timeout", scan_http_timeout())
    kwargs.setdefault("limits", scan_http_limits())
    client = httpx.AsyncClient(**kwargs)
    try:
        original_request = client.request
    except AttributeError:
        return client

    async def throttled_request(*args, **req_kwargs):
        async with get_scan_http_semaphore():
            return await original_request(*args, **req_kwargs)

    client.request = throttled_request  # type: ignore[method-assign]
    return client
