"""Global concurrency control for outbound scan HTTP traffic."""

from __future__ import annotations

import asyncio

from app.config import get_settings

_scan_http_semaphore: asyncio.Semaphore | None = None


def get_scan_http_semaphore() -> asyncio.Semaphore:
    """Return a process-wide semaphore limiting concurrent outbound scan requests."""
    global _scan_http_semaphore
    if _scan_http_semaphore is None:
        limit = max(1, get_settings().scanner_concurrency)
        _scan_http_semaphore = asyncio.Semaphore(limit)
    return _scan_http_semaphore


def reset_scan_http_semaphore() -> None:
    """Reset the global semaphore (for tests)."""
    global _scan_http_semaphore
    _scan_http_semaphore = None
