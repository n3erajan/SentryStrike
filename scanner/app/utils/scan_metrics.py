"""Per-scan detector coverage counters."""

from __future__ import annotations

from collections import Counter
from contextvars import ContextVar


# ContextVar-scoped request counters. Each scan run initialises its own
# counter with begin_request_counting() and reads the snapshot before the
# scan completes. Thread/async-safe because ContextVar is per-task.
_request_counts: ContextVar[Counter[str] | None] = ContextVar("scan_request_counts", default=None)


def begin_request_counting() -> None:
    """Initialise a fresh request counter for the current scan task."""
    _request_counts.set(Counter())


def record_detector_request(module: str) -> None:
    """Increment the request counter for the given detector module."""
    counts = _request_counts.get()
    if counts is not None and module:
        counts[module] += 1


def snapshot_request_counts() -> dict[str, int]:
    """Return a copy of the current request counts without terminating them."""
    counts = _request_counts.get()
    return dict(counts or {})


def end_request_counting() -> None:
    """Clear the request counter for the current scan task."""
    _request_counts.set(None)
