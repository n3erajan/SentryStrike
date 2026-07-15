"""Per-scan detector coverage counters."""

from __future__ import annotations

from collections import Counter
from contextvars import ContextVar


_request_counts: ContextVar[Counter[str] | None] = ContextVar("scan_request_counts", default=None)


def begin_request_counting() -> None:
    _request_counts.set(Counter())


def record_detector_request(module: str) -> None:
    counts = _request_counts.get()
    if counts is not None and module:
        counts[module] += 1


def snapshot_request_counts() -> dict[str, int]:
    counts = _request_counts.get()
    return dict(counts or {})


def end_request_counting() -> None:
    _request_counts.set(None)
