"""Per-scan detector coverage counters and the tested-surface ledger.

Two ContextVar-scoped records, both initialised once per scan run:

``_request_counts``
    Per-detector admitted-request totals, used for progress/ETA and for the
    ``DetectorCoverageMetric`` request figures.

``_tested_surface``
    The tested-surface **ledger**: one entry per distinct
    ``(module, method, path, parameter)`` actually exercised against the target.
    This is the ground truth behind the report's "what was tested" inventory, so
    it is written from exactly one place - :func:`app.utils.http_logging.log_http_response`,
    which is only ever called once a real response (or a real transport failure)
    came back. Requests the budget governor denies return before that call, so a
    denied probe can never be reported as tested.
"""

from __future__ import annotations

from collections import Counter
from contextvars import ContextVar
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit


# ContextVar-scoped request counters. Each scan run initialises its own
# counter with begin_request_counting() and reads the snapshot before the
# scan completes. Thread/async-safe because ContextVar is per-task.
_request_counts: ContextVar[Counter[str] | None] = ContextVar("scan_request_counts", default=None)

# Hard ceiling on distinct ledger entries. A broad scan over a large app can
# probe tens of thousands of (path, parameter) pairs; the inventory is persisted
# on the scan document and served in the JSON report, so it must stay bounded.
# Entries past the cap are counted in ``omitted`` rather than silently dropped,
# so the report states "recorded N of M" instead of understating the surface.
LEDGER_MAX_ENTRIES = 5000

# Per-entry ceiling on distinct status codes retained. Enough to show the shape
# of the responses (e.g. 200/302/500) without unbounded growth on an endpoint
# probed thousands of times.
MAX_STATUS_CODES_PER_ENTRY = 8


@dataclass
class TestedSurfaceEntry:
    """One distinct tested ``(module, method, path, parameter)`` tuple."""

    # "Tested..." trips pytest's default ``Test*`` class collection; opt out.
    __test__ = False

    module: str
    method: str
    path: str
    parameter: str
    requests: int = 0
    # Distinct HTTP status codes observed. A 0 means the request was sent but no
    # response came back (timeout/transport error) - tracked separately in
    # ``no_response`` so "probed" is never confused with "answered".
    status_codes: set[int] = field(default_factory=set)
    no_response: int = 0


@dataclass
class _LedgerState:
    entries: dict[tuple[str, str, str, str], TestedSurfaceEntry] = field(default_factory=dict)
    # Distinct tuples that hit the cap and were never recorded.
    omitted: int = 0
    # Total requests observed, including those whose tuple was omitted, so the
    # request total stays truthful even when the inventory is truncated.
    total_requests: int = 0
    total_no_response: int = 0


_tested_surface: ContextVar[_LedgerState | None] = ContextVar("scan_tested_surface", default=None)


def begin_request_counting() -> None:
    """Initialise a fresh request counter and tested-surface ledger."""
    _request_counts.set(Counter())
    _tested_surface.set(_LedgerState())


def record_detector_request(module: str) -> None:
    """Increment the request counter for the given detector module."""
    counts = _request_counts.get()
    if counts is not None and module:
        counts[module] += 1


def normalize_tested_path(url: str) -> str:
    """Strip query and fragment from ``url``, keeping scheme, host, and path.

    The query is dropped because ``?id=1`` and ``?id=2`` are the same tested
    surface - which parameters were exercised is recorded separately, by name.
    Path segments are deliberately **not** collapsed (no ``/users/{id}``
    rewriting): the report states which paths were actually requested, and
    templating them would claim coverage of a pattern rather than of the
    concrete resources probed.
    """
    if not url:
        return ""
    try:
        parts = urlsplit(str(url))
    except ValueError:
        return str(url)
    if not parts.scheme and not parts.netloc:
        # Relative URL - keep the path as-is rather than fabricating an origin.
        return parts.path or str(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", ""))


def record_tested_surface(
    *,
    module: str,
    method: str,
    url: str,
    parameter: str = "",
    status_code: int = 0,
) -> None:
    """Record one actually-dispatched request in the tested-surface ledger.

    No-op outside a scan run, or for uninstrumented callers that supply no
    ``module`` (an unattributable request cannot be reported as coverage of any
    detector class).
    """
    state = _tested_surface.get()
    if state is None or not module:
        return

    path = normalize_tested_path(url)
    if not path:
        return

    state.total_requests += 1
    try:
        status = int(status_code)
    except (TypeError, ValueError):
        status = 0
    if status <= 0:
        state.total_no_response += 1

    key = (module, str(method or "GET").upper(), path, parameter or "")
    entry = state.entries.get(key)
    if entry is None:
        if len(state.entries) >= LEDGER_MAX_ENTRIES:
            state.omitted += 1
            return
        entry = TestedSurfaceEntry(
            module=key[0], method=key[1], path=key[2], parameter=key[3]
        )
        state.entries[key] = entry

    entry.requests += 1
    if status <= 0:
        entry.no_response += 1
    elif len(entry.status_codes) < MAX_STATUS_CODES_PER_ENTRY:
        entry.status_codes.add(status)


def snapshot_request_counts() -> dict[str, int]:
    """Return a copy of the current request counts without terminating them."""
    counts = _request_counts.get()
    return dict(counts or {})


def snapshot_tested_surface() -> list[TestedSurfaceEntry]:
    """Copy of the ledger entries, without terminating the ledger."""
    state = _tested_surface.get()
    if state is None:
        return []
    return [
        TestedSurfaceEntry(
            module=entry.module,
            method=entry.method,
            path=entry.path,
            parameter=entry.parameter,
            requests=entry.requests,
            status_codes=set(entry.status_codes),
            no_response=entry.no_response,
        )
        for entry in state.entries.values()
    ]


def tested_surface_totals() -> dict[str, int]:
    """Ledger-wide totals, including traffic whose tuple exceeded the cap."""
    state = _tested_surface.get()
    if state is None:
        return {"total_requests": 0, "total_no_response": 0, "omitted": 0}
    return {
        "total_requests": state.total_requests,
        "total_no_response": state.total_no_response,
        "omitted": state.omitted,
    }


def end_request_counting() -> None:
    """Clear the request counter and tested-surface ledger for this scan task."""
    _request_counts.set(None)
    _tested_surface.set(None)
