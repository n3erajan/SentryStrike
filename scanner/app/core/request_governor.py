"""Cross-cutting request-budget governor.

A per-scan governor consulted at the single HTTP chokepoint
(:meth:`HttpVerifier.send_request`). It enforces per-detector and
per-(detector, parameter) request ceilings so no single detector or parameter
can dominate scan traffic — the failure mode that let header-stored XSS spend
~93% of all requests for one finding.

Design constraints (this is a security scanner):

* **Fail-safe, never fail-closed-with-a-lie.** When a ceiling is hit the
  governor returns a benign *empty* response rather than raising (which could
  abort a detector) or fabricating content (which could create a false
  positive/negative). An empty body reads as "nothing here" to every detector,
  so the only effect is that the low-value *tail* of an over-budget detector's
  probes is skipped — exactly the intended budget behaviour.
* **No cross-detector response caching.** Serving one detector's cached read to
  another risks stale differentials → false positives, so the governor never
  caches response bodies.

State is held in a :class:`~contextvars.ContextVar` so it is naturally isolated
per scan/async-task and absent (a transparent no-op) outside a governed scan.
"""

from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass, field
from enum import Enum


class GovernorDecision(Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass
class _GovernorState:
    per_detector_cap: int
    per_parameter_cap: int
    detector_counts: dict[str, int] = field(default_factory=dict)
    parameter_counts: dict[tuple[str, str], int] = field(default_factory=dict)
    # Detectors/parameters already reported as capped (so we log once, not per probe).
    denied_detectors: set[str] = field(default_factory=set)
    # Per-detector count of DENIED (ceiling-hit) requests — distinct from the
    # admitted counts above. Feeds truthful "budget_exhausted" telemetry so the
    # coverage summary never infers a budget deny from a mere finding gap.
    denied_counts: dict[str, int] = field(default_factory=dict)


_state: ContextVar[_GovernorState | None] = ContextVar("request_governor_state", default=None)


def begin_governor(per_detector_cap: int, per_parameter_cap: int) -> None:
    """Initialise a per-scan request governor. A cap of 0 disables that ceiling."""
    _state.set(
        _GovernorState(
            per_detector_cap=max(0, int(per_detector_cap)),
            per_parameter_cap=max(0, int(per_parameter_cap)),
        )
    )


def end_governor() -> None:
    """Tear down the governor for the current scan context."""
    _state.set(None)


def admit(module: str, parameter: str) -> GovernorDecision:
    """Account one prospective request and decide whether it may be sent.

    Counts are incremented only for admitted requests, so a denied tail does not
    inflate the share statistics. No-op (always ALLOW) when no governor is active
    or ``module`` is empty (uninstrumented callers).
    """
    state = _state.get()
    if state is None or not module:
        return GovernorDecision.ALLOW

    if state.per_detector_cap and state.detector_counts.get(module, 0) >= state.per_detector_cap:
        state.denied_detectors.add(module)
        state.denied_counts[module] = state.denied_counts.get(module, 0) + 1
        return GovernorDecision.DENY

    if parameter and state.per_parameter_cap:
        key = (module, parameter)
        if state.parameter_counts.get(key, 0) >= state.per_parameter_cap:
            state.denied_counts[module] = state.denied_counts.get(module, 0) + 1
            return GovernorDecision.DENY

    state.detector_counts[module] = state.detector_counts.get(module, 0) + 1
    if parameter:
        key = (module, parameter)
        state.parameter_counts[key] = state.parameter_counts.get(key, 0) + 1
    return GovernorDecision.ALLOW


def was_detector_capped(module: str) -> bool:
    state = _state.get()
    return bool(state and module in state.denied_detectors)


def snapshot() -> dict[str, int]:
    """Per-detector admitted-request counts for reporting/telemetry."""
    state = _state.get()
    return dict(state.detector_counts) if state else {}


def denied_snapshot() -> dict[str, int]:
    """Per-detector DENIED-request counts (ceiling hits) for telemetry."""
    state = _state.get()
    return dict(state.denied_counts) if state else {}
