"""Request-budget governor — per-detector / per-parameter ceilings."""
from __future__ import annotations

import pytest

from app.core import request_governor as rg
from app.core.request_governor import (
    GovernorDecision,
    admit,
    begin_governor,
    end_governor,
    snapshot,
    was_detector_capped,
)
from app.core.verification.verification_framework import HttpVerifier


def test_admit_is_noop_without_active_governor():
    end_governor()  # ensure inactive
    for _ in range(10_000):
        assert admit("sqli", "id") is GovernorDecision.ALLOW
    assert snapshot() == {}


def test_per_detector_cap_denies_tail_but_not_other_detectors():
    begin_governor(per_detector_cap=3, per_parameter_cap=0)
    try:
        assert [admit("sqli", "p").value for _ in range(4)] == ["allow", "allow", "allow", "deny"]
        # A different detector has its own budget.
        assert admit("xss", "p") is GovernorDecision.ALLOW
        assert snapshot()["sqli"] == 3
        assert was_detector_capped("sqli") is True
        assert was_detector_capped("xss") is False
    finally:
        end_governor()


def test_per_parameter_cap_isolates_parameters():
    begin_governor(per_detector_cap=0, per_parameter_cap=2)
    try:
        assert admit("sqli", "a") is GovernorDecision.ALLOW
        assert admit("sqli", "a") is GovernorDecision.ALLOW
        assert admit("sqli", "a") is GovernorDecision.DENY  # param 'a' exhausted
        # A different parameter under the same detector is unaffected.
        assert admit("sqli", "b") is GovernorDecision.ALLOW
    finally:
        end_governor()


def test_denied_requests_do_not_inflate_counts():
    begin_governor(per_detector_cap=2, per_parameter_cap=0)
    try:
        admit("cmd", "x")
        admit("cmd", "x")
        admit("cmd", "x")  # denied
        admit("cmd", "x")  # denied
        assert snapshot()["cmd"] == 2
    finally:
        end_governor()


@pytest.mark.asyncio
async def test_send_request_short_circuits_when_over_budget():
    """Over-budget requests return a benign empty response with no network call."""
    begin_governor(per_detector_cap=1, per_parameter_cap=0)
    verifier = HttpVerifier()
    verifier.set_request_context(module="sqli", parameter="p")
    try:
        # Simulate one prior admitted request so the detector is now at its cap.
        admit("sqli", "p")
        # This would otherwise hit the network; the governor must short-circuit.
        resp = await verifier.send_request(
            "http://127.0.0.1:9/never-reached", "GET", module="sqli", parameter="p"
        )
        # status -1 is the explicit "not tested" sentinel (distinct from a real 0
        # connection error), so detectors treat a budget deny as untested.
        assert resp.status_code == -1
        assert resp.not_tested is True
        assert resp.body == ""
        assert "budget" in (resp.response_snippet or "").lower()
    finally:
        end_governor()
        await verifier.close()


@pytest.mark.asyncio
async def test_denied_probe_does_not_produce_negative_sqli_verdict():
    """A governor-denied boolean probe must be untested, not a negative.

    With the per-detector cap set to 1, the baseline consumes the budget and the
    boolean true/false probes are denied (status -1). The verifier must skip them
    (no confirmed context) rather than score them as a non-differential negative.
    """
    from app.core.verification.sqli_verifier import SQLiVerifier

    begin_governor(per_detector_cap=1, per_parameter_cap=0)
    verifier = SQLiVerifier()
    verifier.http_verifier.set_request_context(module="sqli", parameter="id")
    try:
        result = await verifier._verify_boolean_based(
            url="http://127.0.0.1:9/never?id=1",
            parameter="id",
            method="GET",
            value="1",
        )
        assert result.is_vulnerable is False
        # No finding fabricated from an untested (denied) probe.
        assert result.findings == []
        # Confirm the deny path was actually exercised (budget was hit).
        assert rg.denied_snapshot().get("sqli", 0) > 0
    finally:
        end_governor()
        await verifier.http_verifier.close()


def test_denied_snapshot_counts_ceiling_hits_per_detector():
    begin_governor(per_detector_cap=2, per_parameter_cap=0)
    try:
        admit("cmd", "x")
        admit("cmd", "x")
        admit("cmd", "x")  # denied
        admit("cmd", "x")  # denied
        admit("sqli", "y")  # under cap, not denied
        snap = rg.denied_snapshot()
        assert snap.get("cmd") == 2
        assert "sqli" not in snap  # no denies recorded for a detector under budget
    finally:
        end_governor()


def test_denied_snapshot_empty_without_active_governor():
    end_governor()
    assert rg.denied_snapshot() == {}


def test_module_level_helpers_exposed():
    # Guard against accidental symbol removal used by scanner wiring.
    assert hasattr(rg, "begin_governor")
    assert hasattr(rg, "end_governor")
    assert hasattr(rg, "snapshot")
    assert hasattr(rg, "denied_snapshot")
