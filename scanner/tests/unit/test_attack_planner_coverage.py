"""P0-1: coverage_summary must derive skips from real attempted/denied counts.

Regression guard: a detector that ran fully but found nothing must report
``budget_exhausted == 0`` — the old code inferred budget exhaustion from a
findings shortfall, which manufactured phantom ``budget_exhausted`` buckets.
"""
from __future__ import annotations

from app.core.crawler.models import RequestObservation
from app.core.detectors.attack_planner import AttackPlanner


def _planner_with_body_targets(field_names: list[str]) -> AttackPlanner:
    """Build a planner whose sqli surface is N replayable JSON body targets."""
    request = RequestObservation(
        url="http://example.com/api/items",
        method="POST",
        request_headers={"content-type": "application/json"},
        request_content_type="application/json",
        post_data="{" + ",".join(f'"{name}":"v"' for name in field_names) + "}",
        body_kind="json",
        body_schema=list(field_names),
        replayable=True,
    )
    return AttackPlanner.from_context(
        urls=[],
        forms=[],
        requests=[request],
    )


def test_detector_ran_fully_reports_no_budget_exhausted():
    planner = _planner_with_body_targets(["a", "b", "c"])
    # Detector attempted every body target and found nothing.
    summary = planner.coverage_summary("injection_sql_command", attempted_count=3, denied_count=0)
    assert summary["targets_attempted"] == 3
    assert summary["body_targets_skipped"] == 0
    assert summary["body_targets_skipped_by_reason"] == {}
    assert summary["body_targets_skipped_by_reason"].get("budget_exhausted", 0) == 0


def test_zero_attempt_zero_deny_is_not_budget_exhausted():
    planner = _planner_with_body_targets(["a", "b", "c"])
    summary = planner.coverage_summary("injection_sql_command", attempted_count=0, denied_count=0)
    assert summary["targets_attempted"] == 0
    assert summary["body_targets_skipped"] == 3
    buckets = summary["body_targets_skipped_by_reason"]
    # Replayable body targets left untried with NO governor deny are honest
    # "no candidates matched", never inferred budget exhaustion.
    assert buckets.get("budget_exhausted", 0) == 0
    assert buckets.get("no_candidates_matched", 0) == 3


def test_budget_exhausted_attributed_only_up_to_real_deny_count():
    planner = _planner_with_body_targets(["a", "b", "c"])
    summary = planner.coverage_summary("injection_sql_command", attempted_count=0, denied_count=2)
    buckets = summary["body_targets_skipped_by_reason"]
    assert summary["requests_denied_by_governor"] == 2
    assert buckets.get("budget_exhausted", 0) == 2
    # The remaining skipped target is not a budget deny.
    assert buckets.get("no_candidates_matched", 0) == 1
