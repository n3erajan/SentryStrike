"""Work-weighted detector ETA: targets, cost weights, parallelism, pace recalibration."""

from datetime import datetime, timedelta, timezone
from time import perf_counter
from types import SimpleNamespace
from unittest.mock import MagicMock

from app.core.scanner import (
    DETECTOR_COST_WEIGHT,
    ScanOrchestrator,
    _elapsed_utc_seconds,
)
from shared.models.scan import ScanPhase


class _DummyRepository:
    pass


def _orchestrator() -> ScanOrchestrator:
    return ScanOrchestrator(_DummyRepository())


def _fake_detector(name: str) -> MagicMock:
    det = MagicMock()
    det.name = name
    return det


def _planner_with_targets(counts: dict[str, int]) -> MagicMock:
    planner = MagicMock()

    def targets_for(name: str):
        return [object()] * counts.get(name, 0)

    planner.targets_for.side_effect = targets_for
    return planner


def test_elapsed_utc_seconds_accepts_naive_started_at() -> None:
    started = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(seconds=30)

    elapsed = _elapsed_utc_seconds(started)

    assert 25 <= elapsed <= 40


def test_elapsed_utc_seconds_accepts_aware_started_at() -> None:
    started = datetime.now(timezone.utc) - timedelta(seconds=30)

    elapsed = _elapsed_utc_seconds(started)

    assert 25 <= elapsed <= 40


def test_compute_eta_crawling_with_naive_started_at() -> None:
    orch = _orchestrator()
    scan = SimpleNamespace(
        started_at=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(seconds=60),
    )

    eta = orch._compute_eta_seconds(scan, ScanPhase.crawling, 1.0, progress=27)

    assert eta is not None
    assert eta >= 0


def test_xss_gets_more_work_units_than_light_detector_for_same_targets() -> None:
    orch = _orchestrator()
    planner = _planner_with_targets({"xss": 10, "sensitive_paths": 10})
    detectors = [_fake_detector("xss"), _fake_detector("sensitive_paths")]

    work, _ = orch._estimate_detector_work(
        planner,
        detectors,
        latency_ms=50.0,
        parallelism=2,
        per_detector_cap=6000,
    )

    # XSS has both more payloads-per-target and a higher cost weight.
    assert work["xss"] > 10 * work["sensitive_paths"]
    assert DETECTOR_COST_WEIGHT["xss"] > DETECTOR_COST_WEIGHT["sensitive_paths"]


def test_more_targets_increase_work_units() -> None:
    orch = _orchestrator()
    planner = _planner_with_targets({"xss": 50})
    detectors = [_fake_detector("xss")]

    work_many, _ = orch._estimate_detector_work(
        planner, detectors, latency_ms=100.0, parallelism=2, per_detector_cap=6000
    )

    planner_few = _planner_with_targets({"xss": 5})
    work_few, _ = orch._estimate_detector_work(
        planner_few, detectors, latency_ms=100.0, parallelism=2, per_detector_cap=6000
    )

    assert work_many["xss"] > work_few["xss"]


def test_prior_uses_detector_parallelism_not_full_concurrency() -> None:
    orch = _orchestrator()
    planner = _planner_with_targets({"injection_sql_command": 20, "xss": 20})
    detectors = [_fake_detector("injection_sql_command"), _fake_detector("xss")]

    _, prior_parallel_2 = orch._estimate_detector_work(
        planner, detectors, latency_ms=100.0, parallelism=2, per_detector_cap=6000
    )
    _, prior_parallel_8 = orch._estimate_detector_work(
        planner, detectors, latency_ms=100.0, parallelism=8, per_detector_cap=6000
    )

    assert prior_parallel_2 == prior_parallel_8 * 4


def test_progress_fraction_is_work_weighted_not_detector_count() -> None:
    """12 light detectors finishing first must not jump progress to ~92%."""
    orch = _orchestrator()
    # Heavy XSS dominates work; 12 light units finish first.
    orch._eta_state.detector_work_units = {
        "sensitive_paths": 10.0,
        "csrf": 15.0,
        "xss": 400.0,
    }
    orch._eta_state.detector_total_work = 425.0
    orch._eta_state.detector_completed_work = 25.0  # lights done
    orch._eta_state.detector_total_s = 600.0
    orch._eta_state.detector_phase_started = perf_counter() - 120.0
    orch._eta_state.findings_count = 10

    fraction = orch._eta_state.detector_completed_work / orch._eta_state.detector_total_work
    assert fraction < 0.1

    scan = SimpleNamespace(started_at=datetime.now(timezone.utc) - timedelta(minutes=5))
    eta = orch._compute_eta_seconds(
        scan, ScanPhase.vulnerability_detection, fraction, progress=40
    )

    # Old count-based model would claim ~1/13 of ~35s. Remaining XSS + AI must
    # leave minutes on the clock once pace sees 25 units in 120s.
    assert eta is not None
    assert eta >= 300


def test_starting_eta_includes_crawl_and_detector_priors() -> None:
    """Before detector work is measured, crawl+vuln must not contribute 0s."""
    orch = _orchestrator()
    scan = SimpleNamespace(started_at=datetime.now(timezone.utc))

    eta = orch._compute_eta_seconds(
        scan, ScanPhase.initializing, 1.0, progress=2
    )

    assert eta is not None
    # CRAWL(150)+tech(5)+tls(3)+DETECTOR(480)+dedup(2)+AI(60)+risk(2)+report(8)
    assert eta >= 700
    assert eta < 900


def test_last_heavy_detector_does_not_claim_tiny_eta() -> None:
    orch = _orchestrator()
    orch._eta_state.detector_work_units = {
        "csrf": 20.0,
        "sensitive_paths": 10.0,
        "xss": 500.0,
    }
    orch._eta_state.detector_total_work = 530.0
    orch._eta_state.detector_completed_work = 30.0
    orch._eta_state.detector_total_s = 400.0
    # Lights finished in 60s — pace would understate XSS if we trusted it alone;
    # prior floor keeps remaining honest.
    orch._eta_state.detector_phase_started = perf_counter() - 60.0
    orch._eta_state.findings_count = 40

    remaining = orch._detector_remaining_seconds()
    prior_share = 400.0 * (500.0 / 530.0)
    assert remaining >= prior_share * 0.99

    scan = SimpleNamespace(started_at=datetime.now(timezone.utc) - timedelta(minutes=8))
    eta = orch._compute_eta_seconds(
        scan, ScanPhase.vulnerability_detection, 30 / 530, progress=40
    )
    assert eta is not None
    # XSS prior share (~377s) + AI for 40 findings (320s) + short phases (~12s)
    assert eta >= 600
