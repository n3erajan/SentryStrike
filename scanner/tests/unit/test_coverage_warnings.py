"""Phase 8 — coverage honesty: 0-request detector warnings.

When a detector builds N candidates but sends 0 requests, the scan report
must surface an explicit ``coverage_warning`` so the silent gap is visible to
an operator reading the report — not buried in per-detector metrics.
"""
from app.core.scanner import ScanOrchestrator
from shared.models.scan import DetectorCoverageMetric


class _DummyRepository:
    pass


def _orchestrator() -> ScanOrchestrator:
    return ScanOrchestrator(_DummyRepository())


def test_zero_request_detector_produces_coverage_warning():
    """A detector that built candidates but sent 0 requests must produce a
    coverage warning naming the detector, the candidate count, and the skip
    reason."""
    metrics = [
        DetectorCoverageMetric(
            detector="command_injection",
            candidates_built=10,
            requests_sent=0,
            skipped_reasons={"no_candidates_matched": 10},
        ),
    ]
    warnings = _orchestrator()._detector_coverage_warnings(metrics)
    assert len(warnings) == 1
    w = warnings[0]
    assert "command_injection" in w
    assert "built 10" in w
    assert "sent 0" in w
    assert "no_candidates_matched=10" in w


def test_zero_candidate_detector_produces_no_warning():
    """A detector that built 0 candidates has no gap — there was nothing to
    test. It must not produce a coverage warning (no false alarm)."""
    metrics = [
        DetectorCoverageMetric(
            detector="command_injection",
            candidates_built=0,
            requests_sent=0,
            skipped_reasons={"no_candidates_built": 1},
        ),
    ]
    warnings = _orchestrator()._detector_coverage_warnings(metrics)
    assert warnings == []


def test_detector_with_requests_produces_no_warning():
    """A detector that sent requests has no coverage gap — no warning."""
    metrics = [
        DetectorCoverageMetric(
            detector="xss",
            candidates_built=50,
            requests_sent=120,
        ),
    ]
    warnings = _orchestrator()._detector_coverage_warnings(metrics)
    assert warnings == []


def test_multiple_zero_request_detectors_each_warned():
    """Each 0-request detector gets its own warning, so no gap is hidden
    behind another."""
    metrics = [
        DetectorCoverageMetric(
            detector="command_injection",
            candidates_built=5,
            requests_sent=0,
            skipped_reasons={"no_candidates_matched": 5},
        ),
        DetectorCoverageMetric(
            detector="supply_chain",
            candidates_built=3,
            requests_sent=0,
            skipped_reasons={"no_version_extracted": 3},
        ),
        DetectorCoverageMetric(
            detector="xss",
            candidates_built=50,
            requests_sent=120,
        ),
    ]
    warnings = _orchestrator()._detector_coverage_warnings(metrics)
    assert len(warnings) == 2
    warned_detectors = [w for w in warnings if "command_injection" in w or "supply_chain" in w]
    assert len(warned_detectors) == 2


def test_zero_request_detector_without_skip_reason_still_warned():
    """Even when skipped_reasons is empty, a 0-request detector that built
    candidates still gets a warning with a generic reason — the gap exists
    regardless of whether a skip reason was recorded."""
    metrics = [
        DetectorCoverageMetric(
            detector="crypto",
            candidates_built=2,
            requests_sent=0,
            skipped_reasons={},
        ),
    ]
    warnings = _orchestrator()._detector_coverage_warnings(metrics)
    assert len(warnings) == 1
    assert "crypto" in warnings[0]
    assert "no requests dispatched" in warnings[0]
