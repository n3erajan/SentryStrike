"""Coverage honesty: 0-request detector warnings.

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
            detector="open_redirect",
            candidates_built=3,
            requests_sent=0,
            skipped_reasons={"no_replayable_attack_targets": 3},
        ),
        DetectorCoverageMetric(
            detector="xss",
            candidates_built=50,
            requests_sent=120,
        ),
    ]
    warnings = _orchestrator()._detector_coverage_warnings(metrics)
    assert len(warnings) == 2
    warned_detectors = [w for w in warnings if "command_injection" in w or "open_redirect" in w]
    assert len(warned_detectors) == 2


def test_non_http_detector_never_warned():
    """supply_chain reaches its verdict by correlating the fingerprinted
    technology stack against CVEs — it dispatches no HTTP request at all. A
    0-request metric is its normal complete state, so warning about it would
    report a guaranteed false gap on every scan."""
    metrics = [
        DetectorCoverageMetric(
            detector="supply_chain",
            candidates_built=7,
            requests_sent=0,
            skipped_reasons={"no_findings_after_verification": 1},
        ),
    ]
    assert _orchestrator()._detector_coverage_warnings(metrics) == []


def test_inapplicable_skip_reason_suppresses_warning():
    """crypto_failures gates its active probes on an https:// scheme. On a
    plain-HTTP target the transport checks are inapplicable, not skipped, so the
    recorded exempt reason must suppress the gap warning."""
    metrics = [
        DetectorCoverageMetric(
            detector="crypto_failures",
            candidates_built=12,
            requests_sent=0,
            skipped_reasons={"https_only_checks_not_applicable": 1},
        ),
    ]
    assert _orchestrator()._detector_coverage_warnings(metrics) == []


def test_crypto_failures_still_warned_on_https_target():
    """Without the inapplicability reason — i.e. an https target where the
    transport checks should have run — crypto_failures is a real gap and must
    still be warned about."""
    metrics = [
        DetectorCoverageMetric(
            detector="crypto_failures",
            candidates_built=12,
            requests_sent=0,
            skipped_reasons={"no_findings_after_verification": 1},
        ),
    ]
    warnings = _orchestrator()._detector_coverage_warnings(metrics)
    assert len(warnings) == 1
    assert "crypto_failures" in warnings[0]


def test_http_target_records_crypto_inapplicability_reason():
    """On a plain-HTTP target the skip-reason builder must record the exempt
    reason, so the suppression above actually engages end to end."""
    reasons = _orchestrator()._detector_skip_reasons(
        "crypto_failures",
        candidates_built=4,
        findings=[],
        crawl_context={"root_url": "http://localhost:8080", "urls": ["http://localhost:8080/login.php"]},
    )
    assert reasons.get("https_only_checks_not_applicable") == 1


def test_https_target_does_not_record_crypto_inapplicability_reason():
    """An https target means the transport checks were applicable, so the exempt
    reason must not be recorded and a 0-request metric stays a real gap."""
    reasons = _orchestrator()._detector_skip_reasons(
        "crypto_failures",
        candidates_built=4,
        findings=[],
        crawl_context={"root_url": "https://example.com", "urls": ["https://example.com/login"]},
    )
    assert "https_only_checks_not_applicable" not in reasons


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
