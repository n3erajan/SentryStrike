from app.core.detectors.base_detector import Finding
from app.core.scanner import ScanOrchestrator
from app.models.vulnerability import (
    AiAnalysis,
    Evidence,
    Exploitability,
    LocationInfo,
    OwaspCategory,
    ReviewStatus,
    SeverityLevel,
    Vulnerability,
)


class DummyRepository:
    pass


def _orchestrator() -> ScanOrchestrator:
    return ScanOrchestrator(DummyRepository())


def test_to_vulnerability_preserves_detector_verification_metadata() -> None:
    finding = Finding(
        category=OwaspCategory.a05,
        vuln_type="SQL Injection (Time-Based Blind)",
        severity=SeverityLevel.critical,
        url="http://target.test/dvwa/vulnerabilities/sqli_blind/",
        parameter="id",
        payload="' OR SLEEP(5)--",
        evidence="Timing delta confirmed.",
        confidence_score=90.0,
        detection_method="time_based",
        detection_evidence={"timing_delta_ms": 5100},
        verified=True,
    )

    vulnerability = _orchestrator()._to_vulnerability(finding)

    assert vulnerability.evidence.verified is True
    assert vulnerability.evidence.confidence_score == 90.0
    assert vulnerability.evidence.detection_method == "time_based"
    assert vulnerability.evidence.detection_evidence == {"timing_delta_ms": 5100}


def test_verified_time_based_sqli_is_not_auto_suppressed_by_high_ai_fp_probability() -> None:
    vulnerability = Vulnerability(
        id="v-1",
        category=OwaspCategory.a05,
        vuln_type="SQL Injection (Time-Based Blind)",
        severity=SeverityLevel.critical,
        cvss_score=9.1,
        location=LocationInfo(url="http://target.test/dvwa/vulnerabilities/sqli_blind/", parameter="id"),
        evidence=Evidence(
            payload="' OR SLEEP(5)--",
            response_snippet="Timing delta confirmed for sleep payload.",
            verified=True,
            confidence_score=90.0,
            detection_method="time_based",
            detection_evidence={"timing_delta_ms": 5200},
        ),
        ai_analysis=AiAnalysis(
            false_positive_probability=0.85,
            false_positive_reasoning="Reflected payload without SQL error.",
            exploitability=Exploitability.easy,
        ),
    )

    orchestrator = _orchestrator()
    grade = orchestrator.evidence_grader.grade(vulnerability)
    vulnerability.ai_analysis.evidence_grade = grade.grade
    vulnerability.ai_analysis.false_positive_probability = min(vulnerability.ai_analysis.false_positive_probability, grade.fp_ceiling)
    
    orchestrator._apply_false_positive_adjustments([vulnerability])

    assert vulnerability.is_false_positive is False
    assert vulnerability.review_status == ReviewStatus.confirmed
    assert vulnerability.cvss_score == 9.1
    assert vulnerability.severity == SeverityLevel.critical
    assert vulnerability.ai_analysis.false_positive_probability == 0.05


def test_unverified_high_fp_finding_is_still_suppressed() -> None:
    vulnerability = Vulnerability(
        id="v-2",
        category=OwaspCategory.a05,
        vuln_type="Reflected XSS",
        severity=SeverityLevel.medium,
        cvss_score=6.1,
        location=LocationInfo(url="http://target.test/search", parameter="q"),
        evidence=Evidence(
            payload="<script>alert(1)</script>",
            response_snippet="Payload was reflected in standard HTML text.",
            verified=False,
            confidence_score=20.0,
            detection_method="heuristic",
        ),
        ai_analysis=AiAnalysis(
            false_positive_probability=0.9,
            false_positive_reasoning="Payload was reflected but not executed.",
        ),
    )

    orchestrator = _orchestrator()
    grade = orchestrator.evidence_grader.grade(vulnerability)
    vulnerability.ai_analysis.evidence_grade = grade.grade
    vulnerability.ai_analysis.false_positive_probability = min(vulnerability.ai_analysis.false_positive_probability, grade.fp_ceiling)
    
    orchestrator._apply_false_positive_adjustments([vulnerability])

    assert vulnerability.is_false_positive is False
    assert vulnerability.cvss_score == 6.1
    assert vulnerability.severity == SeverityLevel.medium


def test_incompatible_lfi_ai_remediation_is_detected() -> None:
    orchestrator = _orchestrator()

    assert orchestrator._remediation_is_incompatible(
        "Local File Inclusion (LFI)",
        "Use parameterized queries or prepared statements.",
    )
    assert not orchestrator._remediation_is_incompatible(
        "Local File Inclusion (LFI)",
        "Whitelist allowed page paths and canonicalize file names before inclusion.",
    )


def test_file_upload_fallback_covers_double_extension_bypass() -> None:
    fallback = _orchestrator()._get_fallback_for("Double Extension Bypass")

    assert "compound extensions" in fallback["remediation"]
