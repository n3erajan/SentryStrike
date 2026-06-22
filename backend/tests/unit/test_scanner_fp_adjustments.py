from types import SimpleNamespace

from app.core.detectors.base_detector import Finding
from app.core.crawler.models import RequestObservation
from app.core.scanner import ScanOrchestrator
from app.models.scan import (
    AuthCoverage,
    DetectorCoverageMetric,
    EvidenceStrengthBreakdown,
    ReportMetadata,
    ScanStatistics,
    SpaApiCoverage,
)
from app.models.vulnerability import (
    AiAnalysis,
    Evidence,
    EvidenceStrength,
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


def test_static_spa_coverage_warning_is_deterministic() -> None:
    class CrawlResult:
        is_spa = True
        assets = ["http://target.test/app.js"]
        routes = []
        api_endpoints = []
        parameters = []
        requests = []
        dead_routes = []
        forms = []
        session_cookies = {}
        auth_headers = {"Authorization": "Bearer token"}
        auth_state = "authenticated_verified"
        browser_available = False
        browser_error = "Playwright import failed: No module named 'playwright'"

    scan = SimpleNamespace(
        target_url="http://target.test/",
        statistics=ScanStatistics(),
        report_metadata=ReportMetadata(
            spa_api_coverage=SpaApiCoverage(),
            auth_coverage=AuthCoverage(),
            evidence_strength_breakdown=EvidenceStrengthBreakdown(),
        ),
    )
    _orchestrator()._update_crawl_metadata(scan, CrawlResult())

    coverage = scan.report_metadata.spa_api_coverage
    assert coverage.static_spa_only is True
    assert coverage.browser_available is False
    assert coverage.replayable_json_bodies == 0
    assert scan.report_metadata.coverage_warnings[0] == (
        "SPA detected, but no browser runtime requests were observed. API coverage is static extraction only."
    )
    assert any("Browser crawling unavailable" in warning for warning in scan.report_metadata.coverage_warnings)


def test_replayable_json_body_suppresses_json_body_warning() -> None:
    class CrawlResult:
        is_spa = False
        assets = []
        routes = []
        api_endpoints = []
        parameters = []
        requests = [
            RequestObservation(
                url="http://target.test/api/login",
                method="POST",
                request_headers={"content-type": "application/json"},
                post_data='{"email":"a@example.com"}',
            )
        ]
        dead_routes = []
        forms = []
        session_cookies = {}
        auth_headers = {}
        auth_state = "unauthenticated"
        browser_available = True
        browser_error = None

    scan = SimpleNamespace(
        target_url="http://target.test/",
        statistics=ScanStatistics(),
        report_metadata=ReportMetadata(
            spa_api_coverage=SpaApiCoverage(),
            auth_coverage=AuthCoverage(),
            evidence_strength_breakdown=EvidenceStrengthBreakdown(),
        ),
    )
    _orchestrator()._update_crawl_metadata(scan, CrawlResult())

    assert scan.report_metadata.spa_api_coverage.replayable_json_bodies == 1
    assert not any("No replayable JSON request bodies" in warning for warning in scan.report_metadata.coverage_warnings)


def test_replayable_form_body_suppresses_api_body_warning() -> None:
    class CrawlResult:
        is_spa = False
        assets = []
        routes = []
        api_endpoints = []
        parameters = []
        requests = [
            RequestObservation(
                url="http://target.test/login",
                method="POST",
                request_headers={"content-type": "application/x-www-form-urlencoded"},
                post_data="email=a%40example.com&password=secret",
            )
        ]
        dead_routes = []
        forms = []
        session_cookies = {}
        auth_headers = {}
        auth_state = "unauthenticated"
        browser_available = True
        browser_error = None

    scan = SimpleNamespace(
        target_url="http://target.test/",
        statistics=ScanStatistics(),
        report_metadata=ReportMetadata(
            spa_api_coverage=SpaApiCoverage(),
            auth_coverage=AuthCoverage(),
            evidence_strength_breakdown=EvidenceStrengthBreakdown(),
        ),
    )
    _orchestrator()._update_crawl_metadata(scan, CrawlResult())

    assert scan.report_metadata.spa_api_coverage.replayable_json_bodies == 0
    assert not any("API body testing was limited" in warning for warning in scan.report_metadata.coverage_warnings)


def test_unverified_admin_route_hint_is_not_confirmed_observation() -> None:
    finding = Finding(
        category=OwaspCategory.a01,
        vuln_type="Admin / Privileged Endpoint Discovered",
        severity=SeverityLevel.medium,
        url="http://target.test/administration",
        evidence="Client-side route name was discovered in JavaScript.",
        verified=False,
        confidence_score=0.0,
        detection_method="heuristic",
    )

    strength = _orchestrator()._classify_evidence_strength(finding)

    assert strength == EvidenceStrength.possible


def test_verified_sensitive_content_is_confirmed_observation() -> None:
    finding = Finding(
        category=OwaspCategory.a02,
        vuln_type="Sensitive Path Exposure",
        severity=SeverityLevel.medium,
        url="http://target.test/.env",
        evidence="Response body contained KEY=value configuration markers.",
        verified=True,
        confidence_score=90.0,
        detection_method="content_fingerprint",
    )

    strength = _orchestrator()._classify_evidence_strength(finding)

    assert strength == EvidenceStrength.confirmed_observation


def test_verified_payload_execution_is_confirmed_exploit() -> None:
    finding = Finding(
        category=OwaspCategory.a05,
        vuln_type="SQL Injection (Time-Based Blind)",
        severity=SeverityLevel.critical,
        url="http://target.test/item",
        parameter="id",
        payload="' OR SLEEP(5)--",
        evidence="Time delta confirmed.",
        verified=True,
        confidence_score=90.0,
        detection_method="time_based",
    )

    strength = _orchestrator()._classify_evidence_strength(finding)

    assert strength == EvidenceStrength.confirmed_exploit


def test_data_exposure_finding_includes_long_response_excerpt() -> None:
    finding = Finding(
        category=OwaspCategory.a01,
        vuln_type="Unauthenticated API Data Exposure",
        severity=SeverityLevel.medium,
        url="http://target.test/api/users",
        evidence="Unauthenticated request returned object data.",
        verified=True,
        confidence_score=88.0,
        detection_method="authorization_matrix",
        verification_response_snippet='{"data":[' + ('{"id":1,"email":"a@example.test"},' * 40) + "]}",
    )

    snippet = _orchestrator()._finding_response_snippet(finding)

    assert snippet is not None
    assert "RESPONSE EXCERPT" in snippet
    assert '"email":"a@example.test"' in snippet


def test_union_sqli_without_extraction_proof_is_probable_not_confirmed_exploit() -> None:
    finding = Finding(
        category=OwaspCategory.a05,
        vuln_type="SQL Injection (UNION-Based)",
        severity=SeverityLevel.critical,
        url="http://target.test/api/search?q=test",
        parameter="q",
        payload="' UNION SELECT NULL--",
        evidence="UNION NULL payloads produced response differences.",
        verified=True,
        confidence_score=75.0,
        detection_method="union_based",
        detection_evidence={
            "valid_null_probes": 4,
            "avg_similarity": 0.83,
            "canary_verified": False,
            "version_extracted": False,
        },
    )

    strength = _orchestrator()._classify_evidence_strength(finding)

    assert strength == EvidenceStrength.probable


def test_unverified_non_heuristic_evidence_is_probable() -> None:
    finding = Finding(
        category=OwaspCategory.a05,
        vuln_type="DOM-Based XSS Sink",
        severity=SeverityLevel.medium,
        url="http://target.test/#/search",
        evidence="Static sink matched URL fragment flow into innerHTML.",
        verified=False,
        confidence_score=60.0,
        detection_method="static_dom_sink",
    )

    strength = _orchestrator()._classify_evidence_strength(finding)

    assert strength == EvidenceStrength.probable


def test_low_risk_coverage_note_is_informational() -> None:
    finding = Finding(
        category=OwaspCategory.a02,
        vuln_type="Scanner Coverage Note",
        severity=SeverityLevel.low,
        url="http://target.test/",
        evidence="Browser crawling was unavailable.",
        verified=False,
        confidence_score=0.0,
        detection_method="heuristic",
    )

    strength = _orchestrator()._classify_evidence_strength(finding)

    assert strength == EvidenceStrength.informational


def test_detector_coverage_request_counts_use_module_aliases() -> None:
    orchestrator = _orchestrator()
    metrics = [
        DetectorCoverageMetric(detector="authentication_failures"),
        DetectorCoverageMetric(detector="file_inclusion"),
        DetectorCoverageMetric(detector="injection_sql_command"),
    ]

    orchestrator._apply_detector_request_counts(
        metrics,
        {"auth": 3, "lfi": 2, "rfi": 1, "sqli": 4},
    )

    by_detector = {metric.detector: metric for metric in metrics}
    assert by_detector["authentication_failures"].requests_sent == 3
    assert by_detector["file_inclusion"].requests_sent == 3
    assert by_detector["injection_sql_command"].requests_sent == 4


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
