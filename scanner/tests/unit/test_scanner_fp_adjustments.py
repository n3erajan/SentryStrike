from types import SimpleNamespace

from app.core.detectors.base_detector import Finding
from app.core.crawler.models import RequestObservation
from app.core.scanner import (
    ATTACK_SURFACE_BACKED_DETECTORS,
    SPECIALIZED_INPUT_DETECTORS,
    ScanOrchestrator,
)
from shared.models.scan import (
    AuthCoverage,
    DetectorCoverageMetric,
    EvidenceStrengthBreakdown,
    ReportMetadata,
    ScanStatistics,
    SpaApiCoverage,
)
from shared.models.vulnerability import (
    AiAnalysis,
    AiVerdict,
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
        detection_evidence={
            "timing_delta_ms": 5100,
            "parameter_location": ["json_body"],
            "request_template": [{"json_body": {"id": "7", "name": "record"}}],
            "status_code": [200],
        },
        verified=True,
    )

    vulnerability = _orchestrator()._to_vulnerability(finding)

    assert vulnerability.evidence.verified is True
    assert vulnerability.evidence.confidence_score == 90.0
    assert vulnerability.evidence.detection_method == "time_based"
    assert vulnerability.evidence.detection_evidence == {
        "timing_delta_ms": 5100,
        "parameter_location": ["json_body"],
        "request_template": [{"json_body": {"id": "7", "name": "record"}}],
        "status_code": [200],
    }
    assert vulnerability.location.parameter_location == "json_body"
    assert vulnerability.verification_target is not None
    assert vulnerability.verification_target.parameter_location == "json_body"
    assert vulnerability.verification_target.request_template == {
        "json_body": {"id": "7", "name": "record"}
    }
    assert vulnerability.verification_target.expected_status_code == 200
    assert vulnerability.cvss_score == 9.1
    assert vulnerability.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"


def test_to_vulnerability_redacts_credentials_in_evidence() -> None:
    """Evidence snippets must never persist real auth tokens, cookies, or the
    scan account password — they would leak durable credentials into the stored
    report and PDF, outliving the scan session."""
    secret_password = "#Yatra@9821"
    jwt = (
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9."
        "eyJzdGF0dXMiOiJzdWNjZXNzIn0.sigpart"
    )
    finding = Finding(
        category=OwaspCategory.a05,
        vuln_type="SQL Injection (Error-Based)",
        severity=SeverityLevel.critical,
        url="http://localhost:3000/rest/products/search",
        parameter="q",
        payload="' OR 1=1--",
        evidence=f"Verbose error echoed credential: {secret_password}",
        verification_request_snippet=(
            "POST /rest/user/login HTTP/1.1\r\n"
            "Host: localhost:3000\r\n"
            f"Authorization: Bearer {jwt}\r\n"
            "Cookie: language=en; token=opaque-session-xyz\r\n"
            f'{{"email":"admin@test","password":"{secret_password}"}}'
        ),
        verified=True,
    )

    vuln = _orchestrator()._to_vulnerability(finding, extra_secrets=[secret_password])

    req = vuln.evidence.request_snippet or ""
    resp = vuln.evidence.response_snippet or ""
    # Real secrets are scrubbed from both snippets ...
    assert secret_password not in req
    assert secret_password not in resp
    assert jwt not in req
    assert "opaque-session-xyz" not in req
    # ... while structure and benign context survive for reviewers.
    assert "Authorization:" in req
    assert "Cookie:" in req
    assert "language=en" in req
    assert "admin@test" in req
    assert "[REDACTED]" in req


def test_vulnerability_no_longer_carries_detected_at() -> None:
    """detected_at was identical across every finding (stamped at assembly time,
    not real detection time) and carried no signal beyond the report's
    generated_at — removed to avoid a misleading field."""
    assert "detected_at" not in Vulnerability.model_fields


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
    assert coverage.dynamic_status == "dynamic_failed"
    # The prominent honesty banner leads the warnings when dynamic discovery failed.
    assert scan.report_metadata.coverage_warnings[0].startswith("DYNAMIC DISCOVERY FAILED")
    assert any(
        warning
        == "SPA detected, but no browser runtime requests were observed. API coverage is static extraction only."
        for warning in scan.report_metadata.coverage_warnings
    )
    assert any("Browser crawling unavailable" in warning for warning in scan.report_metadata.coverage_warnings)


def test_dynamic_status_partial_when_browser_launched_but_no_requests() -> None:
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
        browser_available = True
        browser_error = "deadline exceeded after 2/10 routes"

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

    assert scan.report_metadata.spa_api_coverage.dynamic_status == "dynamic_partial"
    assert scan.report_metadata.coverage_warnings[0].startswith("DYNAMIC DISCOVERY PARTIAL")


def test_dynamic_status_ok_when_browser_observed_requests() -> None:
    class CrawlResult:
        is_spa = True
        assets = ["http://target.test/app.js"]
        routes = []
        api_endpoints = []
        parameters = []
        requests = [
            RequestObservation(url="http://target.test/api/me", method="GET"),
        ]
        dead_routes = []
        forms = []
        session_cookies = {}
        auth_headers = {"Authorization": "Bearer token"}
        auth_state = "authenticated_verified"
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

    assert scan.report_metadata.spa_api_coverage.dynamic_status == "dynamic_ok"
    assert not any(
        warning.startswith(("DYNAMIC DISCOVERY FAILED", "DYNAMIC DISCOVERY PARTIAL"))
        for warning in scan.report_metadata.coverage_warnings
    )


def test_classify_dynamic_status_matrix() -> None:
    classify = ScanOrchestrator._classify_dynamic_status
    # Non-SPA is always ok, regardless of browser state.
    assert classify(is_spa=False, browser_available=None, browser_error=None, browser_requests_observed=0) == "dynamic_ok"
    # SPA + no browser → failed.
    assert classify(is_spa=True, browser_available=False, browser_error="x", browser_requests_observed=0) == "dynamic_failed"
    assert classify(is_spa=True, browser_available=None, browser_error=None, browser_requests_observed=0) == "dynamic_failed"
    # SPA + browser up but zero requests or an error → partial.
    assert classify(is_spa=True, browser_available=True, browser_error=None, browser_requests_observed=0) == "dynamic_partial"
    assert classify(is_spa=True, browser_available=True, browser_error="truncated", browser_requests_observed=5) == "dynamic_partial"
    assert classify(
        is_spa=True,
        browser_available=True,
        browser_error=None,
        browser_requests_observed=5,
        browser_forms_submitted=1,
        post_bodies=0,
    ) == "dynamic_partial"
    # SPA + browser up + requests + no error → ok.
    assert classify(is_spa=True, browser_available=True, browser_error=None, browser_requests_observed=5) == "dynamic_ok"


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


def test_ssrf_inband_differential_without_callback_is_probable() -> None:
    finding = Finding(
        category=OwaspCategory.a01,
        vuln_type="Server-Side Request Forgery (SSRF) - Probable",
        severity=SeverityLevel.high,
        url="http://target.test/profile/image/url",
        evidence="Internal target timed out while the control returned immediately.",
        verified=False,
        confidence_score=60.0,
        detection_method="ssrf_inband_differential",
        detection_evidence={"oast_available": False},
    )

    strength = _orchestrator()._classify_evidence_strength(finding)

    assert strength == EvidenceStrength.probable


def test_ssrf_inband_ai_verdict_cannot_be_confirmed_without_callback() -> None:
    finding = Finding(
        category=OwaspCategory.a01,
        vuln_type="Server-Side Request Forgery (SSRF) - Probable",
        severity=SeverityLevel.medium,
        url="http://target.test/profile/image/url",
        verified=False,
        confidence_score=60.0,
        detection_method="ssrf_inband_differential",
        detection_evidence={
            "differential_reason": "internal target timed out",
            "control_samples": [{"status_code": 200}],
            "internal_samples": [{"status_code": 0}],
            "oast_available": False,
        },
    )
    orchestrator = _orchestrator()
    vulnerability = orchestrator._to_vulnerability(finding)
    grade = orchestrator.evidence_grader.grade(vulnerability)

    _fp_probability, verdict = orchestrator._calibrate_ai_false_positive(
        vulnerability,
        grade,
        0.05,
        "confirmed",
        "The internal target timed out.",
    )

    assert grade.proof_type == "ssrf_differential"
    assert verdict == AiVerdict.uncertain


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


def test_detector_metric_records_actionable_skip_reasons() -> None:
    class Detector:
        name = "xss"

    metric = _orchestrator()._detector_metric_for_findings(
        Detector(),
        [],
        {
            "urls": [],
            "forms": [],
            "parameters": [],
            "api_endpoints": [],
            "requests": [],
            "browser_available": False,
        },
    )

    assert metric.unverified_findings == 0
    assert metric.skipped_reasons["no_replayable_attack_targets"] == 1
    assert metric.skipped_reasons["browser_unavailable"] == 1
    assert metric.skipped_reasons["no_replayable_request_bodies"] == 1


def test_parameterized_detector_input_policy_is_explicit() -> None:
    assert {
        "access_control",
        "injection_sql_command",
        "xss",
        "file_inclusion",
        "ssrf",
        "open_redirect",
        "file_upload",
    } <= ATTACK_SURFACE_BACKED_DETECTORS
    assert {
        "security_headers",
        "crypto_failures",
        "sensitive_paths",
        "csrf",
        "authentication_failures",
    } <= SPECIALIZED_INPUT_DETECTORS
    assert ATTACK_SURFACE_BACKED_DETECTORS.isdisjoint(SPECIALIZED_INPUT_DETECTORS)


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
            evidence_strength=EvidenceStrength.confirmed_exploit,
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
    fp_prob, verdict = orchestrator._calibrate_ai_false_positive(
        vulnerability,
        grade,
        0.85,
        "likely_false_positive",
        "Reflected payload without SQL error.",
    )
    vulnerability.ai_analysis.false_positive_probability = fp_prob
    vulnerability.ai_analysis.verdict = verdict

    orchestrator._apply_ai_review_statuses([vulnerability])

    assert vulnerability.is_false_positive is False
    assert vulnerability.review_status == ReviewStatus.confirmed
    assert vulnerability.cvss_score == 9.1
    assert vulnerability.severity == SeverityLevel.critical
    # timing_strong proof type: ceiling is 0.15 (not 0.05) — the proof is
    # strong but indirect (time delta, not output), so the AI has slightly
    # more room than for error_echo/active_output.
    assert vulnerability.ai_analysis.false_positive_probability == 0.15
    assert vulnerability.ai_analysis.verdict == AiVerdict.confirmed


def test_ai_false_positive_estimate_never_suppresses_or_changes_cvss() -> None:
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
            evidence_strength=EvidenceStrength.possible,
        ),
        ai_analysis=AiAnalysis(
            verdict=AiVerdict.likely_false_positive,
            false_positive_probability=0.4,
            false_positive_reasoning="Payload was reflected but not executed.",
        ),
    )

    orchestrator = _orchestrator()
    orchestrator._apply_ai_review_statuses([vulnerability])

    assert vulnerability.is_false_positive is False
    assert vulnerability.review_status == ReviewStatus.needs_review
    assert vulnerability.cvss_score == 6.1
    assert vulnerability.severity == SeverityLevel.medium


def test_public_identical_auth_response_can_request_review_but_not_suppression() -> None:
    vulnerability = Vulnerability(
        id="v-public",
        category=OwaspCategory.a01,
        vuln_type="Unauthenticated API Data Exposure",
        severity=SeverityLevel.medium,
        cvss_score=5.5,
        location=LocationInfo(url="http://target.test/api/catalog"),
        evidence=Evidence(
            verified=True,
            evidence_strength=EvidenceStrength.confirmed_observation,
            detection_method="authorization_matrix",
            detection_evidence={
                "serves_public_data": True,
                "has_object_reference": False,
                "states": {
                    "unauthenticated": {
                        "status_code": 200,
                        "json_shape": ["name", "price"],
                        "secret_fields": [],
                    },
                    "low": {
                        "status_code": 200,
                        "json_shape": ["name", "price"],
                        "secret_fields": [],
                    },
                },
            },
        ),
    )

    orchestrator = _orchestrator()
    grade = orchestrator.evidence_grader.grade(vulnerability)
    fp_prob, verdict = orchestrator._calibrate_ai_false_positive(
        vulnerability,
        grade,
        0.9,
        "likely_false_positive",
        "responses_identical: true, so this is public by design",
    )
    vulnerability.ai_analysis.false_positive_probability = fp_prob
    vulnerability.ai_analysis.verdict = verdict
    orchestrator._apply_ai_review_statuses([vulnerability])

    assert fp_prob == 0.9
    assert verdict == AiVerdict.likely_false_positive
    assert vulnerability.review_status == ReviewStatus.needs_review
    assert vulnerability.is_false_positive is False
    assert vulnerability.cvss_score == 5.5


def test_unsupported_high_fp_verdict_is_downgraded_to_uncertain() -> None:
    vulnerability = Vulnerability(
        id="v-unsupported",
        category=OwaspCategory.a01,
        vuln_type="Missing Authorization on State-Changing Request",
        severity=SeverityLevel.high,
        cvss_score=8.0,
        location=LocationInfo(url="http://target.test/reviews"),
        evidence=Evidence(
            verified=True,
            evidence_strength=EvidenceStrength.confirmed_observation,
            detection_method="mutating_authz_differential",
            detection_evidence={"unauth_status": 201, "owner_status": 201},
        ),
    )

    orchestrator = _orchestrator()
    grade = orchestrator.evidence_grader.grade(vulnerability)
    fp_prob, verdict = orchestrator._calibrate_ai_false_positive(
        vulnerability,
        grade,
        0.9,
        "likely_false_positive",
        "The endpoint may be public by design.",
    )

    assert fp_prob == 0.49
    assert verdict == AiVerdict.uncertain


def test_priority_rank_does_not_use_ai_false_positive_probability() -> None:
    def make_vulnerability(vuln_id: str, fp_prob: float) -> Vulnerability:
        return Vulnerability(
            id=vuln_id,
            category=OwaspCategory.a05,
            vuln_type="SQL Injection (Error-Based)",
            severity=SeverityLevel.high,
            cvss_score=8.0,
            location=LocationInfo(url=f"http://target.test/{vuln_id}"),
            evidence=Evidence(evidence_strength=EvidenceStrength.confirmed_exploit),
            ai_analysis=AiAnalysis(
                exploitability=Exploitability.medium,
                false_positive_probability=fp_prob,
            ),
        )

    low_fp = make_vulnerability("low-fp", 0.0)
    high_fp = make_vulnerability("high-fp", 0.9)

    ranked = _orchestrator()._compute_priority_ranks([high_fp, low_fp])

    assert ranked[0].id == "high-fp"
    assert {v.ai_analysis.priority_rank for v in ranked} == {1, 2}
    assert ranked[0].cvss_score == ranked[1].cvss_score


def test_ai_prompt_separates_false_positive_from_impact_uncertainty() -> None:
    prompt = _orchestrator()._build_prompt(
        "Express, Node.js",
        ["type=Test; evidence_block=proof"],
        is_batch=False,
    )

    assert "A false positive means the reported vulnerability did NOT occur" in prompt
    assert "missing exploit chaining" in prompt
    assert "auth_confirmed" in prompt
    assert '"verdict": "confirmed"' in prompt
    assert "exactly confirmed, uncertain, or likely_false_positive" in prompt
    assert '"confidence"' not in prompt


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


def test_auth_coverage_uses_real_spa_surface_not_collapsed_url_list() -> None:
    """A browser-crawled SPA collapses ``urls`` to the shell (~1). Auth-coverage
    must report the true scanned surface (routes + API endpoints), and a real
    protected-target count from authorized 2xx data responses — not a hardcoded 1."""

    class Route:
        def __init__(self, url):
            self.url = url

    from app.core.crawler.models import ApiEndpoint

    class CrawlResult:
        is_spa = True
        assets = ["http://t.test/main.js"]
        urls = ["http://t.test/"]  # SPA shell only
        routes = [Route("http://t.test/#/login"), Route("http://t.test/#/profile")]
        api_endpoints = [ApiEndpoint(url="http://t.test/api/Cards"), ApiEndpoint(url="http://t.test/rest/basket/7")]
        parameters = []
        dead_routes = []
        forms = []
        session_cookies = {"token": "abc"}
        auth_headers = {}
        auth_state = "authenticated_verified"
        browser_available = True
        browser_error = None
        requests = [
            # Two distinct protected data endpoints reached with 2xx under the session.
            RequestObservation(url="http://t.test/api/Cards", method="GET",
                               response_status=200, response_content_type="application/json"),
            RequestObservation(url="http://t.test/rest/basket/7", method="GET",
                               response_status=200, response_content_type="application/json"),
            # Same endpoint different id -> collapses to one protected target.
            RequestObservation(url="http://t.test/api/Cards?id=9", method="GET",
                               response_status=200, response_content_type="application/json"),
            # A static asset 200 must NOT count.
            RequestObservation(url="http://t.test/main.js", method="GET",
                               response_status=200, response_content_type="application/javascript"),
            # A 401 must NOT count (not authorized).
            RequestObservation(url="http://t.test/api/Secret", method="GET",
                               response_status=401, response_content_type="application/json"),
        ]

    scan = SimpleNamespace(
        target_url="http://t.test/",
        statistics=ScanStatistics(),
        report_metadata=ReportMetadata(
            spa_api_coverage=SpaApiCoverage(),
            auth_coverage=AuthCoverage(),
            evidence_strength_breakdown=EvidenceStrengthBreakdown(),
        ),
    )
    _orchestrator()._update_crawl_metadata(scan, CrawlResult())

    ac = scan.report_metadata.auth_coverage
    # Real surface = union of shell + 2 routes + 2 api endpoints = 5, not 1.
    assert ac.authenticated_url_count == 5
    assert ac.unauthenticated_url_count == 0
    # Two distinct protected endpoints verified (Cards collapsed across ids); the
    # asset and the 401 are excluded. No longer the hardcoded 1.
    assert ac.protected_targets_verified == 2
    assert ac.session_cookies_present is True


def test_protected_targets_zero_when_unverified_session() -> None:
    class CrawlResult:
        is_spa = False
        assets = []
        urls = ["http://t.test/", "http://t.test/a"]
        routes = []
        api_endpoints = []
        parameters = []
        dead_routes = []
        forms = []
        session_cookies = {}
        auth_headers = {}
        auth_state = "unauthenticated"
        browser_available = True
        browser_error = None
        requests = [
            RequestObservation(url="http://t.test/api/x", method="POST",
                               response_status=200, response_content_type="application/json"),
        ]

    scan = SimpleNamespace(
        target_url="http://t.test/",
        statistics=ScanStatistics(),
        report_metadata=ReportMetadata(
            spa_api_coverage=SpaApiCoverage(),
            auth_coverage=AuthCoverage(),
            evidence_strength_breakdown=EvidenceStrengthBreakdown(),
        ),
    )
    _orchestrator()._update_crawl_metadata(scan, CrawlResult())

    ac = scan.report_metadata.auth_coverage
    # Unverified: surface counts as unauthenticated, protected count is 0.
    assert ac.authenticated_url_count == 0
    assert ac.unauthenticated_url_count == 2
    assert ac.protected_targets_verified == 0
