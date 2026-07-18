"""Comprehensive tests for the proof-type-based evidence grader.

Every detection method across all 14 detectors must be classified into a
proof type with the correct ceiling. These tests lock that contract in.
"""

import pytest

from app.core.evidence_grader import EvidenceGrader
from shared.models.vulnerability import (
    AuthContext,
    Evidence,
    EvidenceStrength,
    LocationInfo,
    OwaspCategory,
    SeverityLevel,
    Vulnerability,
)

grader = EvidenceGrader()


def _vuln(
    vuln_type: str,
    detection_method: str = "heuristic",
    detection_evidence: dict | None = None,
    verified: bool = True,
    confidence: float = 80.0,
    payload: str | None = None,
    response_snippet: str | None = None,
    category: OwaspCategory = OwaspCategory.a05,
) -> Vulnerability:
    return Vulnerability(
        id="test",
        category=category,
        vuln_type=vuln_type,
        severity=SeverityLevel.medium,
        cvss_score=5.0,
        location=LocationInfo(url="http://target.test/"),
        evidence=Evidence(
            payload=payload,
            response_snippet=response_snippet,
            verified=verified,
            confidence_score=confidence,
            detection_method=detection_method,
            detection_evidence=detection_evidence or {},
            evidence_strength=EvidenceStrength.probable,
            auth_context=AuthContext.unknown,
        ),
    )


# ---------------------------------------------------------------------------
# Proof-type classification: every detection method mapped
# ---------------------------------------------------------------------------

class TestActiveOutputMethods:
    """Methods where the proof is IN the response — ceiling 0.05."""

    @pytest.mark.parametrize("method", [
        "union_based",
        "boolean_differential",
        "command_output",
        "file_retrieval",
        "path_traversal_file_read",
        "stream_decoding_oracle",
        "remote_include_content_fingerprint",
        "remote_include_error_oracle_content_confirmed",
        "canary_verified",
        "context_breakout",
        "dom_xss_browser_execution",
        "token_bypass",
        "csrf_tamper_test",
        "ssrf_reflection",
        "ssrf_oast_callback",
        "location_header_redirect",
        "observed_external_location_redirect",
        "file_upload_execution",
        "content_type_bypass_execution",
        "double_extension_execution",
        "default_credentials_probe",
        "credential_stuffing_probe",
        "logout_token_reuse_probe",
        "nosql_boolean_operator",
        "mass_assignment_privilege_field",
        "jwt_active_forgery",
        "poison_null_byte_extension_bypass",
        "xxe_external_entity_file_read",
    ])
    def test_active_output_method(self, method):
        grade = grader.grade(_vuln("Test Vuln", detection_method=method))
        assert grade.proof_type == "active_output"
        assert grade.fp_ceiling == 0.05
        assert grade.grade == "A"


class TestErrorEchoMethods:
    """Methods where a DB/framework error string is echoed — ceiling 0.05."""

    @pytest.mark.parametrize("method", ["error_based", "wrapper_error_analysis"])
    def test_error_echo_method(self, method):
        grade = grader.grade(_vuln("SQL Injection (Error-Based)", detection_method=method))
        assert grade.proof_type == "error_echo"
        assert grade.fp_ceiling == 0.05
        assert grade.grade == "A"


class TestTimingMethods:
    """Timing methods — sub-classified by delta ratio."""

    def test_timing_strong_large_delta(self):
        vuln = _vuln("SQL Injection (Time-Based Blind)", detection_method="time_based",
                     detection_evidence={"baseline_mean_ms": 300, "delta_ms": 4800, "expected_sleep_ms": 5000})
        grade = grader.grade(vuln)
        assert grade.proof_type == "timing_strong"
        assert grade.fp_ceiling == 0.15

    def test_timing_strong_no_baseline_large_absolute(self):
        vuln = _vuln("SQL Injection (Time-Based Blind)", detection_method="time_based_blind",
                     detection_evidence={"delta_ms": 3000})
        grade = grader.grade(vuln)
        assert grade.proof_type == "timing_strong"

    def test_timing_weak_small_delta(self):
        vuln = _vuln("SQL Injection (Time-Based Blind)", detection_method="time_based",
                     detection_evidence={"baseline_mean_ms": 300, "delta_ms": 600, "expected_sleep_ms": 5000})
        grade = grader.grade(vuln)
        assert grade.proof_type == "timing_weak"
        assert grade.fp_ceiling == 0.40

    def test_timing_weak_small_absolute_no_baseline(self):
        vuln = _vuln("SQL Injection (Time-Based Blind)", detection_method="time_based",
                     detection_evidence={"delta_ms": 500})
        grade = grader.grade(vuln)
        assert grade.proof_type == "timing_weak"

    def test_timing_uses_legacy_timing_delta_ms_key(self):
        """Older detectors used 'timing_delta_ms' instead of 'delta_ms'."""
        vuln = _vuln("SQL Injection (Time-Based Blind)", detection_method="time_based",
                     detection_evidence={"baseline_mean_ms": 200, "timing_delta_ms": 4500})
        grade = grader.grade(vuln)
        assert grade.proof_type == "timing_strong"


class TestConfirmedAuthMethods:
    """Cross-identity/role proof is strong and receives a low FP ceiling."""

    @pytest.mark.parametrize("method", [
        "authorization_matrix_second_user",
        "authorization_matrix_privileged_baseline",
        "authorization_matrix_cross_identity",
        "differential_idor",
        "second_user_idor",
        "vertical_idor",
    ])
    def test_confirmed_auth_method(self, method):
        grade = grader.grade(_vuln("Insecure Direct Object Reference (IDOR)",
                                   detection_method=method, category=OwaspCategory.a01))
        assert grade.proof_type == "auth_confirmed"
        assert grade.fp_ceiling == 0.15
        assert grade.grade == "A"


class TestAuthDifferentialMethods:
    """Ambiguous access-control observations retain full AI review latitude."""

    @pytest.mark.parametrize("method", [
        "authorization_matrix",
        "mutating_authz_differential",
    ])
    def test_auth_diff_method(self, method):
        grade = grader.grade(_vuln("Unauthenticated API Data Exposure",
                                   detection_method=method, category=OwaspCategory.a01))
        assert grade.proof_type == "auth_differential"
        assert grade.fp_ceiling == 1.0

    @pytest.mark.parametrize("vuln_type", [
        "Unauthenticated API Data Exposure",
        "Horizontal Authorization Bypass",
        "Vertical Privilege Bypass",
        "Privilege Escalation",
        "Mass Assignment",
    ])
    def test_auth_diff_keyword_match(self, vuln_type):
        """Vuln-type keywords also classify, even if method is unknown."""
        grade = grader.grade(_vuln(vuln_type, detection_method="unknown_method",
                                   category=OwaspCategory.a01))
        assert grade.proof_type == "auth_differential"
        assert grade.fp_ceiling == 1.0


class TestPatternMatchMethods:
    """Pattern-match methods — regex hit could be reflected payload — ceiling 1.00."""

    @pytest.mark.parametrize("method", [
        "observed_exception_evidence",
        "path_bruteforce",
        "api_response_reflection",
        "content_type_bypass_response_evidence",
        "double_extension_response_evidence",
        "observed_response_content",
        "path_content_fingerprint",
        "observed_credential_disclosure",
    ])
    def test_pattern_match_method(self, method):
        grade = grader.grade(_vuln("Verbose Error Handling", detection_method=method))
        assert grade.proof_type == "pattern_match"
        assert grade.fp_ceiling == 1.0

    def test_reflection_prefix_is_pattern_match(self):
        """XSS reflection_* methods: reflection without execution — AI judges."""
        grade = grader.grade(_vuln("Reflected XSS", detection_method="reflection_attribute"))
        assert grade.proof_type == "pattern_match"
        assert grade.fp_ceiling == 1.0

    @pytest.mark.parametrize("vuln_type", [
        "Verbose Error Handling",
        "Credential / Config Disclosure in Response Body",
        "Debug / Metrics Endpoint Exposed",
        "Stack Trace Disclosure",
    ])
    def test_pattern_match_keyword_match(self, vuln_type):
        grade = grader.grade(_vuln(vuln_type, detection_method="unknown"))
        assert grade.proof_type == "pattern_match"
        assert grade.fp_ceiling == 1.0


def test_ssrf_inband_is_indirect_differential_not_pattern_match() -> None:
    vulnerability = _vuln(
        "Server-Side Request Forgery (SSRF) - Probable",
        detection_method="ssrf_inband_differential",
        detection_evidence={
            "control_target": "http://control.invalid/",
            "internal_target": "http://169.254.169.254/",
            "differential_reason": "internal target timed out",
            "signal_strength": "strong",
            "oast_available": False,
            "control_samples": [{"status_code": 200, "response_time_ms": 20}],
            "internal_samples": [{"status_code": 0, "response_time_ms": 3000}],
        },
        verified=False,
        category=OwaspCategory.a01,
    )

    grade = grader.grade(vulnerability)
    brief = grader.build_evidence_brief(vulnerability, grade)

    assert grade.proof_type == "ssrf_differential"
    assert grade.fp_ceiling == 0.49
    assert "not confirmed" in grade.reason.lower()
    assert "control_samples" in brief
    assert "internal_samples" in brief

class TestStructuralVulnTypes:
    """Structural vuln types — observation IS the proof — ceiling 0.10."""

    @pytest.mark.parametrize("vuln_type", [
        "Missing Security Header",
        "Weak TLS/SSL Configuration",
        "No TLS Configuration",
        "Insecure Session Cookie",
        "Cookie Without Secure Flag",
        "Authentication Form May Lack CSRF Protection",
        "Authentication Form Lacks CSRF Protection",
        "Credentials Transmitted via HTTP GET",
        "Admin / Privileged Endpoint",
        "Sensitive Path",
        "Lack of Brute-Force Protection on Login Form",
        "Captcha Bypass",
        "JWT Missing Expiration Claim",
        "Missing Rate Limit on Password Reset",
    ])
    def test_structural_vuln_type(self, vuln_type):
        grade = grader.grade(_vuln(vuln_type, detection_method="some_method",
                                   category=OwaspCategory.a02))
        assert grade.proof_type == "structural"
        assert grade.fp_ceiling == 0.10
        assert grade.grade == "B"

    def test_upload_allowlist_differential_is_structural_proof(self):
        grade = grader.grade(
            _vuln(
                "Missing File Type Validation",
                detection_method="upload_type_allowlist_bypass_differential",
            )
        )

        assert grade.proof_type == "structural"
        assert grade.fp_ceiling == 0.10


class TestHeuristicFallback:
    """Unknown methods with no keyword match → heuristic — ceiling 0.40."""

    def test_unknown_method_no_keyword_match(self):
        grade = grader.grade(_vuln("Some Unknown Vulnerability",
                                   detection_method="totally_unknown_method"))
        assert grade.proof_type == "heuristic"
        assert grade.fp_ceiling == 0.40


# ---------------------------------------------------------------------------
# Evidence brief construction
# ---------------------------------------------------------------------------

class TestEvidenceBrief:

    def test_brief_contains_proof_type(self):
        vuln = _vuln("SQL Injection (Error-Based)", detection_method="error_based",
                     detection_evidence={"errors_detected": ["syntax error at or near"]})
        grade = grader.grade(vuln)
        brief = grader.build_evidence_brief(vuln, grade)
        assert "PROOF TYPE: error_echo" in brief
        assert "PROOF SUMMARY:" in brief
        assert "PROOF WEAKNESSES:" in brief
        assert "JUDGE THIS:" in brief

    def test_brief_for_auth_diff_contains_responses_identical(self):
        vuln = _vuln("Unauthenticated API Data Exposure",
                     detection_method="authorization_matrix",
                     detection_evidence={
                         "serves_public_data": True,
                         "has_object_reference": False,
                         "states": {
                             "unauthenticated": {"status_code": 200, "json_shape": ["name", "price"], "secret_fields": []},
                             "low": {"status_code": 200, "json_shape": ["name", "price"], "secret_fields": []},
                         },
                     }, category=OwaspCategory.a01)
        grade = grader.grade(vuln)
        brief = grader.build_evidence_brief(vuln, grade)
        assert "responses_identical: True" in brief
        assert "secret_fields_in_anonymous_response: none" in brief
        assert "public" in brief.lower()

    def test_brief_for_auth_diff_contains_secret_fields(self):
        vuln = _vuln("Unauthenticated API Data Exposure",
                     detection_method="authorization_matrix",
                     detection_evidence={
                         "serves_public_data": False,
                         "has_object_reference": True,
                         "states": {
                             "unauthenticated": {"status_code": 200, "json_shape": ["password", "email"], "secret_fields": ["password"]},
                             "low": {"status_code": 200, "json_shape": ["password", "email"], "secret_fields": ["password"]},
                         },
                     }, category=OwaspCategory.a01)
        grade = grader.grade(vuln)
        brief = grader.build_evidence_brief(vuln, grade)
        assert "responses_identical: False" in brief
        assert "password" in brief
        assert "object_scoped_request: True" in brief

    def test_brief_for_auth_diff_accepts_deduplicated_state_lists(self):
        """Deduplication list-wraps every evidence value, including states."""
        vuln = _vuln(
            "Insecure Direct Object Reference (IDOR)",
            detection_method="authorization_matrix_second_user",
            detection_evidence={
                "serves_public_data": [None],
                "has_object_reference": [True],
                "admin_like": [False],
                "states": [
                    {
                        "unauthenticated": {
                            "status_code": 401,
                            "json_shape": ["error"],
                            "identifiers": [],
                            "secret_fields": [],
                        },
                        "low": {
                            "status_code": 200,
                            "json_shape": ["data.id", "data.email"],
                            "identifiers": ["id=42"],
                            "secret_fields": ["data.email"],
                        },
                        "second": {
                            "status_code": 200,
                            "json_shape": ["data.id", "data.email"],
                            "identifiers": ["id=42"],
                            "secret_fields": ["data.email"],
                        },
                    }
                ],
            },
            category=OwaspCategory.a01,
        )

        grade = grader.grade(vuln)
        brief = grader.build_evidence_brief(vuln, grade)

        assert grade.proof_type == "auth_confirmed"
        assert "anonymous_response: HTTP 401" in brief
        assert "authenticated_response: HTTP 200" in brief
        assert "second_user_response: HTTP 200" in brief
        assert "shared_identifiers_low_vs_second: ['id=42']" in brief
        assert "secret_fields_in_authenticated_responses: ['data.email']" in brief
        assert "object_scoped_request: True" in brief

    def test_brief_for_deduplicated_idor_includes_top_level_shared_identifiers(self):
        vuln = _vuln(
            "Insecure Direct Object Reference (IDOR)",
            detection_method="second_user_idor",
            detection_evidence={
                "parameter_location": ["json_body"],
                "shared_identifiers": [["userid=25"]],
            },
            category=OwaspCategory.a01,
        )

        grade = grader.grade(vuln)
        brief = grader.build_evidence_brief(vuln, grade)

        assert "shared_identifiers_low_vs_second: ['userid=25']" in brief
        assert "secret_fields_in_anonymous_response" not in brief

    def test_brief_for_timing_contains_delta(self):
        vuln = _vuln("SQL Injection (Time-Based Blind)", detection_method="time_based",
                     detection_evidence={"baseline_mean_ms": 300, "injected_mean_ms": 5100,
                                         "delta_ms": 4800, "expected_sleep_ms": 5000})
        grade = grader.grade(vuln)
        brief = grader.build_evidence_brief(vuln, grade)
        assert "baseline_mean_ms: 300" in brief
        assert "delta_ms: 4800" in brief
        assert "expected_sleep_ms: 5000" in brief

    def test_timing_grade_accepts_deduplicated_scalar_lists(self):
        vuln = _vuln(
            "SQL Injection (Time-Based Blind)",
            detection_method="time_based",
            detection_evidence={
                "baseline_mean_ms": [200],
                "injected_mean_ms": [5000],
                "delta_ms": [4800],
                "expected_sleep_ms": [5000],
                "baseline_times_ms": [[190, 200, 210]],
            },
        )

        grade = grader.grade(vuln)
        brief = grader.build_evidence_brief(vuln, grade)

        assert grade.proof_type == "timing_strong"
        assert "baseline_mean_ms: 200" in brief
        assert "delta_ms: 4800" in brief
        assert "baseline_samples: [190, 200, 210]" in brief

    def test_brief_for_pattern_match_detects_reflected_payload(self):
        vuln = _vuln("Verbose Error Handling", detection_method="observed_exception_evidence",
                     payload="' OR 1=1--",
                     response_snippet="Error: syntax error near ' OR 1=1--'")
        grade = grader.grade(vuln)
        brief = grader.build_evidence_brief(vuln, grade)
        assert "payload_reflected_in_response: true" in brief

    def test_brief_for_pattern_match_no_reflection(self):
        vuln = _vuln("Verbose Error Handling", detection_method="observed_exception_evidence",
                     payload="' OR 1=1--",
                     response_snippet="Traceback (most recent call last):\n  File /app/views.py")
        grade = grader.grade(vuln)
        brief = grader.build_evidence_brief(vuln, grade)
        assert "payload_reflected_in_response: false" in brief

    def test_brief_for_active_output_includes_canary_url(self):
        """File-upload execution findings must surface the canary URL as proof."""
        vuln = _vuln("Unrestricted File Upload", detection_method="file_upload_execution",
                     payload="test.php",
                     detection_evidence={
                         "canary_executed": True,
                         "accessible_url": "http://target.test/uploads/test.php",
                         "uploaded_filename": "test.php",
                     })
        grade = grader.grade(vuln)
        brief = grader.build_evidence_brief(vuln, grade)
        assert "accessible_url" in brief
        assert "canary_executed: True" in brief

    def test_brief_for_nosql_boolean_operator_summarizes_both_controls(self):
        vuln = _vuln(
            "NoSQL Injection (Boolean Operator)",
            detection_method="nosql_boolean_operator",
            detection_evidence={
                "first_family": [{
                    "family": "ne_eq",
                    "true_status": 200,
                    "false_status": 500,
                    "similarity": 0.01,
                }],
                "confirm_family": [{
                    "family": "gt_lt",
                    "true_status": 200,
                    "false_status": 200,
                    "similarity": 0.02,
                }],
            },
        )

        grade = grader.grade(vuln)
        brief = grader.build_evidence_brief(vuln, grade)

        assert grade.proof_type == "active_output"
        assert "first_family: family=ne_eq" in brief
        assert "confirm_family: family=gt_lt" in brief

    def test_brief_for_jwt_forgery_surfaces_acceptance_oracle(self):
        vuln = _vuln(
            "JWT alg=none Forgery Accepted",
            detection_method="jwt_active_forgery",
            detection_evidence={
                "forgery": ["alg=none"],
                "proof_mode": ["identity-reflection"],
                "forged_status": [200],
            },
        )

        grade = grader.grade(vuln)
        brief = grader.build_evidence_brief(vuln, grade)

        assert grade.proof_type == "active_output"
        assert "forgery: alg=none" in brief
        assert "proof_mode: identity-reflection" in brief
        assert "forged_status: 200" in brief

    def test_brief_falls_back_to_response_snippet_when_no_structured_evidence(self):
        """When a detector sets no detection_evidence, the brief still gives
        the AI the response snippet to evaluate — never an empty PROOF MARKERS."""
        vuln = _vuln("Some Vulnerability", detection_method="unknown_method",
                     payload="test-payload",
                     response_snippet="HTTP 200 — some response body here",
                     detection_evidence={})
        grade = grader.grade(vuln)
        brief = grader.build_evidence_brief(vuln, grade)
        assert "response_excerpt" in brief or "payload" in brief

    def test_brief_does_not_contain_detector_verified(self):
        """The brief must NOT expose detector_verified/confidence — those cause
        circular reasoning where the AI defers to the detector's verdict."""
        vuln = _vuln("Test", detection_method="error_based", verified=True, confidence=95.0)
        grade = grader.grade(vuln)
        brief = grader.build_evidence_brief(vuln, grade)
        assert "detector_verified" not in brief
        assert "detector_confidence" not in brief


# ---------------------------------------------------------------------------
# Proof-type ceiling correctness (the key behavioral contract)
# ---------------------------------------------------------------------------

class TestCeilingBehavior:

    def test_auth_differential_allows_full_fp_from_ai(self):
        """The whole point: auth_differential has no ceiling so the AI can
        flag detector-verified false positives freely."""
        vuln = _vuln("Unauthenticated API Data Exposure",
                     detection_method="authorization_matrix",
                     verified=True, confidence=88.0, category=OwaspCategory.a01)
        grade = grader.grade(vuln)
        assert grade.fp_ceiling == 1.0
        # Even though verified=True + confidence=88, the AI can output fp=0.9

    def test_error_echo_protects_real_sqli(self):
        """Genuine SQLi error echo is protected — AI cannot dismiss it."""
        vuln = _vuln("SQL Injection (Error-Based)", detection_method="error_based",
                     verified=True, confidence=95.0,
                     detection_evidence={"errors_detected": ["syntax error at or near"]})
        grade = grader.grade(vuln)
        assert grade.fp_ceiling == 0.05

    def test_timing_strong_protects_real_sqli(self):
        vuln = _vuln("SQL Injection (Time-Based Blind)", detection_method="time_based",
                     verified=True, confidence=90.0,
                     detection_evidence={"baseline_mean_ms": 200, "delta_ms": 4800})
        grade = grader.grade(vuln)
        assert grade.fp_ceiling == 0.15

    def test_timing_weak_allows_ai_judgment(self):
        """Borderline timing — AI should be able to flag as FP."""
        vuln = _vuln("SQL Injection (Time-Based Blind)", detection_method="time_based",
                     verified=True, confidence=75.0,
                     detection_evidence={"baseline_mean_ms": 300, "delta_ms": 600})
        grade = grader.grade(vuln)
        assert grade.fp_ceiling == 0.40

    def test_pattern_match_allows_full_fp_from_ai(self):
        vuln = _vuln("Verbose Error Handling", detection_method="observed_exception_evidence",
                     verified=True, confidence=85.0)
        grade = grader.grade(vuln)
        assert grade.fp_ceiling == 1.0
