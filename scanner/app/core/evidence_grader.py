"""Proof-type-based evidence characterization for false-positive adjudication.

The grader classifies each finding's *proof* — what kind of evidence
demonstrates the vulnerability — and sets a false-positive ceiling that
reflects how undeniable that proof is.

The key insight: ``verified=True`` means different things for different finding
types. For SQLi error-based, ``verified`` means "we saw a DB error string
echoed" — genuine proof. For access-control data-exposure, ``verified`` means
"the request returned HTTP 200" — not proof of anything. The grader now
distinguishes these cases via proof types instead of trusting detector
self-verification uniformly.

Proof types and ceilings
------------------------
active_output     — command output / file contents / canary execution  → 0.05
error_echo         — DB/framework error string causally connected       → 0.05
structural         — missing header / TLS / admin path (absence IS vuln) → 0.10
timing_strong      — delta >=5x baseline, large absolute delta          → 0.15
timing_weak        — delta <5x baseline or not reproduced                → 0.40
auth_differential  — access-control / IDOR (200 OK is not proof)        → 1.00
pattern_match      — verbose error / path disclosure (regex hit)        → 1.00
heuristic          — observable but no active proof                     → 0.40

For ``auth_differential`` and ``pattern_match`` the ceiling is 1.00 (no cap)
so the AI can flag false positives freely — but it receives a discriminative
evidence brief (proof markers + weaknesses + judge question) that tells it
exactly what to evaluate, so its judgment is grounded rather than open-ended.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from shared.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Grade result
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EvidenceGrade:
    """Proof characterization + false-positive ceiling for a single finding."""

    grade: str              # "A"-"D" (backward-compat for report display)
    fp_ceiling: float       # Max false-positive probability the AI may assign
    reason: str             # Human-readable explanation
    proof_type: str = ""    # active_output|error_echo|structural|timing_strong|timing_weak|auth_differential|pattern_match|heuristic
    proof_summary: str = "" # One-line description of what the proof is
    proof_weaknesses: str = "" # What could make this a false positive
    judge_question: str = ""   # What the AI should evaluate


# ---------------------------------------------------------------------------
# Proof-type classification tables
# ---------------------------------------------------------------------------

# Detection methods whose output constitutes undeniable proof — the proof
# is IN the response (command output, file contents, canary execution, data
# extraction, boolean differential, CSRF token bypass).
_ACTIVE_OUTPUT_METHODS: frozenset[str] = frozenset({
    # SQLi — boolean/union extract data from the DB
    "union_based",
    "boolean_differential",
    # Command injection — command output in response
    "command_output",
    # File inclusion — file contents retrieved
    "file_retrieval",
    "path_traversal_file_read",
    "stream_decoding_oracle",
    "remote_include_content_fingerprint",
    "remote_include_error_oracle_content_confirmed",
    # XSS — browser-confirmed execution
    "canary_verified",
    "context_breakout",
    "dom_xss_browser_execution",
    # CSRF — token tampering proved the request succeeded without valid token
    "token_bypass",
    "csrf_tamper_test",
    # SSRF — server fetched internal content (reflected) or OAST callback received
    "ssrf_reflection",
    "ssrf_oast_callback",
    # Open redirect — redirect observed (Location header or external redirect)
    "location_header_redirect",
    "observed_external_location_redirect",
    # File upload — uploaded file executed / bypassed content-type check
    "file_upload_execution",
    "content_type_bypass_execution",
    "double_extension_execution",
    # Auth — default creds / credential stuffing succeeded (login confirmed)
    "default_credentials_probe",
    "credential_stuffing_probe",
    # Auth — token still valid after logout (proof: reused token worked)
    "logout_token_reuse_probe",
    "stream_decoding_oracle",
    "remote_include_error_oracle",
})

# Detection methods where a DB/framework error string is echoed — the error
# text IS the proof.
_ERROR_ECHO_METHODS: frozenset[str] = frozenset({
    "error_based",
    "wrapper_error_analysis",
})

# Timing-based detection methods — sub-classified strong/weak by delta ratio.
_TIMING_METHODS: frozenset[str] = frozenset({
    "time_based",
    "time_based_blind",
})

# Access-control detection methods — "200 OK" is not proof; AI must judge
# whether the data is genuinely restricted.
_AUTH_DIFF_METHODS: frozenset[str] = frozenset({
    "authorization_matrix",
    "authorization_matrix_second_user",
    "authorization_matrix_privileged_baseline",
    "mass_assignment_privilege_field",
    "mutating_authz_differential",
    "differential_idor",
    "second_user_idor",
    "vertical_idor",
})

_AUTH_DIFF_KEYWORDS: tuple[str, ...] = (
    "unauthenticated api data exposure",
    "insecure direct object reference",
    "idor",
    "horizontal authorization bypass",
    "vertical privilege bypass",
    "privilege escalation",
    "privilege bypass",
    "mass assignment",
    "access control",
    "authorization bypass",
    "forced browsing",
)

# Pattern-match methods — a regex hit on the response body could be a genuine
# error, reflected payload, or normal page content. The AI must judge.
_PATTERN_MATCH_METHODS: frozenset[str] = frozenset({
    "observed_exception_evidence",
    "path_bruteforce",
    "api_response_reflection",
    "ssrf_inband_differential",
    "content_type_bypass_response_evidence",
    "double_extension_response_evidence",
    "observed_response_content",
    "path_content_fingerprint",
    "observed_credential_disclosure",
})

_PATTERN_MATCH_KEYWORDS: tuple[str, ...] = (
    "verbose error",
    "exception handling",
    "stack trace",
    "error handling",
    "credential",
    "config disclosure",
    "debug",
    "metrics endpoint",
)

# Structural vuln types — the observation itself IS the proof (missing header,
# TLS absence, admin path reachability, GET credentials, CSRF token absence,
# brute-force absence, captcha absence, cookie attribute issues).
_STRUCTURAL_VULN_KEYWORDS: tuple[str, ...] = (
    "missing security header",
    "weak content security policy",
    "cors misconfiguration",
    "missing cache-control",
    "information disclosure in header",
    "server banner",
    "insecure transport",
    "weak tls",
    "ssl configuration",
    "no tls configuration",
    "no tls",
    "credentials transmitted via http get",
    "credential / token exposed",
    "sensitive data in url",
    "sensitive credential",
    "password in get",
    "credentials via get",
    "insecure session cookie",
    "cookie without secure flag",
    "cookie attribute",
    "admin / privileged endpoint",
    "admin endpoint",
    "privileged endpoint",
    "well-known admin",
    "sensitive path",
    "admin panel",
    "phpmyadmin",
    "sensitive file exposure",
    "authentication form may lack csrf",
    "authentication form lacks csrf",
    "mixed content",
    "authentication endpoint served over plaintext",
    "brute-force",
    "brute force",
    "captcha",
    "mfa",
    "rate limit",
    "password change",
    "token enforcement",
    "jwt missing",
    "missing expiration",
)

# Strong evidence-blob keywords (for the legacy Grade A path).
_STRONG_EVIDENCE_KEYWORDS: tuple[str, ...] = (
    "root:x:0",
    "uid=",
    "gid=",
    "pdoexception",
    "you have an error in your sql syntax",
    "sqlstate",
    "boot loader",
    "[extensions]",
    "<script>alert",
    "canary_verified",
    "time_delta",
)

# Ceiling and grade letter per proof type.
_PROOF_CEILINGS: dict[str, float] = {
    "active_output": 0.05,
    "error_echo": 0.05,
    "structural": 0.10,
    "timing_strong": 0.15,
    "timing_weak": 0.40,
    "auth_differential": 1.00,
    "pattern_match": 1.00,
    "heuristic": 0.40,
}

_PROOF_GRADE_LETTERS: dict[str, str] = {
    "active_output": "A",
    "error_echo": "A",
    "structural": "B",
    "timing_strong": "A",
    "timing_weak": "C",
    "auth_differential": "C",
    "pattern_match": "C",
    "heuristic": "C",
}


# ---------------------------------------------------------------------------
# Grader
# ---------------------------------------------------------------------------

class EvidenceGrader:
    """Classifies each finding's proof type and sets a false-positive ceiling.

    Usage::

        grader = EvidenceGrader()
        grade = grader.grade(vulnerability)
        brief = grader.build_evidence_brief(vulnerability, grade)
        # grade.fp_ceiling is the max FP probability the AI may assign
        # brief is the discriminative evidence string for the AI prompt
    """

    def grade(self, vuln: Vulnerability) -> EvidenceGrade:
        """Characterize the finding's proof and set a false-positive ceiling.

        Interpretive proof types (auth_differential, pattern_match) get no
        ceiling so the AI can flag false positives — but it receives a
        discriminative evidence brief so its judgment is grounded.
        """
        proof_type = self._classify_proof_type(vuln)
        ceiling = _PROOF_CEILINGS.get(proof_type, 1.0)
        grade_letter = _PROOF_GRADE_LETTERS.get(proof_type, "D")

        proof_summary = self._proof_summary(proof_type, vuln)
        proof_weaknesses = self._proof_weaknesses(proof_type)
        judge_question = self._judge_question(proof_type)
        reason = self._grade_reason(proof_type, vuln)

        return EvidenceGrade(
            grade=grade_letter,
            fp_ceiling=ceiling,
            reason=reason,
            proof_type=proof_type,
            proof_summary=proof_summary,
            proof_weaknesses=proof_weaknesses,
            judge_question=judge_question,
        )

    def build_evidence_brief(self, vuln: Vulnerability, grade: EvidenceGrade) -> str:
        """Build a discriminative evidence brief for the AI prompt.

        Replaces the old descriptive evidence_block (which exposed
        ``detector_verified`` and ``detector_confidence_score`` — signals the
        AI deferred to circularly). The brief gives the AI the PROOF MARKERS
        and WEAKNESSES it needs to judge whether the finding is real, not the
        detector's self-assessment of confidence.
        """
        markers = self._extract_proof_markers(grade.proof_type, vuln)
        parts = [
            f"PROOF TYPE: {grade.proof_type}",
            f"PROOF SUMMARY: {grade.proof_summary}",
        ]
        if markers:
            parts.append(f"PROOF MARKERS:\n{markers}")
        if grade.proof_weaknesses:
            parts.append(f"PROOF WEAKNESSES: {grade.proof_weaknesses}")
        if grade.judge_question:
            parts.append(f"JUDGE THIS: {grade.judge_question}")
        return "\n".join(parts)

    # ------------------------------------------------------------------
    # Proof-type classification
    # ------------------------------------------------------------------

    def _classify_proof_type(self, vuln: Vulnerability) -> str:
        method = (vuln.evidence.detection_method or "").lower()
        vuln_lower = (vuln.vuln_type or "").lower()

        if method in _ACTIVE_OUTPUT_METHODS:
            return "active_output"

        if method in _ERROR_ECHO_METHODS:
            return "error_echo"

        if method in _TIMING_METHODS:
            return self._classify_timing(vuln.evidence.detection_evidence or {})

        if method in _AUTH_DIFF_METHODS or any(kw in vuln_lower for kw in _AUTH_DIFF_KEYWORDS):
            return "auth_differential"

        # XSS reflection_* methods: payload reflected in response but execution
        # not browser-confirmed. Reflection is not proof of execution — AI judges.
        if method.startswith("reflection_") or method in _PATTERN_MATCH_METHODS:
            return "pattern_match"

        # Structural checked BEFORE pattern_match keywords: some vuln types
        # (e.g. "Credentials Transmitted via HTTP GET") contain substrings that
        # would also match pattern_match keywords ("credential"), but the
        # structural classification is the correct one — the observation IS
        # the proof. Pattern-match keywords only catch non-structural types.
        if self._is_structural(vuln_lower):
            return "structural"

        if any(kw in vuln_lower for kw in _PATTERN_MATCH_KEYWORDS):
            return "pattern_match"

        return "heuristic"

    @staticmethod
    def _classify_timing(de: dict) -> str:
        """Sub-classify timing as strong/weak based on the delta ratio.

        Strong: delta >= 5x baseline (or >= 2000ms absolute with no baseline).
        Weak: delta < 5x baseline — could be network jitter.
        """
        delta = float(de.get("delta_ms", 0) or de.get("timing_delta_ms", 0) or 0)
        baseline = float(de.get("baseline_mean_ms", 0) or 0)

        if baseline > 0:
            return "timing_strong" if delta >= baseline * 5 else "timing_weak"
        # No baseline recorded — use absolute threshold (2s is well above
        # normal HTTP latency and clearly distinguishes SLEEP from jitter).
        return "timing_strong" if delta >= 2000 else "timing_weak"

    # ------------------------------------------------------------------
    # Proof markers extraction (for the evidence brief)
    # ------------------------------------------------------------------

    def _extract_proof_markers(self, proof_type: str, vuln: Vulnerability) -> str:
        """Extract the judgment-relevant evidence markers from detection_evidence.

        Per-proof-type: pulls the discriminative signals (not the detector's
        self-assessment) that the AI needs to evaluate the finding.
        """
        de = vuln.evidence.detection_evidence or {}
        lines: list[str] = []

        if proof_type == "auth_differential":
            lines = self._auth_diff_markers(de, vuln)
        elif proof_type == "pattern_match":
            lines = self._pattern_match_markers(de, vuln)
        elif proof_type in ("timing_strong", "timing_weak"):
            lines = self._timing_markers(de)
        elif proof_type == "error_echo":
            lines = self._error_echo_markers(de)
        elif proof_type == "active_output":
            lines = self._active_output_markers(de, vuln)
        else:
            # Structural / heuristic — generic markers
            if de:
                lines = [f"  - {k}: {self._truncate_value(v)}" for k, v in list(de.items())[:6]]
            # If no structured evidence, fall back to the response snippet so
            # the AI has SOMETHING to evaluate (detectors that only set prose
            # evidence — e.g. file_upload before this pass — still surface it
            # via _finding_response_snippet into response_snippet).
            if not lines and vuln.evidence.response_snippet:
                lines.append(f"  - response_excerpt: {self._truncate_value(vuln.evidence.response_snippet, 300)}")
            if not lines and vuln.evidence.payload:
                lines.append(f"  - payload: {self._truncate_value(vuln.evidence.payload)}")

        return "\n".join(lines)

    def _auth_diff_markers(self, de: dict, vuln: Vulnerability) -> list[str]:
        """Extract access-control differential markers for the AI to judge."""
        lines: list[str] = []
        states = de.get("states") or {}

        unauth = states.get("unauthenticated") or {}
        authed = states.get("low") or {}
        if unauth:
            lines.append(f"  - anonymous_response: HTTP {unauth.get('status_code', '?')}, "
                         f"fields: {unauth.get('json_shape', []) or 'non-JSON'}")
        if authed:
            lines.append(f"  - authenticated_response: HTTP {authed.get('status_code', '?')}, "
                         f"fields: {authed.get('json_shape', []) or 'non-JSON'}")

        # The key discriminative signal: are the responses identical?
        serves_public = de.get("serves_public_data")
        if serves_public is not None:
            lines.append(f"  - responses_identical: {serves_public}")
        elif unauth and authed:
            unauth_fields = set(unauth.get("json_shape") or [])
            authed_fields = set(authed.get("json_shape") or [])
            if unauth_fields and authed_fields and unauth_fields == authed_fields:
                lines.append("  - responses_identical: true (inferred — identical field sets)")

        # Secret fields: the one signal that overrides public-endpoint suppression
        secret_fields = (unauth.get("secret_fields") if isinstance(unauth, dict) else None) or []
        lines.append(f"  - secret_fields_in_anonymous_response: {secret_fields or 'none'}")

        if de.get("has_object_reference") is not None:
            lines.append(f"  - object_scoped_request: {de.get('has_object_reference')}")
        if de.get("admin_like"):
            lines.append("  - admin_like_url: true")

        return lines or [f"  - detection_evidence: {self._truncate_value(de)}"]

    def _pattern_match_markers(self, de: dict, vuln: Vulnerability) -> list[str]:
        """Extract pattern-match markers for the AI to judge."""
        lines: list[str] = []
        matched = de.get("matched_patterns") or de.get("errors_detected") or []
        if matched:
            lines.append(f"  - matched_patterns: {matched[:5]}")
        if de.get("http_status") or vuln.evidence.detection_evidence.get("http_status"):
            lines.append(f"  - http_status: {de.get('http_status', '?')}")
        if vuln.evidence.payload:
            lines.append(f"  - payload_sent: {self._truncate_value(vuln.evidence.payload)}")
        # Whether the matched text is the reflected payload (key FP signal)
        response_snippet = (vuln.evidence.response_snippet or "").lower()
        payload_lower = (vuln.evidence.payload or "").lower()
        if payload_lower and response_snippet and payload_lower in response_snippet:
            lines.append("  - payload_reflected_in_response: true (match may be echoed payload, not a genuine error)")
        else:
            lines.append("  - payload_reflected_in_response: false")
        return lines or [f"  - detection_evidence: {self._truncate_value(de)}"]

    def _timing_markers(self, de: dict) -> list[str]:
        """Extract timing differential markers for the AI to judge."""
        lines: list[str] = []
        baseline = de.get("baseline_mean_ms")
        injected = de.get("injected_mean_ms")
        delta = de.get("delta_ms") or de.get("timing_delta_ms")
        expected = de.get("expected_sleep_ms")
        if baseline is not None:
            lines.append(f"  - baseline_mean_ms: {baseline}")
        if injected is not None:
            lines.append(f"  - injected_mean_ms: {injected}")
        if delta is not None:
            lines.append(f"  - delta_ms: {delta}")
        if expected is not None:
            lines.append(f"  - expected_sleep_ms: {expected}")
        baseline_times = de.get("baseline_times_ms")
        if isinstance(baseline_times, list) and baseline_times:
            lines.append(f"  - baseline_samples: {baseline_times[:5]}")
        return lines or [f"  - timing_evidence: {self._truncate_value(de)}"]

    def _error_echo_markers(self, de: dict) -> list[str]:
        """Extract error-echo markers."""
        lines: list[str] = []
        errors = de.get("errors_detected") or []
        if errors:
            lines.append(f"  - errors_detected: {errors[:3]}")
        if de.get("first_payload"):
            lines.append(f"  - triggering_payload: {de.get('first_payload')}")
        if de.get("confirm_payload"):
            lines.append(f"  - confirming_payload: {de.get('confirm_payload')}")
        return lines or [f"  - detection_evidence: {self._truncate_value(de)}"]

    def _active_output_markers(self, de: dict, vuln: Vulnerability) -> list[str]:
        """Extract active-output proof markers."""
        lines: list[str] = []
        if vuln.evidence.payload:
            lines.append(f"  - payload: {self._truncate_value(vuln.evidence.payload)}")
        # Structured proof keys present in detection_evidence (file upload,
        # command injection, file inclusion, XSS DOM execution, etc.)
        for key in ("accessible_url", "canary_executed", "command_output",
                    "file_contents", "winning_vector", "injection_location",
                    "browser_execution_confirmed"):
            if de.get(key) is not None:
                lines.append(f"  - {key}: {self._truncate_value(de[key])}")
        if vuln.evidence.response_snippet:
            snippet = vuln.evidence.response_snippet[:300]
            lines.append(f"  - response_excerpt: {snippet}")
        return lines or [f"  - detection_evidence: {self._truncate_value(de)}"]

    # ------------------------------------------------------------------
    # Proof summaries, weaknesses, judge questions
    # ------------------------------------------------------------------

    def _proof_summary(self, proof_type: str, vuln: Vulnerability) -> str:
        summaries = {
            "active_output": "Active exploitation confirmed — the proof is in the response (command output, file contents, or code execution).",
            "error_echo": "A database/framework error string was echoed in the response, causally connected to the injected payload.",
            "structural": "The vulnerability is structural — the observation itself IS the proof (missing header, TLS absence, admin path reachability, etc.).",
            "timing_strong": "Strong timing differential — the response delay is large enough to clearly indicate sleep-based SQL injection.",
            "timing_weak": "Weak timing differential — the response delay is small and could be network jitter rather than SQL injection.",
            "auth_differential": "Access-control finding — an unauthenticated request returned data. This is only a real vulnerability if the data is genuinely restricted; a public endpoint returning public data is NOT a failure.",
            "pattern_match": "A pattern was matched in the response body — this could be a genuine error disclosure, reflected payload text, or normal page content.",
            "heuristic": "Heuristic observation without active exploitation proof — the finding is based on observation alone.",
        }
        return summaries.get(proof_type, "Uncharacterized evidence.")

    def _proof_weaknesses(self, proof_type: str) -> str:
        weaknesses = {
            "active_output": "None — the proof is in the response output. This is undeniable.",
            "error_echo": "None — the database error text is causally connected to the payload. This is strong proof.",
            "structural": "Minimal — the observation is the proof. A false positive would require the scanner to have misconfigured its request.",
            "timing_strong": "Time deltas can have non-SQL causes (network jitter, lock contention, background load). But a large delta matching the SLEEP argument is strong. This would be a false positive only if the delta does not scale with the sleep duration.",
            "timing_weak": "The timing delta is small and could be caused by network jitter, database load, or connection overhead rather than SQL SLEEP. If the delta does not clearly exceed normal latency variation, this is likely a false positive.",
            "auth_differential": "If the anonymous and authenticated responses are identical with no secret fields, the endpoint is public by design — there is no authorization boundary being bypassed. A public product catalog, language list, or configuration endpoint is NOT an access-control failure. This is real only if the anonymous response contains secret material (passwords/tokens/keys) or object-scoped data that an unauthenticated user should not access.",
            "pattern_match": "The matched pattern could be (a) a genuine error disclosure, (b) reflected payload text that happens to contain the pattern, or (c) normal page content. If the matched text is the injected payload echoed back, or if it appears in navigation HTML / normal page content, this is a false positive.",
            "heuristic": "The finding is based on observation without active exploitation. Evaluate whether the observation truly constitutes a vulnerability or is a benign application behavior.",
        }
        return weaknesses.get(proof_type, "")

    def _judge_question(self, proof_type: str) -> str:
        questions = {
            "active_output": "Is the proof in the response genuine? (It should be — do not flag as false positive.)",
            "error_echo": "Is the error string a genuine database/framework error, or could it be a benign message?",
            "structural": "Is this observation a genuine security gap? (It should be — do not flag as false positive.)",
            "timing_strong": "Does the timing delta clearly indicate SQL SLEEP execution, or could it be network noise?",
            "timing_weak": "Is the timing delta clearly caused by SQL SLEEP, or could it be network jitter or normal latency variation?",
            "auth_differential": "Is the data in the anonymous response genuinely restricted (secret fields or object-scoped data that requires authentication), or is this a public endpoint serving public data?",
            "pattern_match": "Is the matched text a genuine error disclosure causally connected to the payload, or could it be reflected payload text or normal page content?",
            "heuristic": "Does this observation constitute a real vulnerability, or is it a benign application behavior?",
        }
        return questions.get(proof_type, "")

    # ------------------------------------------------------------------
    # Reason (for report display — backward compat with evidence_grade_reason)
    # ------------------------------------------------------------------

    def _grade_reason(self, proof_type: str, vuln: Vulnerability) -> str:
        method = (vuln.evidence.detection_method or "").lower()
        confidence = vuln.evidence.confidence_score
        verified = vuln.evidence.verified

        if proof_type == "auth_differential":
            return (
                f"Access-control differential (method={method}): 'verified' means the "
                f"request returned 200, NOT that a boundary was bypassed. AI must judge "
                f"if the data is genuinely restricted."
            )
        if proof_type == "pattern_match":
            return (
                f"Pattern-match (method={method}): a regex hit on the response body. "
                f"The match could be reflected payload, normal content, or a genuine error. "
                f"AI must judge causal connection."
            )
        if proof_type == "timing_strong":
            de = vuln.evidence.detection_evidence or {}
            delta = de.get("delta_ms", de.get("timing_delta_ms", "?"))
            baseline = de.get("baseline_mean_ms", "?")
            return (
                f"Strong timing differential: delta={delta}ms vs baseline={baseline}ms "
                f"(method={method}, confidence={confidence:.0f}, verified={verified})"
            )
        if proof_type == "timing_weak":
            de = vuln.evidence.detection_evidence or {}
            delta = de.get("delta_ms", de.get("timing_delta_ms", "?"))
            return (
                f"Weak timing differential: delta={delta}ms — could be network jitter "
                f"(method={method}, confidence={confidence:.0f}, verified={verified})"
            )
        if proof_type == "active_output":
            return (
                f"Active exploitation confirmed: method={method}, "
                f"confidence={confidence:.0f}, verified={verified}"
            )
        if proof_type == "error_echo":
            return (
                f"Error echo confirmed: method={method}, "
                f"confidence={confidence:.0f}, verified={verified}"
            )
        if proof_type == "structural":
            return (
                f"Structural/observable finding: '{vuln.vuln_type}' — "
                f"the observation itself is the proof"
            )
        return (
            f"Heuristic evidence: confidence={confidence:.0f}, "
            f"verified={verified}, method={method}"
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_structural(vuln_lower: str) -> bool:
        return any(keyword in vuln_lower for keyword in _STRUCTURAL_VULN_KEYWORDS)

    @staticmethod
    def _truncate_value(value: object, max_len: int = 200) -> str:
        s = str(value)
        return s[:max_len] + "..." if len(s) > max_len else s
