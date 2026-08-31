"""Proof-type-based evidence characterization for false-positive adjudication.

The grader classifies each finding's *proof* - what kind of evidence
demonstrates the vulnerability - and sets a false-positive ceiling that
reflects how undeniable that proof is.

The key insight: ``verified=True`` means different things for different finding
types. For SQLi error-based, ``verified`` means "we saw a DB error string
echoed" - genuine proof. For access-control data-exposure, ``verified`` means
"the request returned HTTP 200" - not proof of anything. The grader now
distinguishes these cases via proof types instead of trusting detector
self-verification uniformly.

Proof types and ceilings
------------------------
active_output     - command output / file contents / canary execution  → 0.05
error_echo         - DB/framework error string causally connected       → 0.05
structural         - missing header / TLS / admin path (absence IS vuln) → 0.10
timing_strong      - delta >=5x baseline, large absolute delta          → 0.15
timing_weak        - delta <5x baseline or not reproduced                → 0.40
ssrf_differential  - repeated internal/control behavior difference       → 0.49
auth_confirmed     - cross-identity/object differential with proof      → 0.15
auth_differential  - ambiguous access-control / public-data question   → 1.00
pattern_match      - verbose error / path disclosure (regex hit)        → 1.00
heuristic          - observable but no active proof                     → 0.40

For ``auth_differential`` and ``pattern_match`` the ceiling is 1.00 (no cap)
so the AI can flag false positives freely - but it receives a discriminative
evidence brief (proof markers + weaknesses + judge question) that tells it
exactly what to evaluate, so its judgment is grounded rather than open-ended.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from shared.models.vulnerability import PROOF_CEILINGS, get_fp_ceiling
from shared.utils.evidence import server_response_bytes

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
    proof_type: str = ""    # active_output|error_echo|structural|timing_*|auth_confirmed|auth_differential|pattern_match|heuristic
    proof_summary: str = "" # One-line description of what the proof is
    proof_weaknesses: str = "" # What could make this a false positive
    judge_question: str = ""   # What the AI should evaluate


# ---------------------------------------------------------------------------
# Proof-type classification tables
# ---------------------------------------------------------------------------

# Detection methods whose output constitutes undeniable proof - the proof
# is IN the response (command output, file contents, canary execution, data
# extraction, boolean differential, CSRF token bypass).
_ACTIVE_OUTPUT_METHODS: frozenset[str] = frozenset({
    # SQLi - UNION extracts data into the response body. (Boolean-blind SQLi is
    # a true/false differential with no output; proof_type boolean_differential.)
    "union_based",
    # Command injection - command output in response
    "command_output",
    # File inclusion - file contents retrieved
    "file_retrieval",
    "path_traversal_file_read",
    "stream_decoding_oracle",
    # (RFI proven by the remote resource's own content appearing in the response
    # is proof_type remote_include - the fetched remote body, not reflection.)
    # XSS - reflected/stored payload present in the response body and executes.
    # (DOM XSS proven by the browser oracle with no HTTP-body dependency is
    # proof_type browser_execution, handled separately.)
    "canary_verified",
    "context_breakout",
    # CSRF - token tampering proved the request succeeded without valid token
    "token_bypass",
    "csrf_tamper_test",
    # SSRF - server fetched internal content and reflected it in the response.
    # (Blind SSRF proven by an OAST callback is proof_type oast_callback.)
    "ssrf_reflection",
    # Open redirect - redirect observed (Location header or external redirect)
    "location_header_redirect",
    "observed_external_location_redirect",
    # File upload - uploaded file executed / bypassed content-type check
    "file_upload_execution",
    "content_type_bypass_execution",
    "double_extension_execution",
    # Sequential failed-login attempts with no lockout/rate-limit/CAPTCHA - the
    # absence of protection across many processed attempts is the proof.
    "credential_stuffing_probe",
    # (Default-creds ACCEPTANCE is a login-success differential; proof_type
    # login_success - handled separately.)
    # Auth - token still valid after logout (proof: reused token worked)
    "logout_token_reuse_probe",
    "stream_decoding_oracle",
    "remote_include_error_oracle",
    # NoSQL - two independent true/false operator families changed output
    "nosql_boolean_operator",
    # Access/auth - the response proves the dangerous state was accepted
    "mass_assignment_privilege_field",
    "jwt_active_forgery",
    # File handling - protected content or an external entity was returned
    "poison_null_byte_extension_bypass",
    "xxe_external_entity_file_read",
})

# Blind boolean SQLi: proof is a reproducible TRUE/FALSE response-similarity
# split that tracks the injected boolean, not output in the response body.
_BOOLEAN_DIFF_METHODS: frozenset[str] = frozenset({
    "boolean_differential",
})

# RFI proven by content: the attacker-specified remote resource's own body
# appeared in the response (server-side fetch + include), not the URL reflected.
_REMOTE_INCLUDE_METHODS: frozenset[str] = frozenset({
    "remote_include_content_fingerprint",
    "remote_include_error_oracle_content_confirmed",
})

# Default/guessed credentials accepted: proof is a response consistent with
# authentication success and distinct from the failed-login baseline. (Only the
# credentials-ACCEPTED probe; credential_stuffing_probe reports lockout absence,
# a different class, and stays in active_output.)
_LOGIN_SUCCESS_METHODS: frozenset[str] = frozenset({
    "default_credentials_probe",
})

# Detection methods where a DB/framework error string is echoed - the error
# text IS the proof.
_ERROR_ECHO_METHODS: frozenset[str] = frozenset({
    "error_based",
    "wrapper_error_analysis",
})

# Timing-based detection methods - sub-classified strong/weak by delta ratio.
_TIMING_METHODS: frozenset[str] = frozenset({
    "time_based",
    "time_based_blind",
})

# Cross-context authorization methods that prove the relevant boundary was
# crossed. Unlike a generic anonymous HTTP 200, these compare two identities or
# roles and retain the shared object identifiers / restricted fields.
_AUTH_CONFIRMED_METHODS: frozenset[str] = frozenset({
    "authorization_matrix_second_user",
    "authorization_matrix_privileged_baseline",
    "authorization_matrix_cross_identity",
    "differential_idor",
    "second_user_idor",
    "vertical_idor",
})

# Access-control detection methods - "200 OK" is not proof; AI must judge
# whether the data is genuinely restricted.
_AUTH_DIFF_METHODS: frozenset[str] = frozenset({
    "authorization_matrix",
})

# Blind out-of-band proof: a correlated callback our OAST collaborator recorded
# (e.g. blind SSRF). The proof is the interaction record, not the HTTP response.
_OAST_CALLBACK_METHODS: frozenset[str] = frozenset({
    "ssrf_oast_callback",
})

# Browser-execution proof: our execution-only oracle fired in a real headless
# browser (DOM-based XSS). No HTTP-body reflection is expected or required.
_BROWSER_EXECUTION_METHODS: frozenset[str] = frozenset({
    "dom_xss_browser_execution",
})

# Write-authorization differential: a state-changing request accepted without the
# required authentication. Distinct from data-read auth_differential - here an
# accepted mutation is the signal, not restricted data returned.
_MUTATING_AUTHZ_METHODS: frozenset[str] = frozenset({
    "mutating_authz_differential",
})

# The observation itself proves the reported control is absent. These are
# method-specific because the vulnerability name alone can be ambiguous.
_STRUCTURAL_METHODS: frozenset[str] = frozenset({
    "upload_type_allowlist_bypass_differential",
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


# Pattern-match methods - a regex hit on the response body could be a genuine
# error, reflected payload, or normal page content. The AI must judge.
_PATTERN_MATCH_METHODS: frozenset[str] = frozenset({
    "observed_exception_evidence",
    "path_bruteforce",
    "api_response_reflection",
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

# Structural vuln types - the observation itself IS the proof (missing header,
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
_PROOF_GRADE_LETTERS: dict[str, str] = {
    "active_output": "A",
    "error_echo": "A",
    "structural": "B",
    "timing_strong": "A",
    "timing_weak": "C",
    "ssrf_differential": "C",
    "boolean_differential": "B",
    "oast_callback": "A",
    "browser_execution": "A",
    "remote_include": "A",
    "auth_confirmed": "A",
    "auth_differential": "C",
    "login_success": "A",
    "mutating_authz": "C",
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
        ceiling so the AI can flag false positives - but it receives a
        discriminative evidence brief so its judgment is grounded.
        """
        proof_type = self._classify_proof_type(vuln)
        ceiling = get_fp_ceiling(proof_type)
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
        ``detector_verified`` and ``detector_confidence_score`` - signals the
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

        if method in _OAST_CALLBACK_METHODS:
            return "oast_callback"

        if method in _BROWSER_EXECUTION_METHODS:
            return "browser_execution"

        if method in _REMOTE_INCLUDE_METHODS:
            return "remote_include"

        if method in _BOOLEAN_DIFF_METHODS:
            return "boolean_differential"

        if method in _LOGIN_SUCCESS_METHODS:
            return "login_success"

        if method in _MUTATING_AUTHZ_METHODS:
            return "mutating_authz"

        if method in _ERROR_ECHO_METHODS:
            return "error_echo"

        if method in _TIMING_METHODS:
            return self._classify_timing(self._to_dict(vuln.evidence.detection_evidence))

        if method == "ssrf_inband_differential":
            return "ssrf_differential"

        if method in _AUTH_CONFIRMED_METHODS:
            return "auth_confirmed"

        if method in _AUTH_DIFF_METHODS or any(kw in vuln_lower for kw in _AUTH_DIFF_KEYWORDS):
            return "auth_differential"

        # XSS reflection_* methods: payload reflected in response but execution
        # not browser-confirmed. Reflection is not proof of execution - AI judges.
        if method.startswith("reflection_") or method in _PATTERN_MATCH_METHODS:
            return "pattern_match"

        # Structural checked BEFORE pattern_match keywords: some vuln types
        # (e.g. "Credentials Transmitted via HTTP GET") contain substrings that
        # would also match pattern_match keywords ("credential"), but the
        # structural classification is the correct one - the observation IS
        # the proof. Pattern-match keywords only catch non-structural types.
        if method in _STRUCTURAL_METHODS or self._is_structural(vuln_lower):
            return "structural"

        if any(kw in vuln_lower for kw in _PATTERN_MATCH_KEYWORDS):
            return "pattern_match"

        return "heuristic"

    @staticmethod
    def _classify_timing(de: dict) -> str:
        """Sub-classify timing as strong/weak based on the delta ratio.

        Strong: delta >= 5x baseline (or >= 2000ms absolute with no baseline).
        Weak: delta < 5x baseline - could be network jitter.
        """
        delta_value = EvidenceGrader._first_value(de.get("delta_ms"))
        if delta_value is None:
            delta_value = EvidenceGrader._first_value(de.get("timing_delta_ms"))
        baseline_value = EvidenceGrader._first_value(de.get("baseline_mean_ms"))
        delta = float(delta_value or 0)
        baseline = float(baseline_value or 0)

        if baseline > 0:
            return "timing_strong" if delta >= baseline * 5 else "timing_weak"
        # No baseline recorded - use absolute threshold (2s is well above
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
        de = self._to_dict(vuln.evidence.detection_evidence)
        lines: list[str] = []

        if proof_type in ("auth_confirmed", "auth_differential"):
            lines = self._auth_diff_markers(de, vuln)
        elif proof_type == "pattern_match":
            lines = self._pattern_match_markers(de, vuln)
        elif proof_type in ("timing_strong", "timing_weak"):
            lines = self._timing_markers(de)
        elif proof_type == "ssrf_differential":
            lines = self._ssrf_differential_markers(de)
        elif proof_type == "oast_callback":
            lines = self._oast_callback_markers(de)
        elif proof_type == "browser_execution":
            lines = self._browser_execution_markers(de, vuln)
        elif proof_type == "remote_include":
            lines = self._remote_include_markers(de, vuln)
        elif proof_type == "boolean_differential":
            lines = self._boolean_differential_markers(de)
        elif proof_type == "login_success":
            lines = self._login_success_markers(de)
        elif proof_type == "mutating_authz":
            lines = self._mutating_authz_markers(de, vuln)
        elif proof_type == "error_echo":
            lines = self._error_echo_markers(de)
        elif proof_type == "active_output":
            lines = self._active_output_markers(de, vuln)
        else:
            # Structural / heuristic - generic markers
            if de:
                lines = [f"  - {k}: {self._truncate_value(v)}" for k, v in list(de.items())[:6]]
            # If no structured evidence, fall back to the response snippet so
            # the AI has SOMETHING to evaluate (detectors that only set prose
            # evidence - e.g. file_upload before this pass - still surface it
            # via _finding_response_snippet into response_snippet). Server bytes
            # only: the scanner's own verdict is not evidence for the model.
            if not lines:
                server_bytes = server_response_bytes(vuln.evidence.response_snippet)
                if server_bytes:
                    lines.append(f"  - response_excerpt: {self._truncate_value(server_bytes, 300)}")
            if not lines and vuln.evidence.payload:
                lines.append(f"  - payload: {self._truncate_value(vuln.evidence.payload)}")

        return "\n".join(lines)

    def _auth_diff_markers(self, de: dict, vuln: Vulnerability) -> list[str]:
        """Extract access-control differential markers for the AI to judge."""
        lines: list[str] = []
        # FindingDeduplicator preserves each distinct evidence value in a list.
        # Even one matrix observation therefore arrives as ``states=[{...}]``;
        # object-id route collapsing can produce several observations.
        state_sets = self._to_dicts(de.get("states"))
        role_profiles: dict[str, list[dict]] = {
            "unauthenticated": [],
            "low": [],
            "second": [],
            "privileged": [],
        }
        shared_identifiers: set[str] = set()

        for states in state_sets:
            profiles = {
                role: self._to_dict(states.get(role))
                for role in role_profiles
            }
            for role, profile in profiles.items():
                if profile:
                    role_profiles[role].append(profile)

            low_ids = {
                str(value)
                for value in self._flatten_values(profiles["low"].get("identifiers"))
            }
            second_ids = {
                str(value)
                for value in self._flatten_values(profiles["second"].get("identifiers"))
            }
            shared_identifiers.update(low_ids & second_ids)

        marker_names = {
            "unauthenticated": "anonymous_response",
            "low": "authenticated_response",
            "second": "second_user_response",
            "privileged": "privileged_response",
        }
        for role, profiles in role_profiles.items():
            if not profiles:
                continue
            statuses = self._profile_values(profiles, "status_code")
            fields = self._profile_values(profiles, "json_shape")
            status_text = statuses[0] if len(statuses) == 1 else statuses
            lines.append(
                f"  - {marker_names[role]}: HTTP {status_text}, "
                f"fields: {self._truncate_value(fields or 'non-JSON', 400)}"
            )

        shared_identifiers.update(
            str(value)
            for value in self._flatten_values(de.get("shared_identifiers"))
        )
        if shared_identifiers:
            lines.append(
                "  - shared_identifiers_low_vs_second: "
                f"{self._truncate_value(sorted(shared_identifiers), 400)}"
            )

        # The key discriminative signal: are the responses identical?
        public_flags = [
            value
            for value in self._flatten_values(de.get("serves_public_data"))
            if isinstance(value, bool)
        ]
        serves_public: bool | str | None = None
        if public_flags:
            if all(public_flags):
                serves_public = True
            elif not any(public_flags):
                serves_public = False
            else:
                serves_public = "mixed across observations"

        if serves_public is not None:
            lines.append(f"  - responses_identical: {serves_public}")
        elif role_profiles["unauthenticated"] and role_profiles["low"]:
            unauth_fields = set(self._profile_values(role_profiles["unauthenticated"], "json_shape"))
            authed_fields = set(self._profile_values(role_profiles["low"], "json_shape"))
            if unauth_fields and authed_fields and unauth_fields == authed_fields:
                lines.append("  - responses_identical: true (inferred - identical field sets)")

        # Horizontal IDOR/BOLA normally exposes restricted data in two authenticated
        # contexts while anonymous access is denied, so preserve both sides.
        anonymous_secret_fields = self._profile_values(
            role_profiles["unauthenticated"], "secret_fields"
        )
        if role_profiles["unauthenticated"]:
            lines.append(
                "  - secret_fields_in_anonymous_response: "
                f"{anonymous_secret_fields or 'none'}"
            )
        authenticated_secret_fields = self._profile_values(
            role_profiles["low"] + role_profiles["second"] + role_profiles["privileged"],
            "secret_fields",
        )
        if authenticated_secret_fields:
            lines.append(
                "  - secret_fields_in_authenticated_responses: "
                f"{self._truncate_value(authenticated_secret_fields, 400)}"
            )

        object_scope_flags = [
            value
            for value in self._flatten_values(de.get("has_object_reference"))
            if isinstance(value, bool)
        ]
        if object_scope_flags:
            lines.append(f"  - object_scoped_request: {any(object_scope_flags)}")
        admin_flags = [
            value
            for value in self._flatten_values(de.get("admin_like"))
            if isinstance(value, bool)
        ]
        if any(admin_flags):
            lines.append("  - admin_like_url: true")

        return lines or [f"  - detection_evidence: {self._truncate_value(de)}"]

    def _pattern_match_markers(self, de: dict, vuln: Vulnerability) -> list[str]:
        """Extract pattern-match markers for the AI to judge."""
        lines: list[str] = []
        matched = self._flatten_values(de.get("matched_patterns"))
        if not matched:
            matched = self._flatten_values(de.get("errors_detected"))
        if matched:
            lines.append(f"  - matched_patterns: {matched[:5]}")
        http_status = self._first_value(de.get("http_status"))
        if http_status is not None:
            lines.append(f"  - http_status: {http_status}")
        if vuln.evidence.payload:
            lines.append(f"  - payload_sent: {self._truncate_value(vuln.evidence.payload)}")
        # Whether the matched text is the reflected payload (key FP signal).
        # Compare against the TARGET's bytes only: the composite snippet's
        # "VERIFICATION EVIDENCE: ... triggered by '<payload>'" preamble quotes the
        # payload itself, which would otherwise report reflection that the server
        # never produced.
        response_snippet = server_response_bytes(vuln.evidence.response_snippet).lower()
        payload_lower = (vuln.evidence.payload or "").lower()
        if payload_lower and response_snippet and payload_lower in response_snippet:
            lines.append("  - payload_reflected_in_response: true (match may be echoed payload, not a genuine error)")
        else:
            lines.append("  - payload_reflected_in_response: false")
        return lines or [f"  - detection_evidence: {self._truncate_value(de)}"]

    def _timing_markers(self, de: dict) -> list[str]:
        """Extract timing differential markers for the AI to judge."""
        lines: list[str] = []
        baseline = self._first_value(de.get("baseline_mean_ms"))
        injected = self._first_value(de.get("injected_mean_ms"))
        delta = self._first_value(de.get("delta_ms"))
        if delta is None:
            delta = self._first_value(de.get("timing_delta_ms"))
        expected = self._first_value(de.get("expected_sleep_ms"))
        if baseline is not None:
            lines.append(f"  - baseline_mean_ms: {baseline}")
        if injected is not None:
            lines.append(f"  - injected_mean_ms: {injected}")
        if delta is not None:
            lines.append(f"  - delta_ms: {delta}")
        if expected is not None:
            lines.append(f"  - expected_sleep_ms: {expected}")
        baseline_times = self._flatten_values(de.get("baseline_times_ms"))
        if baseline_times:
            lines.append(f"  - baseline_samples: {baseline_times[:5]}")
        return lines or [f"  - timing_evidence: {self._truncate_value(de)}"]

    def _ssrf_differential_markers(self, de: dict) -> list[str]:
        lines: list[str] = []
        for key in (
            "control_target",
            "internal_target",
            "differential_reason",
            "signal_strength",
            "oast_available",
        ):
            value = self._first_value(de.get(key))
            if value is not None:
                lines.append(f"  - {key}: {self._truncate_value(value, 400)}")
        for key in ("control_samples", "internal_samples"):
            samples = self._flatten_values(de.get(key))
            if samples:
                lines.append(f"  - {key}: {self._truncate_value(samples[:4], 600)}")
        return lines or [f"  - differential_evidence: {self._truncate_value(de)}"]

    def _oast_callback_markers(self, de: dict) -> list[str]:
        """Surface the correlated out-of-band interaction - the proof for blind
        SSRF. The target reaching our uniquely-tokened collaborator URL is what
        confirms the server-side fetch; there is no HTTP response body to read,
        so the target's returned page is deliberately NOT surfaced here."""
        lines: list[str] = []
        interaction_id = self._first_value(de.get("interaction_id"))
        if interaction_id is not None:
            lines.append(
                "  - interaction_id (unique token we planted): "
                f"{self._truncate_value(interaction_id)}"
            )
        count = self._first_value(de.get("interaction_count"))
        if count is not None:
            lines.append(f"  - interaction_count: {self._truncate_value(count)}")
        interactions = [
            item
            for item in self._flatten_values(de.get("interactions"))
            if isinstance(item, dict)
        ]
        for interaction in interactions[:4]:
            lines.append(
                "  - callback_received: "
                f"source_ip={interaction.get('source_ip', '?')}, "
                f"method={interaction.get('method', '?')}, "
                f"path={interaction.get('path', '?')}, "
                f"received_at={interaction.get('received_at', '?')}"
            )
        readback = self._first_value(de.get("response_readback"))
        if readback is not None:
            lines.append(
                f"  - response_readback: {readback} "
                "(blind SSRF does not require any response readback)"
            )
        return lines or [f"  - detection_evidence: {self._truncate_value(de)}"]

    def _browser_execution_markers(self, de: dict, vuln: Vulnerability) -> list[str]:
        """Surface the execution proof for DOM XSS: our canaried callback fired in
        a real browser. The captured DOM excerpt is the page AFTER client-side
        execution, not the server's HTTP response body."""
        lines: list[str] = []
        if vuln.evidence.payload:
            lines.append(f"  - payload: {self._truncate_value(vuln.evidence.payload)}")
        for key in (
            "winning_vector",
            "injection_location",
            "winning_surface",
            "browser_execution_confirmed",
            "route_backed",
        ):
            value = self._first_value(de.get(key))
            if value is not None:
                lines.append(f"  - {key}: {self._truncate_value(value)}")
        events = self._flatten_values(de.get("execution_events"))
        if events:
            lines.append(f"  - execution_events: {self._truncate_value(events[:5], 400)}")
        excerpt = self._first_value(de.get("executed_dom_excerpt"))
        if excerpt:
            lines.append(
                "  - executed_dom_excerpt (rendered DOM AFTER execution, not the "
                f"HTTP response body): {self._truncate_value(excerpt, 600)}"
            )
        return lines or [f"  - detection_evidence: {self._truncate_value(de)}"]

    def _mutating_authz_markers(self, de: dict, vuln: Vulnerability) -> list[str]:
        """Surface the write-authorization signal: an unauthenticated state-changing
        request was accepted with the same processed status as the authenticated
        owner. The proof is the accepted mutation, not returned data."""
        lines: list[str] = []
        unauth = self._first_value(de.get("unauth_status"))
        owner = self._first_value(de.get("owner_status"))
        if unauth is not None:
            lines.append(f"  - unauth_status: {unauth}")
        if owner is not None:
            lines.append(f"  - owner_status: {owner}")
        # A processed 2xx/3xx status means the mutation ran; the detector already
        # drops matching 4xx/5xx statuses (which prove nothing about auth).
        try:
            processed = 200 <= int(owner) < 400 if owner is not None else None
        except (TypeError, ValueError):
            processed = None
        if processed is not None:
            lines.append(
                f"  - mutation_accepted_and_processed: {processed} "
                "(2xx/3xx means the state change actually ran)"
            )
        destructive = self._first_value(de.get("destructive_confirmed"))
        if destructive is not None:
            lines.append(f"  - destructive_confirmed_on_real_object: {destructive}")
        server_bytes = server_response_bytes(vuln.evidence.response_snippet)
        if server_bytes:
            lines.append(f"  - response_excerpt: {server_bytes[:300]}")
        return lines or [f"  - detection_evidence: {self._truncate_value(de)}"]

    def _boolean_differential_markers(self, de: dict) -> list[str]:
        """Surface the TRUE/FALSE response split - the discriminator for blind
        boolean SQLi. The proof is a reproducible difference that tracks the
        injected boolean, not any content in the response body."""
        lines: list[str] = []
        true_sim = self._first_value(de.get("confirm_true_sim"))
        false_sim = self._first_value(de.get("confirm_false_sim"))
        if true_sim is not None:
            lines.append(f"  - confirm_true_sim: {true_sim} (TRUE payload vs true-baseline)")
        if false_sim is not None:
            lines.append(f"  - confirm_false_sim: {false_sim} (FALSE payload vs true-baseline)")
        try:
            if true_sim is not None and false_sim is not None:
                delta = abs(float(true_sim) - float(false_sim))
                lines.append(
                    f"  - true_vs_false_delta: {delta:.4f} "
                    "(larger = clearer boolean control; must exceed baseline noise)"
                )
        except (TypeError, ValueError):
            pass
        context = self._first_value(de.get("injection_context"))
        if context is not None:
            lines.append(f"  - injection_context: {self._truncate_value(context)}")
        # Diff-focused signal: TRUE vs FALSE restricted to the region that varies,
        # so a real boolean-controlled difference is not diluted by page chrome.
        focused = self._first_value(de.get("focused_true_vs_false_sim"))
        if focused is not None:
            lines.append(
                f"  - focused_true_vs_false_sim: {focused} "
                "(TRUE vs FALSE in the varying region only; LOW = clear boolean control)"
            )
        fraction = self._first_value(de.get("varying_fraction"))
        if fraction is not None:
            lines.append(
                f"  - varying_fraction: {fraction} "
                "(share of the page that changed - explains a small whole-page delta)"
            )
        first_pair = self._to_dict(self._first_value(de.get("first_pair")))
        if first_pair:
            lines.append(
                "  - independent_pair: "
                f"true_sim={first_pair.get('baseline_similarity_to_true', '?')}, "
                f"false_sim={first_pair.get('baseline_similarity_to_false', '?')}"
            )
        return lines or [f"  - detection_evidence: {self._truncate_value(de)}"]

    def _remote_include_markers(self, de: dict, vuln: Vulnerability) -> list[str]:
        """Surface the remote-inclusion proof: which external URL was included and
        what content unique to it appeared in the response."""
        lines: list[str] = []
        target = self._first_value(de.get("remote_target"))
        if target is None and vuln.evidence.payload:
            target = vuln.evidence.payload
        if target is not None:
            lines.append(
                f"  - remote_target (external URL included): {self._truncate_value(target)}"
            )
        fingerprint = self._first_value(de.get("fingerprint"))
        if fingerprint is not None:
            lines.append(
                "  - fingerprint (content unique to the remote resource): "
                f"{self._truncate_value(fingerprint)}"
            )
        matched = self._first_value(de.get("matched"))
        if matched is not None:
            lines.append(f"  - remote_content_matched: {matched}")
        tokens = self._flatten_values(de.get("matched_tokens"))
        if tokens:
            lines.append(f"  - matched_tokens: {self._truncate_value(tokens[:6], 300)}")
        return lines or [f"  - detection_evidence: {self._truncate_value(de)}"]

    def _login_success_markers(self, de: dict) -> list[str]:
        """Surface the login-success differential: the credential pair tested and
        the post-auth signal that distinguished success from the failed-login
        baseline."""
        lines: list[str] = []
        pair = self._first_value(de.get("credential_pair"))
        if pair is not None:
            lines.append(f"  - credential_pair: {self._truncate_value(pair)}")
        baseline = self._first_value(de.get("baseline_status"))
        authed = self._first_value(de.get("authed_status"))
        if baseline is not None:
            lines.append(f"  - failed_login_baseline_status: {baseline}")
        if authed is not None:
            lines.append(f"  - credentialed_status: {authed}")
        delta = self._first_value(de.get("body_delta_bytes"))
        if delta is not None:
            lines.append(f"  - body_delta_bytes: {delta}")
        signal = self._first_value(de.get("post_auth_signal"))
        if signal is not None:
            lines.append(f"  - post_auth_signal: {self._truncate_value(signal)}")
        return lines or [f"  - detection_evidence: {self._truncate_value(de)}"]

    def _error_echo_markers(self, de: dict) -> list[str]:
        """Extract error-echo markers."""
        lines: list[str] = []
        errors = self._flatten_values(de.get("errors_detected"))
        if errors:
            lines.append(f"  - errors_detected: {errors[:3]}")
        first_payload = self._first_value(de.get("first_payload"))
        if first_payload:
            lines.append(f"  - triggering_payload: {first_payload}")
        confirm_payload = self._first_value(de.get("confirm_payload"))
        if confirm_payload:
            lines.append(f"  - confirming_payload: {confirm_payload}")
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
                    "browser_execution_confirmed", "field", "value",
                    "field_confirmed_in_response", "entity_uri",
                    "reflected_file_content", "file_disclosed", "forgery",
                    "proof_mode", "carrier", "real_status", "noauth_status",
                    "forged_status"):
            value = self._first_value(de.get(key))
            if value is not None:
                lines.append(f"  - {key}: {self._truncate_value(value)}")

        # Boolean NoSQL verification records two independent operator families.
        # Keep only the discriminative status/similarity values; request snippets
        # can contain credentials and are already represented by the redacted
        # top-level request evidence.
        for evidence_key in ("first_family", "confirm_family"):
            family = self._to_dict(self._first_value(de.get(evidence_key)))
            if not family:
                continue
            lines.append(
                f"  - {evidence_key}: family={family.get('family', '?')}, "
                f"true_status={family.get('true_status', '?')}, "
                f"false_status={family.get('false_status', '?')}, "
                f"similarity={family.get('similarity', '?')}"
            )
        # Show the model only the bytes the TARGET sent - never the scanner's own
        # "VERIFICATION EVIDENCE: ... confirms data extraction" preamble. Feeding it
        # the scanner's conclusion invites circular agreement (the model reads the
        # verdict and echoes it) instead of independent judgment of the response.
        server_bytes = server_response_bytes(vuln.evidence.response_snippet)
        if server_bytes:
            lines.append(f"  - response_excerpt: {server_bytes[:300]}")
        return lines or [f"  - detection_evidence: {self._truncate_value(de)}"]

    # ------------------------------------------------------------------
    # Proof summaries, weaknesses, judge questions
    # ------------------------------------------------------------------

    def _proof_summary(self, proof_type: str, vuln: Vulnerability) -> str:
        summaries = {
            "active_output": "Active exploitation confirmed - the proof is in the response (command output, file contents, or code execution).",
            "error_echo": "A database/framework error string was echoed in the response, causally connected to the injected payload.",
            "structural": "The vulnerability is structural - the observation itself IS the proof (missing header, TLS absence, admin path reachability, etc.).",
            "timing_strong": "Strong timing differential - the response delay is large enough to clearly indicate sleep-based SQL injection.",
            "timing_weak": "Weak timing differential - the response delay is small and could be network jitter rather than SQL injection.",
            "ssrf_differential": "Repeated internal-target versus external-control behavior differed, but no outbound callback or internal response content was observed.",
            "oast_callback": "Blind SSRF confirmed out-of-band: the target fetched a URL carrying a unique token we planted, and our OAST collaborator recorded the incoming request. The proof is that correlated interaction, not the target's HTTP response.",
            "browser_execution": "DOM-based XSS confirmed by execution: our uniquely-canaried script actually ran in a real headless browser via an execution-only oracle (it fires on execution, never on the canary merely being present as text/markup). The payload reaches the sink through a client-side source, so it need not appear in the server's response.",
            "mutating_authz": "Write-authorization finding: a state-changing request from a context that should require authentication was accepted and processed (2xx/3xx), identical to the authenticated owner. The proof is the accepted mutation, not data returned.",
            "boolean_differential": "Blind boolean SQL injection: a TRUE-condition payload and a FALSE-condition payload produced a reproducible difference in the response, consistent with the injected boolean controlling the query. The proof is the differential, not any content in the response.",
            "remote_include": "Remote File Inclusion: content belonging to the attacker-specified REMOTE resource appeared in the response, i.e. the server fetched and included an external URL. The proof is the remote resource's own body, not the URL string echoed back.",
            "login_success": "Default/guessed credentials accepted: the credential pair produced a response consistent with successful authentication and distinct from the failed-login baseline (post-auth content, a redirect, or an established session).",
            "auth_confirmed": "Confirmed authorization differential - distinct users or privilege levels received the same restricted object, fields, or privileged capability.",
            "auth_differential": "Access-control finding - responses from different authentication or user contexts indicate a possible boundary bypass. This is real only when a less-privileged context receives restricted data or the same object as another user.",
            "pattern_match": "A pattern was matched in the response body - this could be a genuine error disclosure, reflected payload text, or normal page content.",
            "heuristic": "Heuristic observation without active exploitation proof - the finding is based on observation alone.",
        }
        return summaries.get(proof_type, "Uncharacterized evidence.")

    def _proof_weaknesses(self, proof_type: str) -> str:
        weaknesses = {
            "active_output": (
                "The proof holds only if the response contains output the TARGET produced - "
                "command output, file contents, or a value the database returned. Input echoed "
                "back is NOT extraction: a reflected request URL (canonical or self-referential "
                "links, og:url, Location, pagination or form-action hrefs), a reflected parameter, "
                "or an error quoting the request all replay the payload. An alphanumeric marker "
                "survives percent- and HTML-encoding, so it can read as 'absent from baseline' "
                "while being pure reflection. Confirm the matched value is data the target "
                "generated, not our own request echoed back."
            ),
            "error_echo": "None - the database error text is causally connected to the payload. This is strong proof.",
            "structural": "Minimal - the observation is the proof. A false positive would require the scanner to have misconfigured its request.",
            "timing_strong": "Time deltas can have non-SQL causes (network jitter, lock contention, background load). But a large delta matching the SLEEP argument is strong. This would be a false positive only if the delta does not scale with the sleep duration.",
            "timing_weak": "The timing delta is small and could be caused by network jitter, database load, or connection overhead rather than SQL SLEEP. If the delta does not clearly exceed normal latency variation, this is likely a false positive.",
            "ssrf_differential": "A timeout, status, or body-length difference can also be caused by URL validation, denylisting, application timeouts, DNS behavior, or upstream filtering. It does not prove that the server issued an outbound request.",
            "oast_callback": (
                "A callback carrying the exact unique token planted for this finding can only "
                "originate from a server that fetched our URL, so the correlation is strong. It "
                "would be weak only if the recorded token does not match the one planted here, or "
                "if the interaction could have been triggered by something other than the target "
                "processing the payload. Do NOT treat the target's returned HTML page as the "
                "evidence: blind SSRF is proven out-of-band, and no response readback is expected."
            ),
            "browser_execution": (
                "The oracle fires only when our canaried JavaScript executes, never on mere "
                "reflection of the canary as inert text or markup, so reflection cannot cause a "
                "false fire. The captured DOM excerpt is the page AFTER client-side execution, NOT "
                "the server's HTTP response body - do not evaluate it for payload reflection. It "
                "would be a false positive only if the execution hook could be reached without the "
                "injected payload actually running."
            ),
            "mutating_authz": (
                "Identical PROCESSED (2xx/3xx) responses to the unauthenticated and owner requests "
                "are the confirmation here - not a public-by-design signal (that caveat applies to "
                "data-read findings). The detector already discarded matching 4xx/5xx statuses, "
                "which prove nothing. The real question is whether this endpoint is INTENDED to be "
                "anonymous (e.g. a public feedback or contact form) - some state changes "
                "legitimately accept anonymous input."
            ),
            "boolean_differential": (
                "Blind injection is confirmed by a CONSISTENT, REPRODUCIBLE true-vs-false split that "
                "tracks the injected boolean - not by response content and not by the magnitude "
                "alone. The split can be small when the differing region is a fraction of the page, "
                "so what matters is that it is stable, reproduced by an independent operator pair, "
                "and larger than baseline page-to-page variance. A split within normal noise, or one "
                "not reproduced, is weak."
            ),
            "remote_include": (
                "This is confirmed when content UNIQUE to the remote resource (its fingerprint) "
                "appears in the response - proving the server fetched and included the external URL, "
                "as opposed to merely reflecting the URL string we submitted. It would be weak only "
                "if the matched content could plausibly be produced by the target itself rather than "
                "fetched from the remote origin. Note: including a remote URL yields THAT resource's "
                "page, so the remote site's own content appearing is the success signal, not a miss."
            ),
            "login_success": (
                "A login form that returns 200 for every attempt, or that reflects the submitted "
                "username, can mimic success. It is confirmed when the credentialed response carries "
                "a post-auth indicator the failed-login baseline lacks - a session cookie, a redirect "
                "to an authenticated area, or authenticated-only navigation/logout affordances. "
                "Authenticated-only navigation appearing is itself a post-auth indicator, not generic "
                "page chrome."
            ),
            "auth_confirmed": "The proof compares distinct authenticated identities or roles, not merely HTTP success. Treat it as false only if the evidence shows the sessions were not distinct, the identifiers were not shared, or the returned data was explicitly public.",
            "auth_differential": "For anonymous-access findings, identical anonymous and authenticated responses with no restricted fields can mean the endpoint is public by design. For horizontal or vertical findings, compare authenticated identities or roles instead: shared object identifiers, sensitive fields, or privileged capabilities in the less-privileged response support a real boundary bypass.",
            "pattern_match": "The matched pattern could be (a) a genuine error disclosure, (b) reflected payload text that happens to contain the pattern, or (c) normal page content. If the matched text is the injected payload echoed back, or if it appears in navigation HTML / normal page content, this is a false positive.",
            "heuristic": "The finding is based on observation without active exploitation. Evaluate whether the observation truly constitutes a vulnerability or is a benign application behavior.",
        }
        return weaknesses.get(proof_type, "")

    def _judge_question(self, proof_type: str) -> str:
        questions = {
            "active_output": (
                "Does the response contain output the target itself generated (command output, "
                "file contents, or a database-returned value), or does the matched token appear "
                "only inside a reflection of our own request/payload (a URL echoed into a link, a "
                "reflected parameter), possibly percent- or HTML-encoded?"
            ),
            "error_echo": "Is the error string a genuine database/framework error, or could it be a benign message?",
            "structural": "Is this observation a genuine security gap? (It should be - do not flag as false positive.)",
            "timing_strong": "Does the timing delta clearly indicate SQL SLEEP execution, or could it be network noise?",
            "timing_weak": "Is the timing delta clearly caused by SQL SLEEP, or could it be network jitter or normal latency variation?",
            "ssrf_differential": "Do the repeated control and internal samples support a probable server-side fetch, while remaining short of confirmation without an OAST callback or reflected internal content?",
            "oast_callback": "Does a recorded out-of-band interaction carry the unique token planted for this finding, confirming the target issued the server-side request? (The target's HTML response is not the evidence for blind SSRF.)",
            "browser_execution": "Did our uniquely-canaried script execute in the browser (the oracle fired), confirming a client-side source-to-sink XSS - independent of any HTTP-body reflection?",
            "mutating_authz": "Was a state-changing operation accepted and processed without the required authentication, or is this endpoint intentionally anonymous (e.g. a public submission form)?",
            "boolean_differential": "Do the TRUE and FALSE payloads produce a stable, reproducible response split that tracks the injected boolean and exceeds baseline page-to-page noise?",
            "remote_include": "Does the response contain the remote resource's own content (proving a server-side fetch and include), as opposed to the target echoing back the URL string we submitted?",
            "login_success": "Did the credential pair move the session from unauthenticated to authenticated (a post-auth indicator absent from the failed-login baseline), or does the response merely resemble the login page / a generic 200?",
            "auth_confirmed": "Do the markers show distinct identities or roles crossing an object or privilege boundary? Do not require a further exploit chain once that boundary crossing is proven.",
            "auth_differential": "Did a less-privileged context receive genuinely restricted data or the same object/capability as another user or privileged role, or do the responses only show public/benign behavior?",
            "pattern_match": "Is the matched text a genuine error disclosure causally connected to the payload, or could it be reflected payload text or normal page content?",
            "heuristic": "Does this observation constitute a real vulnerability, or is it a benign application behavior?",
        }
        return questions.get(proof_type, "")

    # ------------------------------------------------------------------
    # Reason (for report display - backward compat with evidence_grade_reason)
    # ------------------------------------------------------------------

    def _grade_reason(self, proof_type: str, vuln: Vulnerability) -> str:
        method = (vuln.evidence.detection_method or "").lower()
        confidence = vuln.evidence.confidence_score
        verified = vuln.evidence.verified

        if proof_type == "auth_confirmed":
            return (
                f"Confirmed cross-context authorization differential (method={method}): "
                f"the recorded identities or roles crossed the reported boundary."
            )
        if proof_type == "auth_differential":
            return (
                f"Access-control differential (method={method}): 'verified' means the "
                f"requests produced the recorded responses, NOT by itself that a boundary "
                f"was bypassed. AI must compare the relevant identities or roles."
            )
        if proof_type == "pattern_match":
            return (
                f"Pattern-match (method={method}): a regex hit on the response body. "
                f"The match could be reflected payload, normal content, or a genuine error. "
                f"AI must judge causal connection."
            )
        if proof_type == "ssrf_differential":
            return (
                "Indirect SSRF differential: repeated internal/control behavior differs, "
                "but there is no callback or reflected internal content. Treat as probable, "
                "not confirmed."
            )
        if proof_type == "oast_callback":
            return (
                f"Blind SSRF confirmed out-of-band (method={method}): a correlated callback "
                f"carrying our planted token reached the OAST collaborator."
            )
        if proof_type == "browser_execution":
            return (
                f"Browser execution confirmed (method={method}, confidence={confidence:.0f}): "
                f"the canaried payload executed in a real headless browser."
            )
        if proof_type == "mutating_authz":
            return (
                f"Write-authorization differential (method={method}): an unauthenticated "
                f"state-changing request was accepted with the owner's processed status. AI "
                f"must judge whether the endpoint is intended to be anonymous."
            )
        if proof_type == "boolean_differential":
            return (
                f"Blind boolean SQLi differential (method={method}): a reproducible TRUE/FALSE "
                f"response split that tracks the injected boolean. AI must judge whether the "
                f"split is stable and exceeds baseline noise."
            )
        if proof_type == "remote_include":
            return (
                f"Remote file inclusion confirmed by content (method={method}): the remote "
                f"resource's own body appeared in the response, proving a server-side fetch."
            )
        if proof_type == "login_success":
            return (
                f"Login-success differential (method={method}): the credential pair produced a "
                f"response consistent with authentication, distinct from the failed-login baseline."
            )
        if proof_type == "timing_strong":
            de = self._to_dict(vuln.evidence.detection_evidence)
            delta = self._first_value(de.get("delta_ms"))
            if delta is None:
                delta = self._first_value(de.get("timing_delta_ms"))
            baseline = self._first_value(de.get("baseline_mean_ms"))
            return (
                f"Strong timing differential: delta={delta if delta is not None else '?'}ms "
                f"vs baseline={baseline if baseline is not None else '?'}ms "
                f"(method={method}, confidence={confidence:.0f}, verified={verified})"
            )
        if proof_type == "timing_weak":
            de = self._to_dict(vuln.evidence.detection_evidence)
            delta = self._first_value(de.get("delta_ms"))
            if delta is None:
                delta = self._first_value(de.get("timing_delta_ms"))
            return (
                f"Weak timing differential: delta={delta if delta is not None else '?'}ms "
                f"- could be network jitter "
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
                f"Structural/observable finding: '{vuln.vuln_type}' - "
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
    def _to_dict(value: object) -> dict:
        """Coerce *value* to a dict.

        ``detection_evidence`` is typed as ``dict`` but some detectors
        store a ``list`` (e.g. a list of evidence dicts).  Calling
        ``.get()`` on a list causes ``AttributeError``.  This helper
        normalises the value so callers always receive a dict.
        """
        if isinstance(value, dict):
            return value
        if isinstance(value, list):
            # Use the first dict element if available; otherwise empty.
            for item in value:
                if isinstance(item, dict):
                    return item
            return {}
        return {}

    @staticmethod
    def _to_dicts(value: object) -> list[dict]:
        """Return all mapping values from direct or deduplicated evidence."""
        if isinstance(value, dict):
            return [value]
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        return []

    @staticmethod
    def _flatten_values(value: object) -> list[object]:
        """Flatten list-wrapped evidence values while discarding nulls."""
        if value is None:
            return []
        if isinstance(value, list):
            flattened: list[object] = []
            for item in value:
                flattened.extend(EvidenceGrader._flatten_values(item))
            return flattened
        return [value]

    @staticmethod
    def _first_value(value: object) -> object | None:
        """Return the primary scalar from a list-wrapped evidence value."""
        flattened = EvidenceGrader._flatten_values(value)
        return flattened[0] if flattened else None

    @staticmethod
    def _profile_values(profiles: list[dict], key: str) -> list[object]:
        """Collect unique profile values across merged auth observations."""
        values: list[object] = []
        for profile in profiles:
            for value in EvidenceGrader._flatten_values(profile.get(key)):
                if value not in values:
                    values.append(value)
        return values

    @staticmethod
    def _is_structural(vuln_lower: str) -> bool:
        return any(keyword in vuln_lower for keyword in _STRUCTURAL_VULN_KEYWORDS)

    @staticmethod
    def _truncate_value(value: object, max_len: int = 200) -> str:
        s = str(value)
        return s[:max_len] + "..." if len(s) > max_len else s
