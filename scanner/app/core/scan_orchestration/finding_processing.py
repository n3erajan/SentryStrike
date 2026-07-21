import json
import math
import re
from collections.abc import Iterable
from uuid import uuid4

from app.core.detectors.base_detector import Finding
from app.utils.cvss_calculator import CvssCalculator
from app.utils.redaction import redact_secrets
from shared.models.scan import EvidenceStrengthBreakdown
from shared.models.vulnerability import (
    AuthContext,
    Evidence,
    EvidenceStrength,
    Exploitability,
    LocationInfo,
    SeverityLevel,
    Vulnerability,
    VerificationTarget,
)


class FindingProcessingMixin:
    def _compute_priority_ranks(self, vulnerabilities: list[Vulnerability]) -> list[Vulnerability]:
        exploitability_weight = {"Easy": 3.0, "Medium": 2.0, "Hard": 1.0}
        evidence_weight = {
            EvidenceStrength.confirmed_exploit: 1.0,
            EvidenceStrength.confirmed_observation: 0.9,
            EvidenceStrength.probable: 0.7,
            EvidenceStrength.possible: 0.5,
            EvidenceStrength.informational: 0.1,
        }

        def risk_score(vuln: Vulnerability) -> float:
            exploit_value = vuln.ai_analysis.exploitability.value if vuln.ai_analysis.exploitability else "Medium"
            exploit_w = exploitability_weight.get(exploit_value, 2.0)
            proof_w = evidence_weight.get(vuln.evidence_strength, 0.5)
            return vuln.cvss_score * exploit_w * proof_w

        vulnerabilities.sort(key=risk_score, reverse=True)
        for rank, vuln in enumerate(vulnerabilities, start=1):
            vuln.ai_analysis.priority_rank = rank
        return vulnerabilities

    def _calibrate_exploitability(self, vuln: Vulnerability) -> Exploitability:
        vuln_type_lower = vuln.vuln_type.lower()
        severity = vuln.severity

        # Preserve AI reasoning for exploitability; only override when the
        # evidence contains unambiguous proof (e.g. command output in a
        # critical injection finding).
        if severity == SeverityLevel.critical and any(
            tok in vuln_type_lower
            for tok in ["command injection", "sql injection", "file inclusion", "file upload"]
        ):
            if vuln.evidence.response_snippet and "root:" in vuln.evidence.response_snippet.lower():
                return Exploitability.easy

        if "csrf" in vuln_type_lower and "samesite" in (vuln.evidence.payload or vuln.evidence.response_snippet or "").lower():
            if vuln.ai_analysis:
                if not vuln.ai_analysis.exploitability_reasoning:
                    vuln.ai_analysis.exploitability_reasoning = "SameSite attribute provides partial protection, increasing exploitation difficulty."
            return Exploitability.hard if severity == SeverityLevel.low else Exploitability.medium

        if vuln.ai_analysis and vuln.ai_analysis.exploitability:
            return vuln.ai_analysis.exploitability

        if severity == SeverityLevel.low:
            return Exploitability.hard

        if severity == SeverityLevel.high and vuln.evidence.request_snippet:
            return Exploitability.easy

        return Exploitability.medium

    def _synthesize_attack_chains(self, vulnerabilities: list[Vulnerability]) -> list['AttackChain']:
        from uuid import uuid4
        from shared.models.scan import AttackChain
        chains = []
        
        # Rule-based chains
        # 1. CSRF to Command Injection
        csrf_vulns = [v for v in vulnerabilities if "csrf" in v.vuln_type.lower()]
        cmdi_vulns = [v for v in vulnerabilities if "command injection" in v.vuln_type.lower()]
        for csrf in csrf_vulns:
            for cmdi in cmdi_vulns:
                if csrf.location.url == cmdi.location.url:
                    chains.append(AttackChain(
                        id=str(uuid4()),
                        description=f"CSRF to Command Injection chain on {csrf.location.url}. An attacker can forge a request to execute arbitrary OS commands.",
                        vulnerability_ids=[csrf.id, cmdi.id],
                        severity="Critical"
                    ))
                    
        # 2. Stored XSS + missing CSP -> session theft chain
        xss_vulns = [v for v in vulnerabilities if "stored xss" in v.vuln_type.lower()]
        csp_vulns = [v for v in vulnerabilities if "content security policy" in v.vuln_type.lower() or "csp" in v.vuln_type.lower()]
        if xss_vulns and csp_vulns:
            for xss in xss_vulns:
                chains.append(AttackChain(
                    id=str(uuid4()),
                    description=f"Stored XSS combined with missing/weak CSP on {xss.location.url} facilitates reliable session theft.",
                    vulnerability_ids=[xss.id] + [c.id for c in csp_vulns],
                    severity="High"
                ))
                
        return chains

    def _to_vulnerability(self, finding: Finding, extra_secrets: Iterable[str] = ()) -> Vulnerability:
        evidence_strength = self._classify_evidence_strength(finding)
        auth_context = self._classify_auth_context(finding)
        if finding.severity == SeverityLevel.info:
            cvss_score = 0.0
            cvss_vector = None
        else:
            requires_auth = auth_context in {
                AuthContext.authenticated,
                AuthContext.requires_user_session,
            }
            cvss = CvssCalculator.from_vulnerability_context(
                vuln_type=finding.vuln_type,
                requires_auth=requires_auth,
            )
            cvss_score = cvss.score
            cvss_vector = cvss.vector

        detection_evidence = getattr(finding, "detection_evidence", {}) or {}

        # Deduplication merges evidence values into lists. Replay metadata still
        # describes the primary (highest-confidence) finding, so consume its first
        # value while continuing to support detectors that emit scalar metadata.
        def primary_evidence_value(key: str, default=None):
            value = detection_evidence.get(key, default)
            if isinstance(value, list):
                return value[0] if value else default
            return value

        request_template = primary_evidence_value("request_template", {})
        if not isinstance(request_template, dict):
            request_template = {}
        serialized_template = json.dumps(request_template, default=str)
        safe_template = json.loads(
            redact_secrets(serialized_template, extra_secrets) or "{}"
        )
        detector_id = str(
            getattr(finding, "detector_name", None)
            or getattr(finding, "detection_method", None)
            or "unknown_detector"
        ).strip().lower().replace(" ", "_")
        response_snippet = redact_secrets(
            self._finding_response_snippet(finding), extra_secrets
        )
        verification_url = redact_secrets(
            str(primary_evidence_value("request_url", finding.url)), extra_secrets
        ) or finding.url
        control_payload = primary_evidence_value("control_payload")
        expected_status_code = primary_evidence_value("status_code", "")

        return Vulnerability(
            id=str(uuid4()),
            category=finding.category,
            vuln_type=finding.vuln_type,
            severity=finding.severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            location=LocationInfo(
                url=verification_url,
                parameter=finding.parameter,
                parameters=(
                    list(getattr(finding, "affected_parameters", None) or [])
                    or ([finding.parameter] if finding.parameter else [])
                ),
                http_method=finding.method,
                parameter_location=(
                    getattr(finding, "parameter_location", None)
                    or primary_evidence_value("parameter_location")
                    or None
                ),
            ),
            evidence=Evidence(
                payload=redact_secrets(finding.payload, extra_secrets),
                request_snippet=redact_secrets(
                    getattr(finding, "verification_request_snippet", None), extra_secrets
                ),
                response_snippet=response_snippet,
                verified=getattr(finding, "verified", False),
                confidence_score=float(getattr(finding, "confidence_score", 0.0) or 0.0),
                detection_method=getattr(finding, "detection_method", None),
                detection_evidence=getattr(finding, "detection_evidence", {}) or {},
                evidence_strength=evidence_strength,
                auth_context=auth_context,
            ),
            evidence_strength=evidence_strength,
            auth_context=auth_context,
            verification_target=VerificationTarget(
                detector_id=detector_id,
                url=finding.url,
                method=finding.method or "GET",
                parameter=finding.parameter,
                parameter_location=(
                    getattr(finding, "parameter_location", None)
                    or primary_evidence_value("parameter_location")
                    or None
                ),
                request_template=safe_template,
                payload=redact_secrets(finding.payload, extra_secrets),
                control_payload=(
                    str(control_payload) if control_payload is not None else None
                ),
                proof_type=getattr(finding, "detection_method", None),
                auth_context=auth_context,
                expected_response_snippet=(response_snippet or "")[:1000] or None,
                expected_status_code=(
                    int(expected_status_code) if str(expected_status_code).isdigit() else None
                ),
            ),
        )

    @staticmethod
    def _collect_redaction_secrets(accounts: list | None) -> list[str]:
        """Plaintext account passwords used by this scan, for evidence redaction.

        ``redact_secrets`` already masks auth headers, cookies, JWTs, and
        credential-labeled JSON fields by structure. The one blind spot is a
        plaintext password echoed outside a ``password:``-labeled field (e.g.
        in a response body); passing the exact password values closes that
        gap. Usernames are excluded so reviewers can still see which identity a
        finding pertains to.
        """
        secrets: list[str] = []
        for account in accounts or []:
            password = getattr(account, "password", None)
            if password:
                secrets.append(str(password))
        return secrets

    @staticmethod
    def _calculate_aggregate_risk(vulnerabilities: list[Vulnerability]) -> tuple[float, str]:
        """Aggregate per-vulnerability CVSS into one 0-100 posture score + qualitative band.

        Standards-aligned design. CVSS base scores are per-vulnerability severity metrics
        and must NOT be averaged: averaging dilutes the worst finding, and an attacker only
        needs to exploit a single vulnerability (FIRST CVSS guidance; OWASP Risk Rating).
        Instead:

          * anchor  — worst-case. The highest verified-weighted CVSS, scaled to 0-100.
                      This dominates, so a single confirmed Critical reads as Critical and
                      is never diluted by lower-severity noise.
          * breadth — a bounded, saturating bonus for the *additional* attack surface,
                      severity-weighted (Critical > High > Medium > Low) so many low
                      findings can never outweigh one severe one. It can fill at most
                      ``BREADTH_CAP`` of the headroom above the anchor, with diminishing
                      returns, so the score stays anchored and does not trivially saturate
                      at 100 the way a volume multiplier did.

        Verified findings weigh 1.0, unverified 0.7 (applied to both anchor and breadth).
        The band label reuses the CVSS severity thresholds via ``CvssCalculator.get_severity``.

        Returns ``(score 0-100, band)`` where band is Critical/High/Medium/Low/Info.
        """
        active = [v for v in vulnerabilities if not v.is_false_positive]
        if not active:
            return 0.0, CvssCalculator.get_severity(0.0)

        # Severity → breadth weight: many low findings must never outweigh one severe one.
        tier_weight = {
            SeverityLevel.critical: 1.0,
            SeverityLevel.high: 0.6,
            SeverityLevel.medium: 0.3,
            SeverityLevel.low: 0.1,
            SeverityLevel.info: 0.0,
        }
        BREADTH_CAP = 0.5   # breadth fills at most 50% of the headroom above the anchor
        BREADTH_K = 0.35    # saturation rate of the breadth bonus vs. severity-weighted volume

        weighted_cvss: list[float] = []
        sev_weight_sum = 0.0
        for v in active:
            w = 1.0 if v.evidence.verified else 0.7
            weighted_cvss.append(v.cvss_score * w)
            sev_weight_sum += tier_weight.get(v.severity, 0.3) * w

        anchor = max(weighted_cvss) * 10.0                      # worst-case, 0-100
        headroom = 100.0 - anchor
        breadth = headroom * BREADTH_CAP * (1.0 - math.exp(-BREADTH_K * sev_weight_sum))

        score = round(min(100.0, anchor + breadth), 2)
        return score, CvssCalculator.get_severity(score / 10.0)

    def _evidence_strength_breakdown(self, vulnerabilities: list[Vulnerability]) -> EvidenceStrengthBreakdown:
        counts = EvidenceStrengthBreakdown()
        for vuln in vulnerabilities:
            strength = vuln.evidence_strength.value if hasattr(vuln.evidence_strength, "value") else str(vuln.evidence_strength)
            if hasattr(counts, strength):
                setattr(counts, strength, getattr(counts, strength) + 1)
        return counts

    def _classify_evidence_strength(self, finding: Finding) -> EvidenceStrength:
        vt = (finding.vuln_type or "").lower()
        method = (getattr(finding, "detection_method", "") or "").lower()
        verified = bool(getattr(finding, "verified", False))
        confidence = float(getattr(finding, "confidence_score", 0.0) or 0.0)

        informational_terms = (
            "coverage",
            "scanner limitation",
            "not tested",
            "out of scope",
            "informational",
        )
        if finding.severity == SeverityLevel.info or any(term in vt for term in informational_terms):
            return EvidenceStrength.informational

        # A timeout/status differential can indicate SSRF, but without reflected
        # internal content or an OAST callback it is not a confirmed exploit.
        if method == "ssrf_inband_differential":
            return EvidenceStrength.probable

        confirmed_exploit_methods = {
            "nosql_boolean_operator",
            "jwt_active_forgery",
            "xxe_external_entity_file_read",
            "poison_null_byte_extension_bypass",
            "second_user_idor",
        }
        if verified and method in confirmed_exploit_methods:
            return EvidenceStrength.confirmed_exploit

        if method == "union_based" and "sql injection" in vt:
            evidence = getattr(finding, "detection_evidence", {}) or {}
            if not evidence.get("canary_verified") and not evidence.get("version_extracted"):
                return EvidenceStrength.probable if verified else EvidenceStrength.possible

        active_terms = (
            "sql injection",
            "xss",
            "command injection",
            "file inclusion",
            "path traversal",
            "arbitrary file read",
            "ssrf",
            "file upload",
            "idor",
            "privilege escalation",
        )
        active_methods = {
            "boolean",
            "boolean_based",
            "error",
            "error_based",
            "time",
            "time_based",
            "union",
            "union_based",
            "command_output",
            "token_bypass",
            "stored_xss_execution",
            "dom_execution",
            "path_traversal",
            "file_content",
            "ssrf_callback",
            "open_redirect",
            "upload_canary",
        }
        if verified and any(term in vt for term in active_terms) and (
            confidence >= 70.0 or method in active_methods
        ):
            return EvidenceStrength.confirmed_exploit

        if "vulnerable component" in vt:
            return EvidenceStrength.probable
        if verified:
            return EvidenceStrength.confirmed_observation

        if confidence >= 50.0 or method not in {"heuristic", ""}:
            return EvidenceStrength.probable
        if finding.severity == SeverityLevel.low:
            return EvidenceStrength.informational
        return EvidenceStrength.possible

    def _classify_auth_context(self, finding: Finding) -> AuthContext:
        evidence_blob = " ".join(
            str(part or "")
            for part in (
                getattr(finding, "verification_request_snippet", None),
                getattr(finding, "evidence", None),
            )
        ).lower()
        if "authorization:" in evidence_blob or "cookie:" in evidence_blob:
            return AuthContext.authenticated
        vt = (finding.vuln_type or "").lower()
        if "csrf" in vt or "idor" in vt or "privilege escalation" in vt:
            return AuthContext.requires_user_session
        if getattr(finding, "verified", False):
            return AuthContext.unauthenticated
        return AuthContext.unknown

    # Defensive upper bound on the raw response excerpt stored per finding.
    # ResponseAnalyzer.build_evidence_response_snippet already centers and
    # bounds bodies (~1200 chars), but detectors that stash a response some
    # other way could exceed that; cap here so the report can't be bloated.
    _MAX_RESPONSE_EXCERPT_CHARS = 2000

    def _finding_response_snippet(self, finding: Finding) -> str | None:
        evidence = self._clean_evidence_text(finding.evidence or "")
        response_snippet = (getattr(finding, "verification_response_snippet", None) or "").strip()

        if not self._should_include_response_excerpt(finding):
            return f"VERIFICATION EVIDENCE:\n{evidence}" if evidence else None

        if response_snippet and len(response_snippet) > self._MAX_RESPONSE_EXCERPT_CHARS:
            response_snippet = (
                response_snippet[: self._MAX_RESPONSE_EXCERPT_CHARS]
                + "\n[...snip after excerpt...]"
            )

        if evidence and response_snippet:
            return f"VERIFICATION EVIDENCE:\n{evidence}\n\nRESPONSE EXCERPT:\n{response_snippet}"
        if evidence:
            return f"VERIFICATION EVIDENCE:\n{evidence}"
        return response_snippet or None

    @staticmethod
    def _clean_evidence_text(evidence: str) -> str:
        """Collapse repeated evidence fragments and format as lines."""
        parts = re.split(r"\s*[;\n]\s*", str(evidence or "").strip())
        clean_parts: list[str] = []
        seen: set[str] = set()
        for part in parts:
            normalized = " ".join(part.split())
            key = normalized.lower()
            if normalized and key not in seen:
                seen.add(key)
                clean_parts.append(normalized)
        return "\n".join(clean_parts)

    def _should_include_response_excerpt(self, finding: Finding) -> bool:
        vt = (finding.vuln_type or "").lower()
        method = (getattr(finding, "detection_method", "") or "").lower()
        response_snippet = (getattr(finding, "verification_response_snippet", None) or "").strip()

        header_metadata_terms = (
            "header", "cookie", "transport", "tls", "ssl", "https", "server banner",
            "cache-control", "hsts",
        )
        if "mixed content" not in vt and any(term in vt for term in header_metadata_terms):
            return False

        no_body_proof_terms = (
            "csrf", "brute-force", "brute force", "time-based blind",
            "boolean-based blind", "rate", "captcha bypass",
            "credentials transmitted via http get",
            "credential / token exposed",
            "authentication form lacks csrf",
            "authentication form may lack csrf",
        )
        if any(term in vt for term in no_body_proof_terms):
            return False

        body_proof_terms = (
            "xss", "command injection", "file inclusion", "path traversal",
            "arbitrary file read", "ssrf", "verbose error", "debug / metrics",
            "sensitive path", "information disclosure", "vulnerable component", "mixed content",
            "data exposure", "authorization bypass", "forced browsing",
            "access control", "idor", "privilege bypass",
        )
        if any(term in vt for term in body_proof_terms):
            return True

        if method in {
            "error_based",
            "union_based",
            "file_retrieval",
            "path_traversal_file_read",
            "stream_decoding_oracle",
            "command_output",
            "remote_include_error_oracle",
            "authorization_matrix",
            "authorization_matrix_second_user",
            "authorization_matrix_cross_identity",
            "authorization_matrix_privileged_baseline",
        }:
            return True

        # Any active finding that captured a real response body is proof worth
        # showing. Passive/heuristic findings never populate
        # ``verification_response_snippet``, so they stay excluded here. We do
        # NOT gate on response length: the snippet is already centered and
        # bounded around the proof at capture time, and a larger response body
        # is stronger evidence for an active finding, not a reason to drop it.
        return bool(response_snippet)
