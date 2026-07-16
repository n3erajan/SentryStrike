"""
NoSQL Injection Verifier: active verification for NoSQL (document-DB) operator
injection, structured to mirror :mod:`app.core.verification.sqli_verifier`.

NoSQL operator injection is a distinct class from SQL injection: instead of
breaking out of a quoted SQL string, the attacker replaces a *field value* with a
query-operator object (``{"$ne": …}``, ``{"$gt": …}``, ``{"$regex": …}``,
``{"$where": …}``). When the server passes that object straight into a document-DB
query filter, the operator is *evaluated* as query logic rather than compared as a
literal value — bypassing intended matching.

The operator object reaches the server two ways, both handled here:
  * **JSON body** — ``{"field": {"$ne": …}}`` on a JSON endpoint.
  * **Bracket notation** — ``field[$ne]=…`` in a query string or urlencoded form,
    which Express's ``qs`` parser (and equivalents) expands into the same nested
    object ``{field: {$ne: …}}``. This is the classic query/form NoSQL vector.

Three techniques, ordered by reliability (same shape as the SQLi verifier):
  1. Boolean operator differential — an always-true operator produces a healthy
     response that DIVERGES from an always-false operator; confirmed across two
     independent operator families before reporting.
  2. Error-based — a malformed operator forces a document-DB/ODM error whose
     marker is absent from the baseline; two independent payloads must confirm.
  3. Timing-based blind — a ``$where`` sleep-equivalent, gated exactly like the
     SQLi time-based technique (baseline-slow skip, relative floor).

False-positive philosophy (inherited): no single-payload, single-check result is
ever reported. Boolean requires two operator families to diverge; error requires
two confirming payloads; timing requires the relative-delay floor.

Framework/target-agnostic: payloads are the standard MongoDB/document-DB operator
set — a universal property of the technology, never an app-specific value. The
verifier only runs against JSON-body parameters (the sole place an operator
object is parsed as query logic).
"""

import asyncio
import difflib
import json
import logging
from typing import Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from app.config import get_settings
from app.core.detectors.attack_surface import AttackTarget, build_form_payload
from app.core.crawler.models import ParameterLocation
from app.core.verification.response_analyzer import ResponseAnalyzer, ResponseData, is_dead_baseline
from app.core.verification.verification_framework import BaseVerifier, VerificationResult
from shared.models.vulnerability import OwaspCategory, SeverityLevel

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------

_HIGH_CONFIDENCE_THRESHOLD = 85.0

# If two identical benign requests are less similar than this, the endpoint is
# too volatile for a boolean differential — an operator "divergence" could be
# noise, so boolean is disabled for that parameter.
_STABILITY_FLOOR = 0.70

# An always-true vs always-false operator pair counts as DIVERGED (operators
# were evaluated as query logic) when their bodies are at most this similar,
# or when their status codes differ.
_DIVERGE_MAX = 0.60

# ---------------------------------------------------------------------------
# Document-DB / ODM error markers.
# Universal MongoDB driver + Mongoose ODM error phrases (aligned with the
# MongoDB/Mongoose signatures in error_fingerprints.py). Intentionally excludes
# bare operator tokens (``$ne``/``$regex``) that a benign app might echo.
# ---------------------------------------------------------------------------

_NOSQL_ERROR_MARKERS = frozenset({
    "mongoerror",
    "mongoservererror",
    "mongonetworkerror",
    "bsonerror",
    "e11000 duplicate key",
    "com.mongodb",
    "mongooseerror",
    "cast to objectid failed",
    "cast to number failed",
    "validatorerror",
    "unknown operator",
    "unknown top level operator",
    "can't canonicalize query",
    "regular expression is invalid",
    "$regex has to be a string",
    "bad $regex",
    "$where must be",
})


def _body_similarity(a: Optional[str], b: Optional[str]) -> float:
    """Sequence-matcher similarity between two bodies (1.0 for both-empty)."""
    a = a or ""
    b = b or ""
    if not a and not b:
        return 1.0
    return difflib.SequenceMatcher(None, a, b).ratio()


def _new_nosql_errors(baseline_body: str, injected_body: str, payload: str) -> list[str]:
    """Document-DB error markers present in the injected body, absent from baseline.

    The serialized operator payload is stripped from the injected body first, so
    an app that merely echoes the payload text (``{"$regex": "("}``) cannot
    self-trigger an error match.
    """
    bl = (baseline_body or "").lower()
    inj = (injected_body or "").lower()
    payload_low = (payload or "").lower()
    if payload_low:
        inj = inj.replace(payload_low, "")
    return [m for m in _NOSQL_ERROR_MARKERS if m in inj and m not in bl]


class NoSqliVerifier(BaseVerifier):
    """Verifies NoSQL operator injection through active testing."""

    module_name = "nosqli"

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

        # Operator injection makes sense wherever a field value can carry a nested
        # operator object: a JSON body (``{"field": {"$ne": …}}``) or a query/form
        # param via bracket notation (``field[$ne]=…``, which the qs parser nests).
        # Path/header/cookie locations cannot express a nested operator, so they
        # are skipped (untested, not a negative).
        if not self._is_injectable_target(target):
            return VerificationResult(
                is_vulnerable=False, confidence_score=0.0,
                detection_method="none", findings=[],
                evidence={"skipped": "not_injectable_parameter"},
            )

        baseline = await self.fetch_pre_test_baseline(
            url, parameter, method, value, form_inputs, target=target
        )

        # Dead baseline: a plain 401/403/404/405 means the endpoint is unreachable
        # as sent, so no operator differential can exist — abort before spending
        # the payload budget (mirrors the SQLi verifier).
        if is_dead_baseline(baseline):
            return VerificationResult(
                is_vulnerable=False, confidence_score=0.0,
                detection_method="none", findings=[],
                evidence={"skipped": "dead_baseline", "baseline_status": baseline.status_code},
            )

        results: list[VerificationResult] = []

        # Technique 1: boolean operator differential.
        result = await self._verify_boolean_operator(url, parameter, method, target, baseline)
        if result.is_vulnerable:
            results.append(result)
            if result.confidence_score >= _HIGH_CONFIDENCE_THRESHOLD:
                return result

        # Technique 2: error-based.
        result = await self._verify_error_based(url, parameter, method, target, baseline)
        if result.is_vulnerable:
            results.append(result)
            if result.confidence_score >= _HIGH_CONFIDENCE_THRESHOLD:
                return result

        # Technique 3: timing-based blind (last resort only).
        if not results:
            result = await self._verify_time_based(url, parameter, method, target, baseline)
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
    # Helpers
    # ======================================================================

    # Locations whose value can carry a nested operator object.
    _JSON_LOCATIONS = frozenset({ParameterLocation.json_body, ParameterLocation.graphql_variable})
    _BRACKET_LOCATIONS = frozenset({ParameterLocation.query, ParameterLocation.form})

    @classmethod
    def _is_injectable_target(cls, target: Optional[object]) -> bool:
        return isinstance(target, AttackTarget) and target.location in (
            cls._JSON_LOCATIONS | cls._BRACKET_LOCATIONS
        )

    @staticmethod
    def _flatten_operator(prefix: str, operator: object) -> dict[str, str]:
        """Flatten an operator object into bracket-notation query/form keys.

        ``("email", {"$ne": "x"})``           -> ``{"email[$ne]": "x"}``
        ``("id",   {"$gt": {"$gt": ""}})``    -> ``{"id[$gt][$gt]": ""}``

        This is the wire form Express's ``qs`` parser (and equivalents) re-nest
        back into ``{email: {$ne: "x"}}`` — generic to any deep-object body parser.
        """
        out: dict[str, str] = {}
        if isinstance(operator, dict):
            for key, value in operator.items():
                out.update(NoSqliVerifier._flatten_operator(f"{prefix}[{key}]", value))
        else:
            out[prefix] = "" if operator is None else str(operator)
        return out

    async def _send_operator(
        self,
        target: AttackTarget,
        operator: object,
        *,
        test_phase: str,
    ) -> ResponseData:
        """Send the target's request with ``parameter`` carrying ``operator``.

        A dict ``operator`` is injected as an operator object: nested in the JSON
        body for JSON targets, or as bracket-notation keys for query/form targets.
        A plain (string) ``operator`` is the benign baseline/stability value and
        goes through the target's normal builder unchanged.
        """
        if isinstance(operator, dict) and target.location in self._BRACKET_LOCATIONS:
            return await self._send_bracket(target, operator, test_phase=test_phase)

        prepared = target.build_request(operator, merge_with_baseline=False)
        payload = (
            json.dumps(operator, separators=(",", ":"), default=str)
            if isinstance(operator, dict) else str(operator)
        )
        return await self._send(
            prepared.url,
            target.method,
            prepared.params,
            prepared.data,
            headers=prepared.headers,
            cookies=prepared.cookies,
            json_body=prepared.json_body,
            test_phase=test_phase,
            payload=payload,
        )

    async def _send_bracket(
        self,
        target: AttackTarget,
        operator: dict,
        *,
        test_phase: str,
    ) -> ResponseData:
        """Inject an operator via bracket notation into a query/form parameter.

        The plain ``field=value`` pair is replaced by the bracket keys so the
        server sees only the operator form, and sibling params/fields keep their
        baseline values (so e.g. a login form's other fields still validate).
        """
        bracket = self._flatten_operator(target.parameter, operator)
        method = target.method.upper()
        headers = dict(target.headers or {}) or None
        cookies = dict(target.cookies or {}) or None
        payload_text = json.dumps(operator, separators=(",", ":"), default=str)

        if target.location == ParameterLocation.form:
            data = build_form_payload(target.form_inputs or [], target.parameter, "")
            data.pop(target.parameter, None)
            data.update(bracket)
            return await self._send(
                target.url, method, None, data,
                headers=headers, cookies=cookies,
                test_phase=test_phase, payload=payload_text,
            )

        parsed = urlparse(target.url)
        query = {
            key: (value[0] if isinstance(value, list) and value else "")
            for key, value in parse_qs(parsed.query, keep_blank_values=True).items()
        }
        query.pop(target.parameter, None)
        query.update(bracket)
        if method == "GET":
            new_url = urlunparse(parsed._replace(query=urlencode(query, doseq=False)))
            return await self._send(
                new_url, method, None, None,
                headers=headers, cookies=cookies,
                test_phase=test_phase, payload=payload_text,
            )
        return await self._send(
            target.url, method, query, None,
            headers=headers, cookies=cookies,
            test_phase=test_phase, payload=payload_text,
        )

    async def _is_stable(self, target: AttackTarget, baseline: ResponseData) -> bool:
        """Two benign re-requests must be similar; else the page is too volatile."""
        try:
            probe = await self._send_operator(
                target, str(target.value), test_phase="nosql_stability_probe"
            )
            if probe.not_tested:
                return True
            return _body_similarity(baseline.body, probe.body) >= _STABILITY_FLOOR
        except Exception:
            return True

    # ======================================================================
    # Technique 1: boolean operator differential
    # ======================================================================

    async def _verify_boolean_operator(
        self,
        url: str,
        parameter: str,
        method: str,
        target: AttackTarget,
        baseline: ResponseData,
    ) -> VerificationResult:
        """Confirm operator evaluation via always-true vs always-false divergence.

        For each operator family, an always-true operator must produce a healthy
        (200) response that DIVERGES from the always-false operator's response.
        If the server treats the object as a literal (no operator support) both
        responses collapse to the same not-found/error shape and do not diverge.
        Two independent families must diverge before reporting — two evaluations
        passing independently is strong evidence against coincidence.
        """
        try:
            if not await self._is_stable(target, baseline):
                return VerificationResult(
                    is_vulnerable=False, confidence_score=0.0,
                    detection_method="nosql_boolean_operator", findings=[],
                    evidence={"skipped": "unstable_endpoint"},
                )

            canary = ResponseAnalyzer.generate_probe_canary()
            # (family, always-true operator, always-false operator)
            operator_families = [
                ("ne_eq", {"$ne": canary}, {"$eq": canary}),
                ("gt_lt", {"$gt": ""}, {"$lt": ""}),
                ("regex", {"$regex": ".*"}, {"$regex": f"{canary}^"}),
            ]

            passed: list[dict] = []
            for family, true_op, false_op in operator_families:
                detail = await self._run_operator_pair(
                    target, canary, baseline, family, true_op, false_op
                )
                if detail is not None:
                    passed.append(detail)
                if len(passed) >= 2:
                    break

            if len(passed) < 2:
                return VerificationResult(
                    is_vulnerable=False, confidence_score=0.0,
                    detection_method="nosql_boolean_operator", findings=[],
                    evidence={
                        "families_diverged": [d["family"] for d in passed],
                        "note": "fewer than two operator families diverged - not reported",
                    } if passed else {"families_diverged": []},
                )

            first, second = passed[0], passed[1]
            confidence = 80.0
            finding = self._create_finding(
                category=OwaspCategory.a05,
                vuln_type="NoSQL Injection (Boolean Operator)",
                severity=SeverityLevel.high,
                url=url, parameter=parameter,
                payload=json.dumps(first["true_op"], separators=(",", ":")),
                evidence=(
                    f"Always-true operator {first['true_op']} returned HTTP {first['true_status']} "
                    f"but always-false operator {first['false_op']} diverged "
                    f"(similarity {first['similarity']:.0%}). Confirmed with an independent "
                    f"'{second['family']}' operator family "
                    f"(similarity {second['similarity']:.0%}). The field value is evaluated as a "
                    f"query operator, not compared as a literal."
                ),
                confidence_score=confidence,
                detection_method="nosql_boolean_operator",
                method=method,
                detection_evidence={
                    "first_family": first,
                    "confirm_family": second,
                    "injection_parameter": parameter,
                },
                reproducible=True, verified=True,
                verification_request_snippet=first.get("request_snippet"),
                verification_response_snippet=first.get("response_snippet"),
            )
            return VerificationResult(
                is_vulnerable=True, confidence_score=confidence,
                detection_method="nosql_boolean_operator", findings=[finding],
                evidence={"families_diverged": [first["family"], second["family"]]},
                reproducible=True,
            )

        except Exception as e:
            logger.error("NoSQL boolean verification failed %s:%s: %s", url, parameter, e)
            return VerificationResult(
                is_vulnerable=False, confidence_score=0.0,
                detection_method="nosql_boolean_operator", findings=[],
                evidence={"error": str(e)},
            )

    async def _run_operator_pair(
        self,
        target: AttackTarget,
        canary: str,
        baseline: ResponseData,
        family: str,
        true_op: dict,
        false_op: dict,
    ) -> Optional[dict]:
        """Run one always-true/always-false operator pair; return detail if it diverged.

        Divergence with a healthy always-true response is the operator-evaluation
        signal. Returns ``None`` (pair rejected) on any of:
          * either probe budget-denied (untested),
          * the canary reflected literally (echoed, not evaluated),
          * the always-true operator did not yield a healthy 200,
          * the two responses did not meaningfully diverge.
        """
        true_resp = await self._send_operator(target, true_op, test_phase="nosql_bool_true")
        false_resp = await self._send_operator(target, false_op, test_phase="nosql_bool_false")

        if true_resp.not_tested or false_resp.not_tested:
            return None

        # Reflection guard: a literal canary echo means the object was stored/echoed
        # as text, not evaluated as an operator.
        if canary and canary in (true_resp.body or "") and canary not in (baseline.body or ""):
            return None

        # The always-true operator must be accepted and evaluated (healthy 200).
        if true_resp.status_code != 200:
            return None

        similarity = _body_similarity(true_resp.body, false_resp.body)
        diverged = (true_resp.status_code != false_resp.status_code) or (similarity <= _DIVERGE_MAX)
        if not diverged:
            return None

        return {
            "family": family,
            "true_op": true_op,
            "false_op": false_op,
            "true_status": true_resp.status_code,
            "false_status": false_resp.status_code,
            "similarity": similarity,
            "request_snippet": true_resp.request_snippet,
            "response_snippet": true_resp.response_snippet,
        }

    # ======================================================================
    # Technique 2: error-based
    # ======================================================================

    async def _verify_error_based(
        self,
        url: str,
        parameter: str,
        method: str,
        target: AttackTarget,
        baseline: ResponseData,
    ) -> VerificationResult:
        """Force a document-DB/ODM error with a malformed operator.

        Only document-DB-specific error markers count, and they must be ABSENT
        from the baseline. Two independent payloads must both trigger a new error
        before reporting — a single hit is recorded but never reported.
        """
        error_operators = [
            {"$regex": "("},          # invalid regex → "Regular expression is invalid"
            {"$regex": "*"},          # dangling quantifier → invalid regex
            {"$where": "return }"},   # malformed JS → "$where must be"/parse error
            {"$gt": {"$gt": ""}},     # nested operator where a value is expected
        ]

        try:
            baseline_body = baseline.body or ""
            first_payload: Optional[str] = None
            first_errors: Optional[list[str]] = None
            first_resp: Optional[ResponseData] = None

            for operator in error_operators:
                resp = await self._send_operator(target, operator, test_phase="nosql_error_injection")
                if resp.not_tested:
                    continue
                payload_text = json.dumps(operator, separators=(",", ":"))
                errors = _new_nosql_errors(baseline_body, resp.body or "", payload_text)
                if not errors:
                    continue

                if first_payload is None:
                    first_payload = payload_text
                    first_errors = errors
                    first_resp = resp
                    continue

                # Second independent payload confirmed a document-DB error.
                all_errors = sorted(set((first_errors or []) + errors))
                confidence = 85.0
                finding = self._create_finding(
                    category=OwaspCategory.a05,
                    vuln_type="NoSQL Injection (Error-Based)",
                    severity=SeverityLevel.high,
                    url=url, parameter=parameter, payload=payload_text,
                    evidence=(
                        f"Document-DB error triggered by '{first_payload}' and confirmed by "
                        f"'{payload_text}'. Errors (absent from baseline): {', '.join(all_errors[:3])}."
                    ),
                    confidence_score=confidence,
                    detection_method="nosql_error_based",
                    method=method,
                    detection_evidence={
                        "errors_detected": all_errors,
                        "first_payload": first_payload,
                        "confirm_payload": payload_text,
                    },
                    reproducible=True, verified=True,
                    verification_request_snippet=resp.request_snippet,
                    verification_response_snippet=resp.response_snippet,
                )
                return VerificationResult(
                    is_vulnerable=True, confidence_score=confidence,
                    detection_method="nosql_error_based", findings=[finding],
                    evidence={"errors": all_errors}, reproducible=True,
                )

            return VerificationResult(
                is_vulnerable=False, confidence_score=0.0,
                detection_method="nosql_error_based", findings=[],
                evidence={
                    "first_hit": first_payload,
                    "note": "single error hit - not reported without confirmation",
                } if first_payload else {},
            )

        except Exception as e:
            logger.error("NoSQL error verification failed %s:%s: %s", url, parameter, e)
            return VerificationResult(
                is_vulnerable=False, confidence_score=0.0,
                detection_method="nosql_error_based", findings=[],
                evidence={"error": str(e)},
            )

    # ======================================================================
    # Technique 3: timing-based blind
    # ======================================================================

    async def _verify_time_based(
        self,
        url: str,
        parameter: str,
        method: str,
        target: AttackTarget,
        baseline: ResponseData,
    ) -> VerificationResult:
        """Blind timing via a ``$where`` sleep-equivalent operator.

        Gated exactly like the SQLi time-based technique: skip when the baseline
        is already slow, require the observed delay to clear a relative floor
        (fraction of the intended sleep), and require the injected mean itself to
        be a substantial fraction of the sleep — so network jitter cannot pass.
        """
        sleep_ms = 3000
        sleep_operators = [
            {"$where": "sleep(3000)"},
            {"$where": "sleep(3000) || true"},
            {"$where": "function(){sleep(3000);return true;}"},
        ]

        try:
            baseline_times: list[float] = []
            if baseline is not None and not baseline.not_tested:
                baseline_times.append(baseline.response_time_ms)
            for _ in range(3 - len(baseline_times)):
                probe = await self._send_operator(
                    target, str(target.value), test_phase="nosql_time_baseline"
                )
                if probe.not_tested:
                    continue
                baseline_times.append(probe.response_time_ms)
                await asyncio.sleep(0.1)

            if not baseline_times:
                return VerificationResult(
                    is_vulnerable=False, confidence_score=0.0,
                    detection_method="nosql_time_based", findings=[],
                    evidence={"skipped": "not_tested_budget_denied"},
                )

            baseline_mean = sum(baseline_times) / len(baseline_times)
            if baseline_mean > 2000:
                return VerificationResult(
                    is_vulnerable=False, confidence_score=0.0,
                    detection_method="nosql_time_based", findings=[],
                    evidence={"skipped": "baseline_too_slow", "baseline_mean_ms": baseline_mean},
                )

            threshold_fraction = (
                getattr(self, "blind_timing_threshold", None)
                or get_settings().blind_injection_timing_threshold
            )

            for operator in sleep_operators:
                inj_times: list[float] = []
                last_resp: Optional[ResponseData] = None
                budget_denied = False
                for _ in range(2):
                    resp = await self._send_operator(
                        target, operator, test_phase="nosql_time_injection"
                    )
                    if resp.not_tested:
                        budget_denied = True
                        break
                    inj_times.append(resp.response_time_ms)
                    last_resp = resp
                    await asyncio.sleep(0.1)
                if budget_denied or not inj_times:
                    continue

                is_significant, timing = ResponseAnalyzer.is_timing_significant(
                    baseline_times, inj_times,
                    threshold_ms=sleep_ms * threshold_fraction,
                )
                if not is_significant:
                    continue

                diff_ms = timing.get("diff_ms", 0)
                injected_mean = timing.get("injected_mean", 0)
                if diff_ms < sleep_ms * 0.60 or injected_mean < sleep_ms * 0.50:
                    continue

                confidence = 75.0
                payload_text = json.dumps(operator, separators=(",", ":"))
                timing_evidence = {
                    **timing,
                    "baseline_times_ms": baseline_times,
                    "injected_times_ms": inj_times,
                    "baseline_mean_ms": round(baseline_mean, 1),
                    "injected_mean_ms": round(injected_mean, 1),
                    "delta_ms": round(diff_ms, 1),
                    "expected_sleep_ms": sleep_ms,
                }
                finding = self._create_finding(
                    category=OwaspCategory.a05,
                    vuln_type="NoSQL Injection (Time-Based Blind)",
                    severity=SeverityLevel.high,
                    url=url, parameter=parameter, payload=payload_text,
                    evidence=(
                        f"Response delayed {diff_ms:.0f}ms with a $where sleep operator "
                        f"(baseline_mean={baseline_mean:.0f}ms, injected_mean={injected_mean:.0f}ms, "
                        f"expected_sleep={sleep_ms}ms)."
                    ),
                    confidence_score=confidence,
                    detection_method="nosql_time_based",
                    method=method, detection_evidence=timing_evidence,
                    reproducible=True, verified=True,
                    verification_request_snippet=last_resp.request_snippet if last_resp else None,
                    verification_response_snippet=last_resp.response_snippet if last_resp else None,
                )
                return VerificationResult(
                    is_vulnerable=True, confidence_score=confidence,
                    detection_method="nosql_time_based", findings=[finding],
                    evidence=timing_evidence, reproducible=True,
                )

            return VerificationResult(
                is_vulnerable=False, confidence_score=0.0,
                detection_method="nosql_time_based", findings=[],
                evidence={"baseline_times": baseline_times},
            )

        except Exception as e:
            logger.error("NoSQL time verification failed %s:%s: %s", url, parameter, e)
            return VerificationResult(
                is_vulnerable=False, confidence_score=0.0,
                detection_method="nosql_time_based", findings=[],
                evidence={"error": str(e)},
            )
