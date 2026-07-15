import pytest

from app.core.crawler.models import ParameterLocation
from app.core.detectors.attack_planner import BODY_RELEVANT_DETECTORS
from app.core.detectors.attack_surface import AttackTarget
from app.core.detectors.base_detector import Finding
from app.core.detectors.nosql_injection import NoSqlInjectionDetector
from app.core.verification.nosqli_verifier import NoSqliVerifier
from app.core.verification.response_analyzer import ResponseData
from app.core.verification.verification_framework import VerificationResult
from shared.models.vulnerability import OwaspCategory, SeverityLevel


def _json_body_target() -> AttackTarget:
    return AttackTarget(
        url="http://example.com/rest/track-order",
        parameter="orderId",
        method="POST",
        value="abc123",
        location=ParameterLocation.json_body,
        parent_path="orderId",
        json_template={"orderId": "abc123"},
    )


def _resp(status: int, body: str) -> ResponseData:
    return ResponseData(
        status_code=status,
        headers={},
        body=body,
        response_time_ms=10.0,
        request_snippet="",
        response_snippet="",
    )


@pytest.mark.asyncio
async def test_boolean_operator_differential_is_flagged():
    """Always-true operator returns healthy 200 that diverges from always-false;
    two operator families diverge → verified NoSQL operator injection."""
    verifier = NoSqliVerifier()

    async def mock_send(url, method="POST", params=None, data=None, **kwargs):
        phase = kwargs.get("test_phase")
        if phase == "nosql_bool_true":
            # Broad match: the whole product list comes back.
            return _resp(200, "PRODUCT " * 300)
        if phase == "nosql_bool_false":
            # No match: empty result set — diverges from the true response.
            return _resp(200, "[]")
        # baseline / stability / error-injection: a stable benign body.
        return _resp(200, "N" * 500)

    verifier._send = mock_send

    result = await verifier.verify(
        url="http://example.com/rest/track-order",
        parameter="orderId",
        method="POST",
        value="abc123",
        target=_json_body_target(),
    )

    assert result.is_vulnerable
    assert result.detection_method == "nosql_boolean_operator"
    finding = result.findings[0]
    assert finding.vuln_type == "NoSQL Injection (Boolean Operator)"
    assert finding.category == OwaspCategory.a05
    assert finding.verified is True
    assert len(result.evidence["families_diverged"]) >= 2


@pytest.mark.asyncio
async def test_benign_endpoint_is_not_flagged():
    """When the server treats the operator object as a literal, always-true and
    always-false collapse to the same response → no divergence → no finding."""
    verifier = NoSqliVerifier()

    async def mock_send(url, method="POST", params=None, data=None, **kwargs):
        # Every request — true, false, baseline — returns the identical body.
        return _resp(200, "N" * 500)

    verifier._send = mock_send

    result = await verifier.verify(
        url="http://example.com/rest/track-order",
        parameter="orderId",
        method="POST",
        value="abc123",
        target=_json_body_target(),
    )

    assert result.is_vulnerable is False
    assert result.findings == []


@pytest.mark.asyncio
async def test_error_based_requires_two_confirmations():
    """Two malformed operators both surface a document-DB error marker absent
    from the baseline → verified error-based NoSQL injection."""
    verifier = NoSqliVerifier()

    async def mock_send(url, method="POST", params=None, data=None, **kwargs):
        phase = kwargs.get("test_phase")
        if phase == "nosql_bool_true" or phase == "nosql_bool_false":
            # No boolean divergence — force the error technique to be the signal.
            return _resp(200, "N" * 500)
        if phase == "nosql_error_injection":
            return _resp(500, "MongoServerError: unknown operator: $nope")
        return _resp(200, "N" * 500)

    verifier._send = mock_send

    result = await verifier.verify(
        url="http://example.com/rest/track-order",
        parameter="orderId",
        method="POST",
        value="abc123",
        target=_json_body_target(),
    )

    assert result.is_vulnerable
    assert result.detection_method == "nosql_error_based"
    assert result.findings[0].vuln_type == "NoSQL Injection (Error-Based)"


@pytest.mark.asyncio
async def test_single_error_hit_is_not_reported():
    """One malformed operator surfacing an error is recorded but not reported —
    a second independent confirmation is required."""
    verifier = NoSqliVerifier()
    calls = {"error": 0}

    async def mock_send(url, method="POST", params=None, data=None, **kwargs):
        phase = kwargs.get("test_phase")
        if phase in ("nosql_bool_true", "nosql_bool_false"):
            return _resp(200, "N" * 500)
        if phase == "nosql_error_injection":
            calls["error"] += 1
            # Only the FIRST error payload surfaces a marker.
            if calls["error"] == 1:
                return _resp(500, "MongoServerError: unknown operator")
            return _resp(200, "N" * 500)
        return _resp(200, "N" * 500)

    verifier._send = mock_send

    result = await verifier.verify(
        url="http://example.com/rest/track-order",
        parameter="orderId",
        method="POST",
        value="abc123",
        target=_json_body_target(),
    )

    assert result.is_vulnerable is False


@pytest.mark.asyncio
async def test_operator_pair_reflection_is_rejected():
    """A literal canary echo means the object was stored/echoed as text, not
    evaluated as an operator — the pair is rejected."""
    verifier = NoSqliVerifier()
    target = _json_body_target()
    baseline = _resp(200, "N" * 500)

    async def mock_send(url, method="POST", params=None, data=None, **kwargs):
        phase = kwargs.get("test_phase")
        if phase == "nosql_bool_true":
            # Echo the canary back verbatim (JSON body carries {"$ne": canary}).
            body = kwargs.get("payload", "")
            return _resp(200, f"you searched for {body}")
        return _resp(200, "[]")

    verifier._send = mock_send

    # Use the ne_eq family whose true operator carries the canary.
    canary = "SENTRYCANARY123"
    detail = await verifier._run_operator_pair(
        target, canary, baseline, "ne_eq", {"$ne": canary}, {"$eq": canary}
    )
    assert detail is None


def _query_target() -> AttackTarget:
    return AttackTarget(
        url="http://example.com/api/products?category=fruit",
        parameter="category",
        method="GET",
        value="fruit",
        location=ParameterLocation.query,
    )


@pytest.mark.asyncio
async def test_bracket_notation_query_operator_is_flagged():
    """A query param via bracket notation (`category[$ne]=`) that diverges across
    two operator families is flagged — the classic query/form NoSQL vector."""
    verifier = NoSqliVerifier()
    seen: dict[str, str] = {}

    async def mock_send(url, method="GET", params=None, data=None, **kwargs):
        phase = kwargs.get("test_phase")
        if phase == "nosql_bool_true":
            seen["true_url"] = url
            return _resp(200, "PRODUCT " * 300)
        if phase == "nosql_bool_false":
            return _resp(200, "[]")
        return _resp(200, "N" * 500)

    verifier._send = mock_send

    result = await verifier.verify(
        url="http://example.com/api/products?category=fruit",
        parameter="category",
        method="GET",
        value="fruit",
        target=_query_target(),
    )

    assert result.is_vulnerable
    assert result.detection_method == "nosql_boolean_operator"
    # The operator went out as bracket notation (`category[$...]=`), not a plain
    # value. `category[$` percent-encodes to `category%5B%24`.
    assert "category%5B%24" in seen["true_url"]
    # The plain `category=fruit` pair was replaced, not appended.
    assert "category=fruit" not in seen["true_url"]


@pytest.mark.asyncio
async def test_non_injectable_target_is_skipped():
    """Path/header/cookie locations cannot express a nested operator — skipped."""
    verifier = NoSqliVerifier()
    path_target = AttackTarget(
        url="http://example.com/rest/track-order/{id}",
        parameter="id",
        method="GET",
        value="1",
        location=ParameterLocation.path,
    )
    result = await verifier.verify(
        url="http://example.com/rest/track-order/{id}",
        parameter="id",
        method="GET",
        value="1",
        target=path_target,
    )
    assert result.is_vulnerable is False
    assert result.evidence.get("skipped") == "not_injectable_parameter"


@pytest.mark.asyncio
async def test_dead_baseline_aborts():
    verifier = NoSqliVerifier()

    async def mock_send(url, method="POST", params=None, data=None, **kwargs):
        return _resp(404, "Not Found")

    verifier._send = mock_send
    result = await verifier.verify(
        url="http://example.com/rest/track-order",
        parameter="orderId",
        method="POST",
        value="abc123",
        target=_json_body_target(),
    )
    assert result.is_vulnerable is False
    assert result.evidence.get("skipped") == "dead_baseline"


def test_detector_selects_json_body_and_query_form_targets():
    detector = NoSqlInjectionDetector()
    json_target = _json_body_target()
    query_target = AttackTarget(
        url="http://example.com/search?q=abc",
        parameter="q",
        method="GET",
        value="abc",
        location=ParameterLocation.query,
    )
    path_target = AttackTarget(
        url="http://example.com/rest/track-order/{id}",
        parameter="id",
        method="GET",
        value="1",
        location=ParameterLocation.path,
    )
    # JSON body and real (replayable) query/form params are in scope; path is not.
    assert detector._is_nosql_candidate(json_target) is True
    assert detector._is_nosql_candidate(query_target) is True
    assert detector._is_nosql_candidate(path_target) is False


@pytest.mark.asyncio
async def test_detector_returns_verifier_findings(monkeypatch):
    detector = NoSqlInjectionDetector()
    json_target = _json_body_target()

    class FakePlanner:
        def targets_for(self, name):
            assert name == "nosql_injection"
            return [json_target]

    async def fake_verify(self, *args, **kwargs):
        return VerificationResult(
            is_vulnerable=True,
            confidence_score=80.0,
            detection_method="nosql_boolean_operator",
            findings=[
                Finding(
                    category=OwaspCategory.a05,
                    vuln_type="NoSQL Injection (Boolean Operator)",
                    severity=SeverityLevel.high,
                    url=json_target.url,
                    parameter="orderId",
                )
            ],
        )

    monkeypatch.setattr(NoSqliVerifier, "verify", fake_verify)

    findings = await detector.detect(
        urls=[],
        forms=[],
        attack_planner=FakePlanner(),
    )
    assert len(findings) == 1
    assert findings[0].vuln_type == "NoSQL Injection (Boolean Operator)"


def test_nosql_detector_is_registered_as_body_relevant():
    assert "nosql_injection" in BODY_RELEVANT_DETECTORS
