import pytest

from app.core.detectors.sql_injection import SQLInjectionDetector
from app.core.verification.sqli_verifier import SQLiVerifier
from app.core.verification.verification_framework import VerificationResult

def test_sqli_detector_excludes_submit_button():
    detector = SQLInjectionDetector()
    
    class FakeInput:
        def __init__(self, name, type):
            self.name = name
            self.input_type = type
    
    class FakeForm:
        def __init__(self):
            self.method = "POST"
            self.action = "http://example.com/login"
            self.inputs = [
                FakeInput("username", "text"),
                FakeInput("loginBtn", "submit"),
                FakeInput("resetBtn", "reset"),
                FakeInput("imageBtn", "image"),
            ]
            
    # Mock extract_candidates
    candidates = detector._extract_candidates(["http://example.com"], [FakeForm()])
    
    # We should only get candidates for "username", not the buttons
    params = [candidate.parameter for candidate in candidates if candidate.parameter]
    assert "username" in params
    assert "loginBtn" not in params
    assert "resetBtn" not in params
    assert "imageBtn" not in params


from app.core.verification.response_analyzer import ResponseData
from shared.models.vulnerability import SeverityLevel


@pytest.mark.asyncio
async def test_sqli_detector_configures_verifier_with_auth_headers(monkeypatch):
    detector = SQLInjectionDetector()
    observed: list[tuple[dict, dict]] = []

    async def verify(self, *args, **kwargs):
        observed.append((dict(self.http_verifier.headers), dict(self.http_verifier.cookies)))
        return VerificationResult(False, 0.0, "none")

    monkeypatch.setattr(SQLiVerifier, "verify", verify)

    await detector.detect(
        urls=["https://example.test/api/products?id=1"],
        forms=[],
        session_cookies={"sid": "abc"},
        auth_headers={"Authorization": "Bearer token"},
    )

    assert observed
    headers, cookies = observed[0]
    assert headers["User-Agent"] == "SentryStrikeScanner/1.0"
    assert headers["Authorization"] == "Bearer token"
    assert cookies == {"sid": "abc"}

@pytest.mark.asyncio
async def test_sqli_verifier_union_requires_version_proof():
    verifier = SQLiVerifier()
    
    # Mock _send to simulate responses with no canary and very high similarity (> 0.85)
    async def mock_send(url, method, params=None, data=None, **kwargs):
        body = "Some normal response" * 50
        if kwargs.get("test_phase") == "union_injection":
            # Change length slightly to make it "significant" (>50 diff) but keep similarity > 0.85
            body = ("Some normal response" * 50) + "A" * 55
        return ResponseData(
            status_code=200,
            headers={},
            body=body,
            response_time_ms=10.0,
            request_snippet="",
            response_snippet="",
        )
        
    verifier._send = mock_send
    
    result = await verifier._verify_union_based(
        url="http://example.com",
        parameter="id",
        method="GET",
        value="1",
    )
    
    # Since similarity > 0.85 and no canary was found, it should not be verified or is_vulnerable
    assert not result.is_vulnerable or not any(f.verified for f in result.findings)


@pytest.mark.asyncio
async def test_union_canary_with_literal_query_syntax_is_reflection_not_sqli():
    verifier = SQLiVerifier()
    baseline = ResponseData(200, {}, "guestbook", 1.0)

    async def mock_send(url, method, params=None, data=None, **kwargs):
        payload = kwargs.get("payload", "")
        body = f"guestbook entry: {payload}" if kwargs.get("test_phase") == "union_canary" else baseline.body
        return ResponseData(200, {}, body, 1.0, "POST /", body)

    verifier._send = mock_send
    result = await verifier._verify_union_based(
        "http://example.com/comments", "message", "POST", "hello",
        pre_test_baseline=baseline,
    )

    assert result.is_vulnerable is False


from app.core.verification.sqli_verifier import _has_sql_specific_error, _new_sql_errors


def test_postgres_error_markers_are_sql_specific():
    """PostgreSQL / node-postgres errors must count as SQL-engine-specific.

    Without these markers, error-based detection cannot fire on a pg target
    (the app leaks 'unterminated quoted string' / 'syntax error at or near'),
    so the verifier falls through to time-based and mislabels the finding.
    """
    pg_errors = [
        'error: unterminated quoted string at or near "\'1\'\'"',
        'error: syntax error at or near "x7e"',
        'invalid input syntax for type numeric: "abc"',
        'operator does not exist: text = integer',
        'error: unterminated quoted identifier at or near """',
    ]
    for body in pg_errors:
        assert _has_sql_specific_error(body), f"Postgres error not recognized: {body}"


def test_postgres_error_is_new_against_clean_json_baseline():
    """The ' payload on a pg endpoint whose baseline is an empty JSON array must
    surface a new, baseline-absent SQL error so error-based verification confirms."""
    baseline_body = "[]"
    injected_body = 'error: unterminated quoted string at or near "\'1\'\'"'
    errors = _new_sql_errors(baseline_body, injected_body, payload="'", baseline_value="1")
    assert errors, "a new Postgres error absent from baseline should be detected"


@pytest.mark.asyncio
async def test_error_based_confirms_on_postgres_target():
    """Two independent payloads must both raise a marker error before error-based
    reports vulnerable.

    Regression: on a PostgreSQL target the MySQL/Oracle payloads
    (extractvalue/updatexml/@@version) degrade to non-marker errors ("column
    \"version\" does not exist", "argument of AND must be type boolean"), so only
    the bare-quote probe matched - a single hit, which never satisfied the
    two-hit confirmation, and detection silently fell through to time-based. The
    added generic/PG syntax-breakers ("')", CAST) give the second hit.
    """
    verifier = SQLiVerifier()

    def resp(status, body):
        return ResponseData(
            status_code=status, headers={}, body=body,
            response_time_ms=5.0, request_snippet="GET /search", response_snippet=body,
        )

    async def mock_send(url, method, params=None, data=None, **kwargs):
        # Mirror the real pg target: only genuine quote/paren/cast breaks error
        # with an engine-specific marker; the MySQL/Oracle probes return 200 or a
        # non-marker error, exactly as observed live.
        payload = kwargs.get("payload", "")
        if payload == "'":
            return resp(500, 'error: unterminated quoted string at or near "\'1\'\'"')
        if payload in ("')", "'))"):
            return resp(500, 'error: syntax error at or near ")"')
        if "CAST('x' AS INT)" in payload:
            return resp(500, 'error: invalid input syntax for type integer: "x"')
        return resp(200, "[]")

    verifier._send = mock_send

    result = await verifier._verify_error_based(
        url="http://pg.test/search",
        parameter="search",
        method="GET",
        value="1",
        pre_test_baseline=resp(200, "[]"),
    )

    assert result.is_vulnerable is True
    assert result.detection_method == "error_based"
    assert result.findings and result.findings[0].verified
    assert result.findings[0].severity == SeverityLevel.critical


@pytest.mark.asyncio
async def test_union_canary_reflected_in_percent_encoded_url_is_not_sqli():
    """A request URL echoed back (canonical/self link, og:url, Location, ...) carries
    the payload PERCENT-ENCODED. The alphanumeric canary survives encoding, so it is
    found in the body, but ``UNION SELECT`` appears only as ``union%20select`` - which
    the raw literal guard misses. This reproduces the WordPress RSS ``<atom:link
    rel="self">`` false positive and must be suppressed on ANY stack that reflects the
    request URL."""
    import re
    from urllib.parse import quote

    verifier = SQLiVerifier()
    baseline = ResponseData(200, {}, "<rss><channel><title>Feed</title></channel></rss>", 1.0)

    async def mock_send(url, method, params=None, data=None, **kwargs):
        payload = kwargs.get("payload", "")
        if kwargs.get("test_phase") == "union_canary":
            # Reflect the full request URL exactly as an RSS self-link does: the
            # value ("1" baseline + payload) percent-encoded inside an href.
            encoded = quote(f"1{payload}")
            body = (
                '<?xml version="1.0"?><rss><channel>'
                f'<atom:link href="http://example.com/feed?id={encoded}" rel="self"/>'
                '<title>Feed</title></channel></rss>'
            )
        else:
            body = baseline.body
        return ResponseData(200, {}, body, 1.0, "GET /", body)

    verifier._send = mock_send
    result = await verifier._verify_union_based(
        "http://example.com/feed", "id", "GET", "1",
        pre_test_baseline=baseline,
    )

    assert result.is_vulnerable is False


@pytest.mark.asyncio
async def test_union_canary_genuinely_extracted_still_detected():
    """Positive control: the encoding-aware guard must not over-suppress. A real UNION
    is consumed by the DB and returns ONLY the extracted canary value - no ``UNION
    SELECT`` echo - so this must still be reported as vulnerable."""
    import re

    verifier = SQLiVerifier()
    baseline = ResponseData(200, {}, "<html><body>Product 1</body></html>", 1.0)

    async def mock_send(url, method, params=None, data=None, **kwargs):
        payload = kwargs.get("payload", "")
        if kwargs.get("test_phase") == "union_canary":
            match = re.search(r"sentryprobe_[0-9a-f]+", payload)
            extracted = match.group(0) if match else "missing"
            # Only the extracted value comes back - the query text does not.
            body = f"<html><body><td>{extracted}</td></body></html>"
        else:
            body = baseline.body
        return ResponseData(200, {}, body, 1.0, "GET /", body)

    verifier._send = mock_send
    result = await verifier._verify_union_based(
        "http://example.com/product", "id", "GET", "1",
        pre_test_baseline=baseline,
    )

    assert result.is_vulnerable is True


@pytest.mark.asyncio
async def test_sqli_verifier_suppresses_null_differential_without_extraction_proof():
    verifier = SQLiVerifier()
    baseline = ResponseData(
        status_code=200,
        headers={},
        body="A" * 1000,
        response_time_ms=10.0,
        request_snippet="",
        response_snippet="",
    )

    async def mock_send(url, method, params=None, data=None, **kwargs):
        phase = kwargs.get("test_phase")
        if phase == "union_canary":
            body = baseline.body
        elif phase in {"union_null", "union_cross_column_confirm"}:
            body = ("A" * 850) + ("B" * 150)
        elif phase == "union_version_extract":
            body = ("A" * 850) + ("C" * 150)
        else:
            body = baseline.body
        return ResponseData(
            status_code=200,
            headers={},
            body=body,
            response_time_ms=10.0,
            request_snippet="",
            response_snippet="",
        )

    verifier._send = mock_send

    result = await verifier._verify_union_based(
        url="http://example.com/search?q=1",
        parameter="q",
        method="GET",
        value="1",
        pre_test_baseline=baseline,
    )

    assert result.is_vulnerable is False
    assert result.findings == []
    assert result.evidence["reason"] == "null_differential_without_extraction_proof"

@pytest.mark.asyncio
async def test_sqli_verifier_boolean_requires_confirmation():
    verifier = SQLiVerifier()
    
    async def mock_send(url, method, params=None, data=None, **kwargs):
        phase = kwargs.get("test_phase")
        if phase == "pre_test_baseline":
            body = "base response"
            status = 200
        elif phase == "boolean_true":
            body = "base response"
            status = 200
        elif phase == "boolean_false":
            body = "different response"
            status = 200
        elif phase == "boolean_confirm_true":
            # Confirmation fails: true response is different (doesn't match baseline/true response)
            body = "different response"
            status = 200
        elif phase == "boolean_confirm_false":
            body = "different response"
            status = 200
        else:
            body = "base response"
            status = 200
            
        return ResponseData(
            status_code=status,
            headers={},
            body=body,
            response_time_ms=10.0,
            request_snippet="",
            response_snippet="",
        )
        
    verifier._send = mock_send
    
    result = await verifier._verify_boolean_based(
        url="http://example.com",
        parameter="id",
        method="GET",
        value="1",
    )
    
    # Since confirmation true/false matched but the second pair confirmation failed, it should not be vulnerable
    assert not result.is_vulnerable


@pytest.mark.asyncio
async def test_sqli_boolean_detects_repeatable_small_template_differential():
    verifier = SQLiVerifier()
    baseline = ResponseData(200, {}, ("TEMPLATE" * 600) + "ROW:alice", 1.0)

    async def mock_send(url, method, params=None, data=None, **kwargs):
        phase = kwargs.get("test_phase")
        if phase in {"boolean_true", "boolean_confirm_true"}:
            body = baseline.body
        elif phase in {"boolean_false", "boolean_confirm_false"}:
            body = "TEMPLATE" * 600
        else:
            body = baseline.body
        return ResponseData(200, {}, body, 1.0, request_snippet="GET /", response_snippet=body)

    verifier._send = mock_send
    result = await verifier._verify_boolean_based(
        "http://example.com/search?id=1",
        "id",
        "GET",
        "1",
        pre_test_baseline=baseline,
        baseline_stability=1.0,
    )

    assert result.is_vulnerable is True
    assert result.detection_method == "boolean_differential"


@pytest.mark.asyncio
async def test_sqli_time_based_rejects_target_wide_queue_delay():
    verifier = SQLiVerifier()
    baseline = ResponseData(200, {}, "stable", 10.0)

    async def mock_send(url, method, params=None, data=None, **kwargs):
        phase = kwargs.get("test_phase")
        elapsed = 3000.0 if phase in {"time_injection", "time_control_after"} else 10.0
        return ResponseData(200, {}, "stable", elapsed, "GET /", "stable")

    verifier._send = mock_send
    result = await verifier._verify_time_based(
        "http://example.com/search?id=1", "id", "GET", "1",
        pre_test_baseline=baseline,
    )

    assert result.is_vulnerable is False
    assert result.findings == []


@pytest.mark.asyncio
async def test_sqli_time_based_requires_two_paired_confirmations():
    verifier = SQLiVerifier()
    baseline = ResponseData(200, {}, "stable", 10.0)

    async def mock_send(url, method, params=None, data=None, **kwargs):
        phase = kwargs.get("test_phase")
        elapsed = 3010.0 if phase == "time_injection" else 10.0
        return ResponseData(200, {}, "stable", elapsed, "GET /", "stable")

    verifier._send = mock_send
    result = await verifier._verify_time_based(
        "http://example.com/search?id=1", "id", "GET", "1",
        pre_test_baseline=baseline,
    )

    assert result.is_vulnerable is True
    assert len(result.evidence["paired_confirmations"]) == 2


def test_sqli_verifier_prepends_baseline_to_payload():
    verifier = SQLiVerifier()

    url, _, _, _, _ = verifier._build_request_args(
        "http://example.com/sqli?id=1",
        "id",
        "' AND '1'='1",
        "GET",
        None,
        baseline_value="1",
    )

    assert "id=1%27+AND+%271%27%3D%271" in url or "id=1' AND '1'='1" in url


def test_sqli_verifier_resolves_value_from_url():
    verifier = SQLiVerifier()
    resolved = verifier._resolve_baseline_value(
        "http://example.com/sqli?id=1&Submit=Submit",
        "id",
        "",
        None,
    )
    assert resolved == "1"


@pytest.mark.asyncio
async def test_sqli_verifier_aborts_on_dead_baseline():
    """A 401/404 baseline means the endpoint is unreachable as sent - the full
    payload matrix must NOT fire (that was ~55% of wasted SQLi traffic)."""
    verifier = SQLiVerifier()
    phases: list[str] = []

    async def mock_send(url, method="GET", params=None, data=None, **kwargs):
        phase = kwargs.get("test_phase")
        phases.append(phase)
        # Every request (baseline included) is a hard 401 auth wall.
        return ResponseData(
            status_code=401, headers={}, body="Unauthorized",
            response_time_ms=5.0, request_snippet="", response_snippet="",
        )

    verifier._send = mock_send

    result = await verifier.verify(
        url="http://example.com/api/Feedbacks/",
        parameter="UserId",
        method="POST",
        value="1",
    )

    assert result.is_vulnerable is False
    assert result.evidence.get("skipped") == "dead_baseline"
    assert result.evidence.get("baseline_status") == 401
    # Only the baseline probe ran; no injection phase was attempted.
    assert phases == ["pre_test_baseline"]
    assert not any(
        p and ("injection" in p or "boolean" in p or "union" in p or "time" in p)
        for p in phases
    )


@pytest.mark.asyncio
async def test_sqli_verifier_proceeds_on_healthy_baseline_status():
    """A healthy 200 baseline (login-style flow) must NOT be gated - injection
    phases still run so real login SQLi is preserved."""
    verifier = SQLiVerifier()
    phases: list[str] = []

    async def mock_send(url, method="GET", params=None, data=None, **kwargs):
        phase = kwargs.get("test_phase")
        phases.append(phase)
        return ResponseData(
            status_code=200, headers={}, body="ok" * 100,
            response_time_ms=5.0, request_snippet="", response_snippet="",
        )

    verifier._send = mock_send

    result = await verifier.verify(
        url="http://example.com/rest/user/login",
        parameter="email",
        method="POST",
        value="a@b.c",
    )

    # Not gated: the verifier moved past the baseline into real technique phases.
    assert result.evidence.get("skipped") != "dead_baseline"
    assert len(phases) > 1
