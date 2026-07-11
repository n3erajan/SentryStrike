from types import SimpleNamespace
from unittest.mock import patch

import pytest

from app.core.crawler.models import ParameterCandidate, ParameterLocation
from app.core.detectors.ssrf_detector import SSRFDetector
from app.core.verification.oast import OastClient
from app.core.verification.response_analyzer import ResponseData
from app.core.verification.verification_framework import HttpVerifier


class FakeOast(OastClient):
    def __init__(self) -> None:
        super().__init__("https://oast.test", None)
        self.interaction_id = "ssrf-test-id"

    def new_callback_url(self, purpose: str = "ssrf") -> tuple[str, str]:
        return "https://oast.test/ssrf-test-id", self.interaction_id

    async def poll(self, interaction_id: str):
        return [SimpleNamespace(interaction_id=interaction_id, raw={"id": interaction_id})]


@pytest.mark.asyncio
async def test_ssrf_detector_reports_blind_oast_callback_for_json_body_target():
    detector = SSRFDetector()
    parameter = ParameterCandidate(
        name="url",
        location=ParameterLocation.json_body,
        url="https://example.test/api/fetch",
        method="POST",
        baseline_value="https://example.test/image.png",
        parent_path="url",
    )
    request_bodies: list[object] = []

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        request_bodies.append(kwargs.get("json_body"))
        return ResponseData(
            200,
            {"content-type": "application/json"},
            '{"ok":true}',
            5.0,
            request_snippet=f"{method} {url}",
            response_snippet="HTTP/1.1 200 OK",
        )

    with patch.object(HttpVerifier, "send_request", send_request):
        findings = await detector.detect(
            urls=[],
            forms=[],
            parameters=[parameter],
            api_endpoints=[],
            oast_client=FakeOast(),
        )

    assert any(body == {"url": "https://oast.test/ssrf-test-id"} for body in request_bodies)
    assert any(f.vuln_type == "Blind Server-Side Request Forgery (SSRF)" for f in findings)


@pytest.mark.asyncio
async def test_ssrf_inband_fallback_reports_verified_when_strong_differential():
    """No OAST configured + internal target behaves strongly differently from
    the external control (timing delta) -> a VERIFIED in-band finding. The
    strong timing differential is accepted as verified because the server
    demonstrably reached the internal target and behaved differently."""
    detector = SSRFDetector()
    parameter = ParameterCandidate(
        name="url",
        location=ParameterLocation.json_body,
        url="https://example.test/api/fetch",
        method="POST",
        baseline_value="https://example.test/image.png",
        parent_path="url",
    )

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        payload = kwargs.get("payload") or ""
        if "127.0.0.1" in payload or "169.254.169.254" in payload:
            return ResponseData(200, {}, "blocked", 3000.0, request_snippet=f"{method} {url}", response_snippet="RESP")
        return ResponseData(200, {}, "external ok", 100.0, request_snippet=f"{method} {url}", response_snippet="RESP")

    with patch.object(HttpVerifier, "send_request", send_request):
        findings = await detector.detect(
            urls=[],
            forms=[],
            parameters=[parameter],
            api_endpoints=[],
        )

    verified = [f for f in findings if f.vuln_type == "Server-Side Request Forgery (SSRF)"]
    assert verified, "expected a verified in-band SSRF finding (strong timing differential)"
    assert verified[0].verified is True
    assert verified[0].detection_method == "ssrf_inband_differential"
    assert verified[0].confidence_score == 75.0


@pytest.mark.asyncio
async def test_ssrf_inband_fallback_reports_probable_for_body_length_only():
    """When the only differential is body-length (no status/timing divergence),
    the finding stays PROBABLE/unverified -- body-length alone is a weaker
    signal."""
    detector = SSRFDetector()
    parameter = ParameterCandidate(
        name="url",
        location=ParameterLocation.json_body,
        url="https://example.test/api/fetch",
        method="POST",
        baseline_value="https://example.test/image.png",
        parent_path="url",
    )

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        payload = kwargs.get("payload") or ""
        if "127.0.0.1" in payload or "169.254.169.254" in payload:
            return ResponseData(200, {}, "x" * 5000, 100.0, request_snippet=f"{method} {url}", response_snippet="RESP")
        return ResponseData(200, {}, "short", 100.0, request_snippet=f"{method} {url}", response_snippet="RESP")

    with patch.object(HttpVerifier, "send_request", send_request):
        findings = await detector.detect(
            urls=[],
            forms=[],
            parameters=[parameter],
            api_endpoints=[],
        )

    probable = [f for f in findings if f.vuln_type == "Server-Side Request Forgery (SSRF) - Probable"]
    assert probable, "expected a probable in-band SSRF finding (body-length-only)"
    assert probable[0].verified is False
    assert probable[0].detection_method == "ssrf_inband_differential"


@pytest.mark.asyncio
async def test_ssrf_inband_runs_as_fallback_when_oast_configured_but_no_callback():
    """When OAST is configured but didn't confirm, the in-band differential
    still runs as a fallback. OAST remains the higher-confidence path (it
    gets first dibs), but the in-band path is no longer gated on
    ``not oast.enabled`` -- it runs whenever no finding was confirmed."""
    detector = SSRFDetector()
    parameter = ParameterCandidate(
        name="url",
        location=ParameterLocation.json_body,
        url="https://example.test/api/fetch",
        method="POST",
        baseline_value="https://example.test/image.png",
        parent_path="url",
    )

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        payload = kwargs.get("payload") or ""
        if "127.0.0.1" in payload or "169.254.169.254" in payload:
            return ResponseData(200, {}, "blocked", 3000.0, request_snippet=f"{method} {url}", response_snippet="RESP")
        return ResponseData(200, {}, "external ok", 100.0, request_snippet=f"{method} {url}", response_snippet="RESP")

    class _NoInteractionOast(FakeOast):
        async def poll(self, interaction_id: str):
            return []

    with patch.object(HttpVerifier, "send_request", send_request):
        findings = await detector.detect(
            urls=[],
            forms=[],
            parameters=[parameter],
            api_endpoints=[],
            oast_client=_NoInteractionOast(),
        )

    inband = [f for f in findings if f.detection_method == "ssrf_inband_differential"]
    assert inband, "in-band fallback should run when OAST didn't confirm"
    assert inband[0].verified is True


@pytest.mark.asyncio
async def test_ssrf_inband_fallback_silent_when_no_differential():
    """Internal and external targets behave identically -> no in-band finding."""
    detector = SSRFDetector()
    parameter = ParameterCandidate(
        name="url",
        location=ParameterLocation.json_body,
        url="https://example.test/api/fetch",
        method="POST",
        baseline_value="https://example.test/image.png",
        parent_path="url",
    )

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        return ResponseData(200, {}, "same body", 100.0, request_snippet=f"{method} {url}", response_snippet="RESP")

    with patch.object(HttpVerifier, "send_request", send_request):
        findings = await detector.detect(
            urls=[],
            forms=[],
            parameters=[parameter],
            api_endpoints=[],
        )

    assert findings == []


def test_ssrf_inband_differential_evaluator_truth_cases():
    detector = SSRFDetector()
    delta = 1500.0
    # Consistent status divergence.
    assert detector._inband_differential(
        [(200, 10, 100.0), (200, 10, 110.0)],
        [(500, 5, 120.0), (500, 5, 130.0)],
        delta,
    )
    # Consistent large timing delta.
    assert detector._inband_differential(
        [(200, 10, 100.0), (200, 10, 100.0)],
        [(200, 10, 2000.0), (200, 10, 2000.0)],
        delta,
    )
    # Indistinguishable -> None.
    assert detector._inband_differential(
        [(200, 10, 100.0), (200, 10, 105.0)],
        [(200, 10, 110.0), (200, 10, 108.0)],
        delta,
    ) is None


def test_oast_client_extracts_interactions_from_common_payload_shapes():
    client = OastClient("https://oast.test", "https://oast.test/poll")

    assert client._extract_interactions({"interactions": [{"id": "a"}]}) == [{"id": "a"}]
    assert client._extract_interactions({"events": ["event-a"]}) == ["event-a"]
    assert client._extract_interactions("plain-event") == ["plain-event"]
