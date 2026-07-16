import pytest

from app.core.crawler.models import ApiEndpoint, ParameterCandidate, ParameterLocation, RequestObservation
from app.core.detectors.command_injection import CommandInjectionDetector
from app.core.detectors.file_inclusion import FileInclusionDetector
from app.core.detectors.xss_detector import XSSDetector
from app.core.detectors.attack_surface import AttackSurface, AttackTarget
from app.core.verification.response_analyzer import ResponseData
from app.core.verification.verification_framework import BaseVerifier, HttpVerifier
from app.core.verification.xss_verifier import XSSVerifier


def test_xss_verifier_builds_json_attack_request_from_attack_target() -> None:
    endpoint = ApiEndpoint(
        url="https://example.com/api/comments",
        method="POST",
        request_body={"comment": "hello", "metadata": {"source": "web"}},
        headers={"Authorization": "Bearer token"},
    )
    target = AttackSurface.build(
        [],
        [],
        api_endpoints=[endpoint],
        filter_fn=lambda name: name == "comment",
    )[0]

    verifier = XSSVerifier()
    url, method, params, data, json_body, headers, cookies = verifier._build_attack_request(
        target.url,
        target.parameter,
        target.method,
        "<script>alert(1)</script>",
        target=target,
    )

    assert url == "https://example.com/api/comments"
    assert method == "POST"
    assert params is None
    assert data is None
    assert json_body == {"comment": "<script>alert(1)</script>", "metadata": {"source": "web"}}
    assert headers == {"Authorization": "Bearer token", "Content-Type": "application/json"}
    assert cookies is None


def test_xss_verifier_builds_path_attack_request_from_attack_target() -> None:
    target = AttackTarget(
        url="https://example.com/api/products/{productId}",
        parameter="productId",
        location=ParameterLocation.path,
    )

    verifier = XSSVerifier()
    url, method, params, data, json_body, headers, cookies = verifier._build_attack_request(
        target.url,
        target.parameter,
        target.method,
        "<img src=x onerror=alert(1)>",
        target=target,
    )

    assert url == "https://example.com/api/products/%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E"
    assert method == "GET"
    assert params is None
    assert data is None
    assert json_body is None
    assert headers is None
    assert cookies is None


@pytest.mark.asyncio
async def test_xss_detector_tests_browser_observed_json_body_targets(monkeypatch) -> None:
    request = RequestObservation(
        url="https://example.com/api/comments",
        method="POST",
        request_headers={"content-type": "application/json"},
        post_data='{"comment":"hello"}',
    )
    seen_json_bodies: list[object] = []

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        json_body = kwargs.get("json_body")
        seen_json_bodies.append(json_body)
        body = ""
        if isinstance(json_body, dict):
            reflected = str(json_body.get("comment", ""))
            body = f'{{"comment":"{reflected.replace("<", "&lt;").replace(">", "&gt;")}"}}'
        return ResponseData(
            status_code=200,
            headers={"content-type": "application/json"},
            body=body,
            response_time_ms=1.0,
            request_snippet=f"{method} {url}",
            response_snippet=body,
        )

    monkeypatch.setattr(HttpVerifier, "send_request", send_request)
    monkeypatch.setattr("app.core.verification.xss_verifier.PLAYWRIGHT_AVAILABLE", False)

    findings = await XSSDetector().detect(urls=[], forms=[], requests=[request])

    assert any(isinstance(body, dict) and "comment" in body for body in seen_json_bodies)
    assert any(f.vuln_type == "Reflected XSS in API Response" for f in findings)


@pytest.mark.asyncio
async def test_file_inclusion_detector_replays_json_body_targets(monkeypatch) -> None:
    parameter = ParameterCandidate(
        name="path",
        location=ParameterLocation.json_body,
        url="https://example.com/api/render",
        method="POST",
        baseline_value="index.html",
        parent_path="path",
    )
    endpoint = ApiEndpoint(
        url="https://example.com/api/render",
        method="POST",
        request_body={"path": "index.html", "theme": "light"},
        headers={"Content-Type": "application/json"},
    )
    seen_json_bodies: list[object] = []

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        json_body = kwargs.get("json_body")
        seen_json_bodies.append(json_body)
        body = "normal"
        if isinstance(json_body, dict) and "etc/passwd" in str(json_body.get("path", "")):
            body = "root:x:0:0:root:/root:/bin/bash"
        return ResponseData(
            status_code=200,
            headers={"content-type": "text/plain"},
            body=body,
            response_time_ms=1.0,
            request_snippet=f"{method} {url}",
            response_snippet=body,
        )

    monkeypatch.setattr(HttpVerifier, "send_request", send_request)

    findings = await FileInclusionDetector().detect(
        urls=[],
        forms=[],
        parameters=[parameter],
        api_endpoints=[endpoint],
    )

    assert any(isinstance(body, dict) and body.get("theme") == "light" for body in seen_json_bodies)
    assert any(f.vuln_type in {"Path Traversal / Arbitrary File Read", "Local File Inclusion (LFI)"} for f in findings)


def test_command_injection_uses_endpoint_context_for_generic_parameters() -> None:
    detector = CommandInjectionDetector()
    contextual_target = AttackTarget(
        url="https://example.com/api/diagnostic/lookup",
        parameter="value",
        location=ParameterLocation.json_body,
    )
    generic_target = AttackTarget(
        url="https://example.com/api/profile",
        parameter="value",
        location=ParameterLocation.json_body,
    )

    assert detector._is_command_candidate(contextual_target)
    assert not detector._is_command_candidate(generic_target)


def test_static_dom_xss_findings_mark_sink_only_as_unverified_probable() -> None:
    findings = XSSDetector._static_dom_findings(
        {
            "root_url": "https://example.com/",
            "spa_root_html": """
                <script>
                  const value = new URLSearchParams(location.search).get('next');
                  document.querySelector('#out').innerHTML = value;
                </script>
            """,
        }
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.vuln_type == "DOM-Based XSS"
    assert finding.verified is False
    assert finding.detection_evidence["browser_execution_confirmed"] is False


@pytest.mark.asyncio
async def test_base_verifier_baseline_uses_full_attack_target_request_shape(monkeypatch) -> None:
    class DummyVerifier(BaseVerifier):
        async def verify(self, url: str, parameter: str, method: str = "GET", value: str = ""):
            raise NotImplementedError

    endpoint = ApiEndpoint(
        url="https://example.com/api/comments",
        method="POST",
        request_body={"comment": "hello", "metadata": {"source": "web"}},
        headers={"Authorization": "Bearer token"},
    )
    target = AttackSurface.build(
        [],
        [],
        api_endpoints=[endpoint],
        filter_fn=lambda name: name == "comment",
    )[0]
    calls: list[dict[str, object]] = []

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        calls.append(
            {
                "url": url,
                "method": method,
                "params": params,
                "data": data,
                "json_body": kwargs.get("json_body"),
                "headers": kwargs.get("headers"),
            }
        )
        return ResponseData(200, {"content-type": "application/json"}, "{}", 1.0)

    monkeypatch.setattr(HttpVerifier, "send_request", send_request)

    await DummyVerifier().fetch_pre_test_baseline(
        target.url,
        target.parameter,
        target.method,
        "hello",
        target=target,
    )

    assert calls == [
        {
            "url": "https://example.com/api/comments",
            "method": "POST",
            "params": None,
            "data": None,
            "json_body": {"comment": "hello", "metadata": {"source": "web"}},
            "headers": {"Authorization": "Bearer token", "Content-Type": "application/json"},
        }
    ]


@pytest.mark.asyncio
async def test_http_verifier_configure_auth_resets_stale_client() -> None:
    verifier = HttpVerifier()
    original_client = await verifier.get_client()

    await verifier.configure_auth(auth_headers={"Authorization": "Bearer fresh"})

    assert verifier._client is None
    assert verifier.headers["Authorization"] == "Bearer fresh"
    assert verifier.headers["User-Agent"] == "SentryStrikeScanner/1.0"
    assert original_client.is_closed

    await verifier.close()


@pytest.mark.asyncio
async def test_static_dom_findings_are_upgraded_when_browser_execution_confirms(monkeypatch) -> None:
    async def confirm_dom_execution(self, url: str) -> bool:
        return url == "https://example.com/"

    monkeypatch.setattr(XSSVerifier, "verify_dom_xss_execution", confirm_dom_execution)

    findings = await XSSDetector._static_dom_findings_with_browser_confirmation(
        {
            "root_url": "https://example.com/",
            "spa_root_html": """
                <script>
                  const value = location.hash;
                  document.write(value);
                </script>
            """,
        },
        session_cookies={},
    )

    assert len(findings) == 1
    assert findings[0].verified is True
    assert findings[0].confidence_score == 90.0
    assert findings[0].detection_method == "dom_xss_browser_execution"
    assert findings[0].detection_evidence["browser_execution_confirmed"] is True
