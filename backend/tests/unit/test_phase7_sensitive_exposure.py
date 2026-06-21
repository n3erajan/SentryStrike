from types import SimpleNamespace

import httpx
import pytest

from app.core.crawler.models import RequestObservation, RouteCandidate, RouteSource
from app.core.detectors.sensitive_paths import SensitivePathsDetector


def test_observed_response_finds_source_map_api_docs_stack_trace_and_secret_values():
    detector = SensitivePathsDetector()
    requests = [
        RequestObservation(
            url="https://example.test/static/app.js.map",
            method="GET",
            response_content_type="application/json",
            response_snippet='{"version":3,"sources":["src/app.ts"],"mappings":"AAAA"}',
        ),
        RequestObservation(
            url="https://example.test/openapi.json",
            method="GET",
            response_content_type="application/json",
            response_snippet='{"openapi":"3.0.0","paths":{"/api/users":{"get":{}}}}',
        ),
        RequestObservation(
            url="https://example.test/api/error",
            method="GET",
            response_content_type="text/plain",
            response_snippet="Traceback (most recent call last):\n  File \"app.py\", line 1",
        ),
        RequestObservation(
            url="https://example.test/api/config",
            method="GET",
            response_content_type="application/json",
            response_snippet='{"client_secret":"super-secret-value-12345"}',
        ),
    ]

    findings = detector._observed_response_findings({"requests": requests})
    vuln_types = {finding.vuln_type for finding in findings}

    assert "Exposed Source Map" in vuln_types
    assert "Exposed API Documentation" in vuln_types
    assert "Verbose Stack Trace Exposure" in vuln_types
    assert "Secret-Like Value Exposure" in vuln_types
    assert all(finding.detection_evidence["proof_type"] == "content_verified_observed_response" for finding in findings)


def test_plain_env_without_secret_pattern_is_not_classified_as_sensitive():
    detector = SensitivePathsDetector()

    matched, *_ = detector._classify_content("/.env", "APP_ENV=production\nDEBUG=false", "text/plain")

    assert matched is False


def test_spa_fallback_context_is_metadata_not_vulnerability():
    detector = SensitivePathsDetector()
    route = RouteCandidate(
        url="https://example.test/admin",
        source=RouteSource.javascript,
        is_spa_fallback=True,
    )

    findings = detector._spa_fallback_context_findings(
        {"root_url": "https://example.test/", "dead_routes": [route]}
    )

    assert findings == []


@pytest.mark.asyncio
async def test_sensitive_path_detector_requires_content_fingerprint_for_env(monkeypatch):
    detector = SensitivePathsDetector()

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def get(self, url):
            if url.endswith("/.env"):
                return httpx.Response(
                    200,
                    text="APP_ENV=production\nDEBUG=false",
                    headers={"content-type": "text/plain"},
                    request=httpx.Request("GET", url),
                )
            return httpx.Response(404, text="not found", request=httpx.Request("GET", url))

    monkeypatch.setattr("app.core.detectors.sensitive_paths.create_scan_client", lambda **kwargs: FakeClient())

    findings = await detector.detect(urls=["https://example.test/"], forms=[], root_url="https://example.test/")

    assert not any(finding.url.endswith("/.env") for finding in findings)


@pytest.mark.asyncio
async def test_sensitive_path_detector_reports_openapi_with_content_proof(monkeypatch):
    detector = SensitivePathsDetector()

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def get(self, url):
            if url.endswith("/openapi.json"):
                return httpx.Response(
                    200,
                    text='{"openapi":"3.0.0","paths":{"/api/users":{"get":{}}}}',
                    headers={"content-type": "application/json"},
                    request=httpx.Request("GET", url),
                )
            return httpx.Response(404, text="not found", request=httpx.Request("GET", url))

    monkeypatch.setattr("app.core.detectors.sensitive_paths.create_scan_client", lambda **kwargs: FakeClient())

    findings = await detector.detect(urls=["https://example.test/"], forms=[], root_url="https://example.test/")

    assert any(finding.vuln_type == "Exposed API Documentation" for finding in findings)
    assert any(
        finding.detection_evidence["proof_type"] == "content_verified_path_probe"
        for finding in findings
    )
