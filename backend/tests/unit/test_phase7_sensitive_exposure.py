from types import SimpleNamespace

import httpx
import pytest

from app.core.crawler.models import RequestObservation, RouteCandidate, RouteSource
from app.core.detectors.sensitive_paths import SensitivePathsDetector
from app.models.vulnerability import SeverityLevel


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


def test_classify_content_detects_apache_autoindex():
    detector = SensitivePathsDetector()
    body = (
        "<html><head><title>Index of /uploads</title></head><body>"
        "<h1>Index of /uploads</h1><pre>"
        '<a href="../">../</a>'
        '<a href="report.pdf">report.pdf</a>'
        '<a href="notes.txt">notes.txt</a>'
        "</pre></body></html>"
    )

    matched, vuln_type, _evidence, severity = detector._classify_content(
        "/uploads/", body, "text/html"
    )

    assert matched is True
    assert vuln_type == "Directory Listing Exposed"
    assert severity == SeverityLevel.medium


def test_classify_content_does_not_flag_regular_html_as_autoindex():
    detector = SensitivePathsDetector()
    body = "<html><body><h1>Welcome</h1><p>Nothing to list here.</p></body></html>"

    matched, *_ = detector._classify_content("/home", body, "text/html")

    assert matched is False


def test_permutation_targets_derive_backup_and_dir_probes_from_crawl():
    detector = SensitivePathsDetector()

    targets = detector._permutation_targets(
        "https://example.test/",
        ["https://example.test/js/config.js", "https://other.test/evil.js"],
        {"assets": ["https://example.test/static/app.js"]},
    )

    # Backup permutation of a crawled file.
    assert "https://example.test/js/config.js.bak" in targets
    assert "https://example.test/static/app.js.old" in targets
    # Trailing-slash directory listing probe.
    assert "https://example.test/js/" in targets
    # Cross-origin URLs are excluded.
    assert not any("other.test" in t for t in targets)


@pytest.mark.asyncio
async def test_sensitive_path_detector_reports_autoindex_via_permutation(monkeypatch):
    detector = SensitivePathsDetector()

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def get(self, url):
            if url == "https://example.test/uploads/":
                return httpx.Response(
                    200,
                    text=(
                        "<html><head><title>Index of /uploads</title></head><body>"
                        "<h1>Index of /uploads</h1><pre>"
                        '<a href="../">../</a>'
                        '<a href="a.txt">a.txt</a>'
                        "</pre></body></html>"
                    ),
                    headers={"content-type": "text/html"},
                    request=httpx.Request("GET", url),
                )
            return httpx.Response(404, text="not found", request=httpx.Request("GET", url))

    monkeypatch.setattr("app.core.detectors.sensitive_paths.create_scan_client", lambda **kwargs: FakeClient())

    findings = await detector.detect(
        urls=["https://example.test/uploads/report.pdf"],
        forms=[],
        root_url="https://example.test/",
    )

    assert any(finding.vuln_type == "Directory Listing Exposed" for finding in findings)
    assert any(finding.url == "https://example.test/uploads/" for finding in findings)


@pytest.mark.asyncio
async def test_sensitive_path_detector_suppresses_spa_shell_200(monkeypatch):
    detector = SensitivePathsDetector()

    spa_shell = (
        "<!doctype html><html><head><title>My SPA</title></head>"
        "<body><div id='root'></div><script src='/main.js'></script></body></html>"
    )

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def get(self, url):
            # SPA catch-all: every path returns the same 200 HTML shell.
            return httpx.Response(
                200,
                text=spa_shell,
                headers={"content-type": "text/html"},
                request=httpx.Request("GET", url),
            )

    monkeypatch.setattr("app.core.detectors.sensitive_paths.create_scan_client", lambda **kwargs: FakeClient())

    findings = await detector.detect(
        urls=["https://example.test/"],
        forms=[],
        root_url="https://example.test/",
        is_spa=True,
        spa_root_html=spa_shell,
    )

    assert findings == []
