from __future__ import annotations

import asyncio

import pytest

from app.core.crawler.models import ParameterLocation
from app.core.detectors.attack_surface import AttackTarget
from app.core.detectors.xss_detector import XSSDetector
from app.core.verification.xss_verifier import XSSVerifier


def _qtarget(url: str, param: str) -> AttackTarget:
    return AttackTarget(url=url, parameter=param, method="GET", location=ParameterLocation.query)


# --- pure selection / probe-url helpers ------------------------------------------------


def test_select_dom_reflection_jobs_prioritises_and_caps():
    detector = XSSDetector()
    targets = [
        _qtarget("http://x/#/search", "q"),          # reflective name
        _qtarget("http://x/#/profile", "xyzzy"),      # non-reflective
        _qtarget("http://x/#/post", "comment"),       # echoed (below)
        AttackTarget(url="http://x/api", parameter="body", method="POST", location=ParameterLocation.form),
    ]

    class _F:
        parameter = "comment"

    jobs = detector._select_dom_reflection_jobs(targets, [_F()], max_jobs=10)
    params = [param for _, param, _ in jobs]
    # POST/form target excluded; echoed 'comment' first, reflective 'q' next, 'xyzzy' last.
    assert "body" not in params
    assert params[0] == "comment"
    assert set(params) == {"comment", "q", "xyzzy"}

    capped = detector._select_dom_reflection_jobs(targets, [_F()], max_jobs=1)
    assert capped == [("http://x/#/post", "comment", "both")]


def test_build_reflection_probe_urls_query_and_fragment():
    verifier = XSSVerifier()
    payload = "<img src=x onerror=1>"
    urls = verifier._build_reflection_probe_urls("http://x/#/search", "q", "both", payload)
    assert len(urls) == 2

    def before_hash(u: str) -> str:
        return u.split("#", 1)[0]

    def after_hash(u: str) -> str:
        return u.split("#", 1)[1] if "#" in u else ""

    # exactly one probe delivers q in the query string, one in the hash fragment
    query_delivery = [u for u in urls if "q=" in before_hash(u)]
    frag_delivery = [u for u in urls if "q=" in after_hash(u)]
    assert len(query_delivery) == 1
    assert len(frag_delivery) == 1


def test_build_reflection_probe_urls_respects_pinned_location():
    verifier = XSSVerifier()
    only_query = verifier._build_reflection_probe_urls("http://x/p", "q", "query", "PAY")
    assert len(only_query) == 1 and "#" not in only_query[0]
    only_frag = verifier._build_reflection_probe_urls("http://x/p", "q", "fragment", "PAY")
    assert len(only_frag) == 1 and "#" in only_frag[0]


# --- sweep gating ----------------------------------------------------------------------


def test_sweep_skipped_when_browser_unavailable():
    detector = XSSDetector()
    targets = [_qtarget("http://x/#/search", "q")]
    result = asyncio.run(
        detector._browser_dom_reflection_sweep(targets, [], {}, browser_available=False, existing_findings=[])
    )
    assert result == []


def test_sweep_invokes_verify_reflected_dom_and_builds_finding(monkeypatch):
    detector = XSSDetector()
    targets = [_qtarget("http://x/#/search", "q")]

    calls: list[tuple[str, str, str]] = []

    class _FakeContext:
        async def close(self):
            pass

    class _FakeBrowser:
        async def new_context(self, **kwargs):
            return _FakeContext()

    class _FakeChromium:
        async def launch(self, **kwargs):
            return _FakeBrowser()

    class _FakeP:
        chromium = _FakeChromium()

        async def stop(self):
            pass

    class _FakePlaywrightCM:
        async def start(self):
            return _FakeP()

    monkeypatch.setattr("app.core.detectors.xss_detector.async_playwright", lambda: _FakePlaywrightCM())
    monkeypatch.setattr("app.core.detectors.xss_detector.PLAYWRIGHT_AVAILABLE", True)

    async def fake_new_ctx(self, browser, route_url, storage_state=None):
        return _FakeContext()

    async def fake_verify(self, route_url, parameter, location, *, canary=None, context=None):
        calls.append((route_url, parameter, location))
        return parameter == "q"

    monkeypatch.setattr(XSSVerifier, "_new_reflection_context", fake_new_ctx)
    monkeypatch.setattr(XSSVerifier, "verify_reflected_dom", fake_verify)

    findings = asyncio.run(
        detector._browser_dom_reflection_sweep(targets, [], {}, browser_available=True, existing_findings=[])
    )

    assert calls == [("http://x/#/search", "q", "both")]
    assert len(findings) == 1
    finding = findings[0]
    assert finding.verified is True
    assert finding.detection_method == "dom_xss_browser_execution"
    assert finding.parameter == "q"


def test_detect_runs_http_only_when_browser_unavailable(monkeypatch):
    """With browser_available False the detector must not throw and must skip the sweep."""
    detector = XSSDetector()

    async def _empty():
        return []

    monkeypatch.setattr(XSSDetector, "_browser_dom_reflection_sweep", lambda self, *a, **k: _empty())

    # No candidates -> returns early anyway; assert it does not raise.
    findings = asyncio.run(detector.detect([], [], browser_available=False))
    assert isinstance(findings, list)
