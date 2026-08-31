"""DOM-XSS evidence capture.

When the browser oracle confirms a DOM-XSS execution, the rendered DOM at that
moment is captured and threaded into the finding's detection_evidence, so the
adjudicator has the post-execution page content to judge on (the model is
text-only; the DOM excerpt, not a screenshot, is what it can read).
"""
from __future__ import annotations

import asyncio

from app.core.crawler.models import ParameterLocation
from app.core.detectors.attack_surface import AttackTarget
from app.core.detectors.xss_detector import XSSDetector
from app.core.verification.xss_verifier import XSSVerifier


class TestDomExcerpt:
    """_dom_excerpt: a bounded slice of rendered DOM, windowed on the canary."""

    def test_windows_around_the_canary(self):
        html = "A" * 500 + "CANARY_TOKEN" + "B" * 500
        excerpt = XSSVerifier._dom_excerpt(html, "CANARY_TOKEN", cap=100)
        assert "CANARY_TOKEN" in excerpt
        assert len(excerpt) <= 100

    def test_falls_back_to_head_when_canary_absent(self):
        html = "<html><head>x</head><body>" + "y" * 5000 + "</body></html>"
        excerpt = XSSVerifier._dom_excerpt(html, "missing_canary", cap=200)
        assert excerpt == html[:200]

    def test_empty_html_returns_empty(self):
        assert XSSVerifier._dom_excerpt("", "canary", cap=200) == ""

    def test_short_html_returned_whole(self):
        html = "<div>onerror=window.sentry_hook('c1')</div>"
        assert XSSVerifier._dom_excerpt(html, "c1", cap=2000) == html


class TestCaptureExecutedDom:
    def test_captures_outerhtml_and_excerpts_it(self):
        captured: dict = {}

        class _FakePage:
            async def evaluate(self, script, *args):
                captured["script"] = script
                return "<div><img src=x onerror=window.sentry_hook('c9')></div>"

        excerpt = asyncio.run(XSSVerifier()._capture_executed_dom(_FakePage(), "c9"))
        assert "outerHTML" in captured["script"]
        assert "sentry_hook('c9')" in excerpt

    def test_returns_empty_when_evaluate_fails(self):
        class _BadPage:
            async def evaluate(self, *args):
                raise RuntimeError("page closed")

        assert asyncio.run(XSSVerifier()._capture_executed_dom(_BadPage(), "c9")) == ""


def test_sweep_propagates_executed_dom_from_firing_probe(monkeypatch):
    """A firing probe's captured DOM rides up into the sweep result under
    executed_dom_excerpt so the detector can attach it to the finding."""
    verifier = XSSVerifier()

    async def fake_probe(self, context, probe_url, canary):
        return {"fired": True, "csp": False, "dom": "<img onerror=window.sentry_hook('c1')>"}

    monkeypatch.setattr(XSSVerifier, "_probe_reflection_url", fake_probe)
    result = asyncio.run(
        verifier._sweep_vectors_and_surfaces(object(), "http://x/#/search", "q", "c1")
    )
    assert result["fired"] is True
    assert result["executed_dom_excerpt"] == "<img onerror=window.sentry_hook('c1')>"


def test_probe_reflection_url_captures_dom_on_fire():
    """_probe_reflection_url captures the rendered DOM while the page is still
    open when the canary fires."""
    verifier = XSSVerifier()
    dom_html = "<html><body><img src=x onerror=window.sentry_hook('c1')></body></html>"

    class _Resp:
        headers: dict = {}

    class _FakePage:
        def is_closed(self):
            return False

        async def add_init_script(self, script):
            pass

        def on(self, *args):
            pass

        async def goto(self, url, **kwargs):
            return _Resp()

        async def evaluate(self, script, *args):
            if "outerHTML" in script:
                return dom_html
            if "__sentry_xss_fired" in script:
                return True
            return None

        async def close(self):
            pass

    class _FakeContext:
        async def new_page(self):
            return _FakePage()

    result = asyncio.run(
        verifier._probe_reflection_url(_FakeContext(), "http://x/#/search?q=p", "c1")
    )
    assert result["fired"] is True
    assert "sentry_hook('c1')" in result["dom"]


def test_detector_attaches_executed_dom_excerpt_to_finding(monkeypatch):
    """End-to-end wiring: the DOM excerpt from the browser sweep lands in the
    DOM-XSS finding's detection_evidence."""
    from app.core.detectors import xss_detector as xd

    detector = XSSDetector()
    target = AttackTarget(
        url="http://x/#/search", parameter="q", method="GET",
        location=ParameterLocation.query,
    )
    excerpt = "<div><img src=x onerror=window.sentry_hook('c1')></div>"

    async def fake_verify_reflected_dom(self, route_url, param, location, *, canary=None, context=None):
        return {
            "fired": True,
            "vector": "img_onerror",
            "surface": "hash_query",
            "payload": f"<img src=x onerror=window.sentry_hook('{canary}')>",
            "url": route_url,
            "executed_dom_excerpt": excerpt,
        }

    async def fake_new_reflection_context(self, browser, route_url, storage_state=None):
        class _Ctx:
            async def close(self):
                pass

        return _Ctx()

    class _FakeBrowser:
        async def close(self):
            pass

    class _FakeChromium:
        async def launch(self, **kwargs):
            return _FakeBrowser()

    class _FakeP:
        chromium = _FakeChromium()

        async def stop(self):
            pass

    class _FakeStarter:
        async def start(self):
            return _FakeP()

    monkeypatch.setattr(xd, "async_playwright", lambda: _FakeStarter())
    monkeypatch.setattr(xd, "PLAYWRIGHT_AVAILABLE", True)
    monkeypatch.setattr(XSSVerifier, "verify_reflected_dom", fake_verify_reflected_dom)
    monkeypatch.setattr(XSSVerifier, "_new_reflection_context", fake_new_reflection_context)

    findings = asyncio.run(
        detector._browser_dom_reflection_sweep(
            targets=[target], routes=[], session_cookies={},
            browser_available=True, existing_findings=[],
        )
    )
    assert len(findings) == 1
    assert findings[0].detection_method == "dom_xss_browser_execution"
    assert findings[0].detection_evidence.get("executed_dom_excerpt") == excerpt


# --- stored/reflected XSS: browser confirmation upgrades to browser_execution ---


def test_location_proof_offset_returns_min_of_nested_locations():
    assert XSSVerifier._location_proof_offset({"locations": [[196099], [193708]]}) == 193708
    assert XSSVerifier._location_proof_offset({"locations": [3304]}) == 3304
    assert XSSVerifier._location_proof_offset({}) == -1


def test_verify_browser_execution_captures_display_dom(monkeypatch):
    """When the oracle fires, the rendered DOM (carrying the canary) is captured -
    previously it was discarded and the finding shipped the injection-phase
    response, which had no canary in it (the DVWA stored-XSS failure)."""
    from app.core.verification import xss_verifier as xv

    canary = "sentryprobe_abc"
    dom_html = f"<html><body><img src=x onerror=window.sentry_hook('{canary}')></body></html>"

    class _Page:
        _fired = False

        def is_closed(self):
            return False

        async def add_init_script(self, s):
            pass

        def on(self, *a):
            pass

        async def goto(self, *a, **k):
            class _R:
                headers: dict = {}
            return _R()

        async def wait_for_load_state(self, *a, **k):
            pass

        async def evaluate(self, script, *a):
            if "outerHTML" in script:
                return dom_html
            return True

        async def set_extra_http_headers(self, *a):
            pass

        async def close(self):
            pass

    class _Context:
        async def add_cookies(self, *a):
            pass

        async def new_page(self):
            return _Page()

        async def close(self):
            pass

    class _Browser:
        async def new_context(self, **k):
            return _Context()

        async def close(self):
            pass

    class _Chromium:
        async def launch(self, **k):
            return _Browser()

    class _Playwright:
        chromium = _Chromium()

    class _PlaywrightContext:
        async def __aenter__(self):
            return _Playwright()

        async def __aexit__(self, *a):
            return False

    monkeypatch.setattr(xv, "async_playwright", lambda: _PlaywrightContext())

    verifier = XSSVerifier()
    fired = asyncio.run(
        verifier._verify_browser_execution(
            "http://t/xss", "name", "GET",
            f"<img src=x onerror=window.sentry_hook('{canary}')>",
            canary, None, None, False,
        )
    )
    assert fired is True
    assert canary in (verifier._last_executed_dom or "")


def test_run_browser_verification_upgrades_to_browser_execution(monkeypatch):
    """A browser-confirmed reflection finding must be reclassified to
    dom_xss_browser_execution and carry the captured DOM, so the grader applies
    the execution frame instead of the reflection-skeptic pattern_match frame."""
    from app.core.detectors.base_detector import Finding
    from app.core.verification.xss_verifier import PendingBrowserVerification
    from shared.models.vulnerability import OwaspCategory, SeverityLevel

    verifier = XSSVerifier()
    partial = Finding(
        category=OwaspCategory.a05, vuln_type="Stored XSS", severity=SeverityLevel.high,
        url="http://t/page", parameter="comment", method="POST",
        payload="<img src=x onerror=window.sentry_hook('c1')>",
        evidence="HTTP static analysis confirmed reflection. Browser verification pending.",
        confidence_score=85.0, detection_method="reflection_attribute",
        detection_evidence={
            "context_type": "event_handler", "is_executable": True,
            "canary_verified": True, "locations": [196099],
        },
        verified=False,
    )
    job = PendingBrowserVerification(
        url="http://t/page", parameter="comment", method="POST",
        payload=partial.payload, canary="c1", form_inputs=None,
        stored_display_urls=["http://t/display"], is_header_injection=False,
        context_analysis=partial.detection_evidence, partial_finding=partial,
    )

    async def fake_verify(self, *a, **k):
        self._last_executed_dom = "<div><img src=x onerror=window.sentry_hook('c1')></div>"
        return True

    monkeypatch.setattr(XSSVerifier, "_verify_browser_execution", fake_verify)

    findings = asyncio.run(verifier.run_browser_verification(job))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.detection_method == "dom_xss_browser_execution"
    assert finding.detection_evidence.get("browser_execution_confirmed") is True
    assert "sentry_hook('c1')" in finding.detection_evidence.get("executed_dom_excerpt", "")
    assert finding.verified is True

