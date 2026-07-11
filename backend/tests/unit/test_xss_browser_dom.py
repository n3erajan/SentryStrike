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


def test_select_dom_reflection_jobs_mines_hash_route_query_params():
    """A hash route with a fragment query (/#/search?q=x) is dropped from the HTTP
    attack surface, so its param must still become a DOM job from the route list."""
    detector = XSSDetector()
    from types import SimpleNamespace

    routes = [
        SimpleNamespace(url="http://x/#/search?q=seed"),        # fragment query
        SimpleNamespace(url="http://x/results?keyword=abc"),     # ordinary query
        SimpleNamespace(url="http://x/#/about"),                 # no params
    ]
    jobs = detector._select_dom_reflection_jobs([], [], max_jobs=10, routes=routes)
    params = {param for _, param, _ in jobs}
    assert "q" in params            # from the hash fragment query
    assert "keyword" in params      # from the ordinary query
    # Both are emitted as "probe both surfaces" jobs.
    assert all(location == "both" for _, _, location in jobs)
    # The reflective 'keyword'/'q' names sort ahead of nothing here; route with
    # no params contributes no job.
    assert ("http://x/#/about", "", "both") not in jobs


def test_select_dom_reflection_jobs_dedupes_route_and_target_params():
    detector = XSSDetector()
    from types import SimpleNamespace

    targets = [_qtarget("http://x/search", "q")]
    routes = [SimpleNamespace(url="http://x/search?q=seed")]
    jobs = detector._select_dom_reflection_jobs(targets, [], max_jobs=10, routes=routes)
    # The (url, param) pair appears once despite being in both sources.
    assert jobs.count(("http://x/search", "q", "both")) == 1


def test_route_query_params_reads_search_and_fragment_query():
    detector = XSSDetector()
    assert detector._route_query_params("http://x/#/search?q=1&lang=en") == ["q", "lang"]
    assert detector._route_query_params("http://x/p?a=1&b=2") == ["a", "b"]
    assert detector._route_query_params("http://x/#/about") == []


def test_reflection_surface_probes_covers_query_hash_and_fragment():
    verifier = XSSVerifier()
    payload = "<img src=x onerror=1>"
    surfaces = verifier._reflection_surface_probes("http://x/#/search", "q", payload)
    names = [name for name, _ in surfaces]
    # All three generic surfaces are produced for a hash-router route.
    assert "query" in names
    assert "hash_query" in names
    assert "fragment" in names

    def before_hash(u: str) -> str:
        return u.split("#", 1)[0]

    def after_hash(u: str) -> str:
        return u.split("#", 1)[1] if "#" in u else ""

    urls = {name: url for name, url in surfaces}
    # Query surface delivers q in location.search (before the hash).
    assert "q=" in before_hash(urls["query"])
    # Hash-route query and raw fragment deliver q after the hash.
    assert "q=" in after_hash(urls["hash_query"])
    assert "q=" in after_hash(urls["fragment"])


def test_reflection_surface_probes_for_plain_path_route():
    verifier = XSSVerifier()
    surfaces = verifier._reflection_surface_probes("http://x/p", "q", "PAY")
    names = [name for name, _ in surfaces]
    assert "query" in names and "fragment" in names
    # The query surface carries no fragment; the fragment surface does.
    urls = {name: url for name, url in surfaces}
    assert "#" not in urls["query"]
    assert "#" in urls["fragment"]


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
        if parameter == "q":
            return {"fired": True, "vector": "svg_onload", "surface": "hash_query",
                    "payload": "<svg onload=window.sentry_hook('c')>"}
        return {"fired": False}

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
    # The winning vector/surface is threaded through to the finding.
    assert finding.detection_evidence.get("winning_vector") == "svg_onload"
    assert finding.detection_evidence.get("winning_surface") == "hash_query"


# --- Task D: multi-vector / multi-surface loop -----------------------------------------


def test_dom_xss_vectors_are_ordered_and_hook_bound():
    verifier = XSSVerifier()
    vectors = verifier._dom_xss_vectors("CANARY")
    names = [n for n, _ in vectors]
    # A small, ordered, generic set (cheap -> specific); every vector executes
    # the hooked canary and no app-specific payload appears.
    assert names[0] == "img_onerror"
    assert "svg_onload" in names and "iframe_js" in names and "script" in names
    for _, payload in vectors:
        assert "window.sentry_hook('CANARY')" in payload


def test_sweep_vectors_stops_on_first_fire(monkeypatch):
    """The vector/surface loop stops at the first firing probe and records it,
    without probing every remaining vector/surface combination."""
    verifier = XSSVerifier()
    probed: list[str] = []

    async def fake_probe(self, context, probe_url, canary):
        probed.append(probe_url)
        # Fire only on the second probe (first vector, second surface).
        return {"fired": len(probed) == 2, "csp": False}

    monkeypatch.setattr(XSSVerifier, "_probe_reflection_url", fake_probe)

    result = asyncio.run(
        verifier._sweep_vectors_and_surfaces(object(), "http://x/#/search", "q", "canary")
    )
    assert result["fired"] is True
    # Stopped immediately after the firing probe.
    assert len(probed) == 2


def test_sweep_vectors_respects_attempt_cap(monkeypatch):
    verifier = XSSVerifier()
    monkeypatch.setattr(XSSVerifier, "_DOM_MAX_ATTEMPTS_PER_CANDIDATE", 3)
    probed: list[str] = []

    async def fake_probe(self, context, probe_url, canary):
        probed.append(probe_url)
        return {"fired": False, "csp": True}

    monkeypatch.setattr(XSSVerifier, "_probe_reflection_url", fake_probe)

    result = asyncio.run(
        verifier._sweep_vectors_and_surfaces(object(), "http://x/#/search", "q", "canary")
    )
    assert result["fired"] is False
    # Never exceeds the per-candidate cap, and CSP is noted on the negative.
    assert len(probed) <= 3
    assert result.get("csp") is True


def test_detect_runs_http_only_when_browser_unavailable(monkeypatch):
    """With browser_available False the detector must not throw and must skip the sweep."""
    detector = XSSDetector()

    async def _empty():
        return []

    monkeypatch.setattr(XSSDetector, "_browser_dom_reflection_sweep", lambda self, *a, **k: _empty())

    # No candidates -> returns early anyway; assert it does not raise.
    findings = asyncio.run(detector.detect([], [], browser_available=False))
    assert isinstance(findings, list)
