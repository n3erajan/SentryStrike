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


# --- Phase 5: API↔SPA route cross-referencing ------------------------------------------


def test_select_dom_reflection_jobs_projects_api_param_onto_spa_route():
    """An API-observed ``q`` (on ``/rest/products/search``) must yield a DOM-sweep
    job against the SPA route sharing the ``search`` segment, not just the raw
    API URL. Navigating the API URL would return raw JSON where the canary never
    executes; the SPA route is where the DOM renders it."""
    detector = XSSDetector()
    from types import SimpleNamespace

    targets = [_qtarget("http://x/rest/products/search", "q")]
    routes = [SimpleNamespace(url="http://x/#/search")]
    jobs = detector._select_dom_reflection_jobs(targets, [], max_jobs=10, routes=routes)
    spa_urls = {url for url, _, _ in jobs}
    assert "http://x/#/search" in spa_urls
    # The job against the SPA route carries the ``q`` param.
    assert ("http://x/#/search", "q", "both") in jobs


def test_select_dom_reflection_jobs_projects_route_api_param_onto_spa():
    """When an API-style route appears in the routes list (e.g. discovered by the
    crawler but not built into the attack surface), its ``q`` param is still
    projected onto the SPA counterpart via segment matching."""
    detector = XSSDetector()
    from types import SimpleNamespace

    routes = [
        SimpleNamespace(url="http://x/rest/products/search?q=seed"),
        SimpleNamespace(url="http://x/#/search"),
    ]
    jobs = detector._select_dom_reflection_jobs([], [], max_jobs=10, routes=routes)
    assert ("http://x/#/search", "q", "both") in jobs


def test_select_dom_reflection_jobs_no_projection_without_shared_segment():
    """No projection when no SPA route shares a segment with the API URL.
    A non-matching SPA route must not receive a fabricated param job."""
    detector = XSSDetector()
    from types import SimpleNamespace

    targets = [_qtarget("http://x/rest/products/search", "q")]
    routes = [SimpleNamespace(url="http://x/#/profile")]
    jobs = detector._select_dom_reflection_jobs(targets, [], max_jobs=10, routes=routes)
    # No SPA route shares "search" — the only ``q`` job is against the API URL.
    spa_urls = {url for url, param, _ in jobs if param == "q"}
    assert "http://x/#/profile" not in spa_urls


def test_select_dom_reflection_jobs_segment_match_is_not_substring():
    """Segment matching is on full path segments, not substrings — ``/search``
    must not match ``/#/research`` (different segment) to avoid false
    projections."""
    detector = XSSDetector()
    from types import SimpleNamespace

    targets = [_qtarget("http://x/rest/products/search", "q")]
    routes = [SimpleNamespace(url="http://x/#/research")]
    jobs = detector._select_dom_reflection_jobs(targets, [], max_jobs=10, routes=routes)
    assert ("http://x/#/research", "q", "both") not in jobs


def test_select_dom_reflection_jobs_path_router_api_needs_no_projection():
    """A path-router SPA and a path API share the same server path; the target
    sweep already navigates the rendered page, so no projection is needed. Only
    hash-router SPA routes participate in segment projection."""
    detector = XSSDetector()
    from types import SimpleNamespace

    # Path-router route (no fragment) — not an SPA hash route, must not seed
    # the segment index, so no projection occurs.
    targets = [_qtarget("http://x/search", "q")]
    routes = [SimpleNamespace(url="http://x/search")]
    jobs = detector._select_dom_reflection_jobs(targets, [], max_jobs=10, routes=routes)
    # Only one job, against the original URL (no projection duplicate).
    q_jobs = [j for j in jobs if j[1] == "q"]
    assert len(q_jobs) == 1
    assert q_jobs[0][0] == "http://x/search"


# --- Phase 5: browser-aware stored oracle ---------------------------------------------


def _stub_playwright(monkeypatch, *, fired: bool):
    """Stub the Playwright plumbing so _browser_stored_execution_probe runs
    without a real browser. ``fired`` controls whether the canary hooks
    report execution."""
    from app.core.verification import xss_verifier as xv

    class _FakePage:
        def __init__(self):
            self._fired = fired

        def is_closed(self):
            return False

        async def add_init_script(self, script):
            pass

        async def goto(self, *a, **k):
            pass

        async def wait_for_load_state(self, *a, **k):
            pass

        async def evaluate(self, *a, **k):
            return fired

        async def close(self):
            pass

    class _FakeContext:
        async def new_page(self):
            return _FakePage()

        async def close(self):
            pass

    class _FakeBrowser:
        async def launch(self, **kwargs):
            return self

        async def new_context(self, **kwargs):
            return _FakeContext()

        async def close(self):
            pass

    class _FakeP:
        chromium = _FakeBrowser()

        async def start(self):
            return _FakeP()

    class _FakePlaywrightCM:
        async def __aenter__(self):
            return _FakeP()

        async def __aexit__(self, *a):
            return False

    monkeypatch.setattr(xv, "async_playwright", lambda: _FakePlaywrightCM())
    monkeypatch.setattr(xv, "PLAYWRIGHT_AVAILABLE", True)


def test_probe_stored_falls_back_to_browser_on_spa_when_http_negative(monkeypatch):
    """On an SPA target where the HTTP-body stored oracle is negative, the
    browser-aware oracle must confirm canary EXECUTION and return a positive.
    This is the core recovery path for client-rendered stored XSS."""
    verifier = XSSVerifier()
    verifier.spa_mode = True
    canary = "sentry_abc123"

    # HTTP _send returns a body with no canary — clean HTTP negative.
    async def fake_send(self, url, method, params=None, data=None, **kwargs):
        from app.core.verification.response_analyzer import ResponseData
        return ResponseData(
            status_code=200, headers={}, body="{}",
            response_time_ms=0.0,
        )

    monkeypatch.setattr(XSSVerifier, "_send", fake_send)
    _stub_playwright(monkeypatch, fired=True)

    # _browser_xss_fired is called by the probe; stub it to report execution.
    async def fake_fired(self, page):
        return True

    monkeypatch.setattr(XSSVerifier, "_browser_xss_fired", fake_fired)

    result = asyncio.run(
        verifier._probe_stored(
            payload=f"<img src=x onerror=window.sentry_hook('{canary}')>",
            origin_url="http://x/rest/products/1",
            stored_display_urls=["http://x/#/search"],
            canary=canary,
        )
    )
    is_stored, _locs, _enc, _resp, evidence = result
    assert is_stored is True
    assert evidence.get("browser_execution_confirmed") is True
    assert evidence.get("verification_canary") == canary


def test_probe_stored_browser_oracle_negative_when_not_fired(monkeypatch):
    """When neither HTTP-body nor browser execution confirms the canary, the
    stored oracle returns a clean negative — no fabricated finding."""
    verifier = XSSVerifier()
    verifier.spa_mode = True
    canary = "sentry_abc123"

    async def fake_send(self, url, method, params=None, data=None, **kwargs):
        from app.core.verification.response_analyzer import ResponseData
        return ResponseData(
            status_code=200, headers={}, body="{}",
            response_time_ms=0.0,
        )

    monkeypatch.setattr(XSSVerifier, "_send", fake_send)
    _stub_playwright(monkeypatch, fired=False)

    async def fake_fired(self, page):
        return False

    monkeypatch.setattr(XSSVerifier, "_browser_xss_fired", fake_fired)

    result = asyncio.run(
        verifier._probe_stored(
            payload=f"<img src=x onerror=window.sentry_hook('{canary}')>",
            origin_url="http://x/rest/products/1",
            stored_display_urls=["http://x/#/search"],
            canary=canary,
        )
    )
    is_stored, _, _, resp, _ = result
    assert is_stored is False
    assert resp is None


def test_probe_stored_browser_oracle_skipped_when_not_spa(monkeypatch):
    """The browser-aware oracle must NOT run on non-SPA targets — the HTTP-body
    oracle is authoritative there. Confirms the SPA gate prevents scope creep."""
    verifier = XSSVerifier()
    verifier.spa_mode = False
    canary = "sentry_abc123"

    async def fake_send(self, url, method, params=None, data=None, **kwargs):
        from app.core.verification.response_analyzer import ResponseData
        return ResponseData(
            status_code=200, headers={}, body="{}",
            response_time_ms=0.0,
        )

    monkeypatch.setattr(XSSVerifier, "_send", fake_send)

    # If the browser path runs at all, this would be invoked; assert it isn't.
    async def fail_new_context(self, *a, **k):
        raise AssertionError("browser oracle must not run on non-SPA targets")

    monkeypatch.setattr(XSSVerifier, "_new_reflection_context", fail_new_context)

    result = asyncio.run(
        verifier._probe_stored(
            payload=f"<img src=x onerror=window.sentry_hook('{canary}')>",
            origin_url="http://x/page",
            stored_display_urls=["http://x/page"],
            canary=canary,
        )
    )
    assert result[0] is False


def test_probe_stored_browser_oracle_skipped_without_canary(monkeypatch):
    """No canary → no browser oracle (nothing to confirm execution of).
    Guards against running an unbounded browser fan-out with no signal."""
    verifier = XSSVerifier()
    verifier.spa_mode = True

    async def fake_send(self, url, method, params=None, data=None, **kwargs):
        from app.core.verification.response_analyzer import ResponseData
        return ResponseData(
            status_code=200, headers={}, body="{}",
            response_time_ms=0.0,
        )

    monkeypatch.setattr(XSSVerifier, "_send", fake_send)

    async def fail_new_context(self, *a, **k):
        raise AssertionError("browser oracle must not run without a canary")

    monkeypatch.setattr(XSSVerifier, "_new_reflection_context", fail_new_context)

    result = asyncio.run(
        verifier._probe_stored(
            payload="<img src=x onerror=alert(1)>",
            origin_url="http://x/page",
            stored_display_urls=["http://x/page"],
            canary=None,
        )
    )
    assert result[0] is False

