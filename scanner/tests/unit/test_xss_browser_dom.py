from __future__ import annotations

import asyncio

import pytest

from app.core.crawler.models import ParameterLocation
from app.core.detectors.attack_surface import AttackTarget
from app.core.detectors.xss_detector import XSSDetector
from app.core.verification.response_analyzer import ResponseData
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


def test_reflection_surface_probes_replaces_seeded_hash_param():
    """A route discovered WITH a seed value must not produce a duplicate param.

    Regression: ``/#/search?q=seed`` previously built ``/#/search?q=seed&q=<pay>``
    for the hash_query surface, and the SPA resolved the repeated ``q`` to the
    seed, so the injected payload never rendered (false negative). The hash_query
    surface must carry exactly one ``q`` whose value is the payload, and preserve
    the route path.
    """
    from urllib.parse import parse_qsl, urlsplit

    verifier = XSSVerifier()
    payload = "<img src=x onerror=1>"
    surfaces = dict(
        verifier._reflection_surface_probes("http://x/#/search?q=seed", "q", payload)
    )

    frag = urlsplit(surfaces["hash_query"]).fragment  # e.g. /search?q=<payload>
    assert frag.split("?", 1)[0] == "/search"  # route path preserved
    hash_q = dict(parse_qsl(frag.split("?", 1)[1], keep_blank_values=True))
    assert hash_q == {"q": payload}  # single q, replaced with the payload


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
                    "payload": "<svg onload=window.sentry_hook('c')>",
                    "url": "http://x/#/search?q=payload"}
        return {"fired": False}

    monkeypatch.setattr(XSSVerifier, "_new_reflection_context", fake_new_ctx)
    monkeypatch.setattr(XSSVerifier, "verify_reflected_dom", fake_verify)

    findings = asyncio.run(
        detector._browser_dom_reflection_sweep(
            targets,
            [],
            {"session": "abc"},
            browser_available=True,
            existing_findings=[],
        )
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
    # DOM-XSS is delivered via browser navigation (no httpx send_request). Keep
    # the full client-side URL for reproduction while separately showing the
    # fragment-free network request that fetched the SPA shell.
    assert finding.verification_request_snippet is not None
    assert finding.verification_request_snippet.startswith(
        "BROWSER NAVIGATION\n"
        "URL: http://x/#/search?q=payload\n\n"
        "NETWORK REQUEST\n"
        "GET / HTTP/1.1\nHost: x"
    )
    assert "User-Agent: SentryStrikeScanner/1.0" in finding.verification_request_snippet
    assert "Cookie: session=abc" in finding.verification_request_snippet
    assert "<svg onload=window.sentry_hook('c')>" not in finding.verification_request_snippet


def test_browser_execution_uses_target_cookie_context(monkeypatch):
    from app.core.verification import xss_verifier as xv

    observed: dict[str, object] = {}

    class _FakePage:
        _fired = True

        async def add_init_script(self, _script):
            pass

        def on(self, *_args):
            pass

        async def set_extra_http_headers(self, headers):
            observed["headers"] = headers

        async def goto(self, url, **_kwargs):
            observed["url"] = url

        async def evaluate(self, *_args):
            return True

    class _FakeContext:
        async def add_cookies(self, cookies):
            observed["cookies"] = cookies

        async def new_page(self):
            return _FakePage()

        async def close(self):
            pass

    class _FakeBrowser:
        async def new_context(self, **_kwargs):
            return _FakeContext()

        async def close(self):
            pass

    class _FakeChromium:
        async def launch(self, **_kwargs):
            return _FakeBrowser()

    class _FakePlaywright:
        chromium = _FakeChromium()

    class _FakePlaywrightContext:
        async def __aenter__(self):
            return _FakePlaywright()

        async def __aexit__(self, *_args):
            pass

    monkeypatch.setattr(xv, "async_playwright", lambda: _FakePlaywrightContext())

    verifier = XSSVerifier()
    verifier.http_verifier.cookies = {"security": "high", "session": "stale"}
    target = AttackTarget(
        url="http://target.test/app/search",
        parameter="q",
        method="GET",
        location=ParameterLocation.query,
        headers={"X-Observed": "yes", "Cookie": "security=high; session=stale"},
        cookies={"security": "low", "session": "fresh"},
    )

    fired = asyncio.run(
        verifier._verify_browser_execution(
            target.url,
            target.parameter,
            target.method,
            "<script>window.sentry_hook('canary')</script>",
            "canary",
            None,
            None,
            False,
            target=target,
        )
    )

    assert fired is True
    assert observed["cookies"] == [
        {"name": "security", "value": "low", "domain": "target.test", "path": "/"},
        {"name": "session", "value": "fresh", "domain": "target.test", "path": "/"},
    ]
    assert observed["headers"] == {"X-Observed": "yes"}


def test_browser_execution_materializes_prepared_get_params(monkeypatch):
    from app.core.verification import xss_verifier as xv

    observed: dict[str, object] = {}

    class _PreparedTarget(AttackTarget):
        def build_request(self, _payload, *, merge_with_baseline=False):
            from app.core.detectors.attack_surface import PreparedAttackRequest

            return PreparedAttackRequest(
                url="http://target.test/search?lang=en",
                method="GET",
                params={"q": "<script>window.sentry_hook('canary')</script>"},
            )

    class _Page:
        _fired = True

        async def add_init_script(self, _script):
            pass

        def on(self, *_args):
            pass

        async def goto(self, url, **_kwargs):
            observed["url"] = url

        async def evaluate(self, *_args):
            return True

    class _Context:
        async def new_page(self):
            return _Page()

        async def close(self):
            pass

    class _Browser:
        async def new_context(self, **_kwargs):
            return _Context()

        async def close(self):
            pass

    class _Chromium:
        async def launch(self, **_kwargs):
            return _Browser()

    class _Playwright:
        chromium = _Chromium()

    class _PlaywrightContext:
        async def __aenter__(self):
            return _Playwright()

        async def __aexit__(self, *_args):
            pass

    monkeypatch.setattr(xv, "async_playwright", lambda: _PlaywrightContext())
    target = _PreparedTarget(
        url="http://target.test/search",
        parameter="q",
        method="GET",
        location=ParameterLocation.query,
    )

    fired = asyncio.run(
        XSSVerifier()._verify_browser_execution(
            target.url,
            target.parameter,
            target.method,
            "payload",
            "canary",
            None,
            None,
            False,
            target=target,
        )
    )

    assert fired is True
    assert observed["url"] == (
        "http://target.test/search?lang=en&q=%3Cscript%3Ewindow.sentry_hook%28%27canary%27%29%3C%2Fscript%3E"
    )


def test_http_reflection_is_handed_to_browser_phase(monkeypatch):
    """Executable HTTP reflection must survive until the authenticated browser phase.

    The page template contains an unrelated HTML entity near the echo. That
    entity is not evidence that the injected payload was encoded; the exact
    reflected payload still needs a browser execution proof.
    """
    from app.core.verification import xss_verifier as xv

    verifier = XSSVerifier()
    sent_phases: list[str] = []

    async def fake_send(self, url, method="GET", params=None, data=None, **kwargs):
        phase = kwargs.get("test_phase", "")
        sent_phases.append(phase)
        payload = kwargs.get("payload") or ""
        if phase == "canary":
            body = f"<html><body>echo {payload} &amp; nearby</body></html>"
        elif phase.startswith("payload_"):
            body = f"<html><body>&amp; nearby {payload}</body></html>"
        else:
            body = "<html><body>clean &amp; nearby</body></html>"
        return ResponseData(
            status_code=200,
            headers={"Content-Type": "text/html"},
            body=body,
            response_time_ms=1.0,
            request_snippet="request",
            response_snippet=body,
        )

    async def fail_if_run(self, job):
        raise AssertionError("verify() must hand jobs to XSSDetector")

    monkeypatch.setattr(XSSVerifier, "_send", fake_send)
    monkeypatch.setattr(XSSVerifier, "run_browser_verification", fail_if_run)
    monkeypatch.setattr(xv, "PLAYWRIGHT_AVAILABLE", True)

    result = asyncio.run(
        verifier.verify(
            "http://target.test/xss",
            "name",
            method="GET",
            value="1",
            stored_display_overrides={},
        )
    )

    assert result.is_vulnerable is False
    assert result.evidence.get("browser_verification_pending") is True
    jobs = result.evidence.get("pending_jobs")
    assert jobs and jobs[0].parameter == "name"
    assert any(phase.startswith("payload_") for phase in sent_phases)


def test_detector_runs_handed_off_jobs_until_first_confirmation(monkeypatch):
    from types import SimpleNamespace

    from app.core.verification.verification_framework import VerificationResult

    detector = XSSDetector()
    target = _qtarget("http://target.test/xss", "name")
    partial = SimpleNamespace(vuln_type="Stored XSS")
    jobs = [
        SimpleNamespace(
            url=target.url,
            parameter=target.parameter,
            method=target.method,
            partial_finding=partial,
        ),
        SimpleNamespace(
            url=target.url,
            parameter=target.parameter,
            method=target.method,
            partial_finding=partial,
        ),
    ]
    confirmed = SimpleNamespace(vuln_type="Stored XSS", parameter="name")
    browser_calls: list[object] = []

    class _Planner:
        def targets_for(self, _name):
            return [target]

    async def no_static_findings(self, _kwargs, _cookies):
        return []

    async def no_baselines(self, _urls, _cookies):
        return {}

    async def fake_verify(self, *_args, **_kwargs):
        return VerificationResult(
            is_vulnerable=False,
            confidence_score=0.0,
            detection_method="browser_verification_pending",
            findings=[],
            evidence={
                "browser_verification_pending": True,
                "pending_job": jobs[0],
                "pending_jobs": jobs,
            },
        )

    async def fake_run_browser(self, job):
        browser_calls.append(job)
        return [confirmed]

    async def no_dom_sweep(self, *_args, **_kwargs):
        return []

    monkeypatch.setattr(XSSDetector, "_static_dom_findings_with_browser_confirmation", no_static_findings)
    monkeypatch.setattr(XSSDetector, "_prefetch_stored_baselines", no_baselines)
    monkeypatch.setattr(XSSDetector, "_build_header_candidates", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(XSSDetector, "_browser_dom_reflection_sweep", no_dom_sweep)
    monkeypatch.setattr(XSSVerifier, "verify", fake_verify)
    monkeypatch.setattr(XSSVerifier, "run_browser_verification", fake_run_browser)

    findings = asyncio.run(
        detector.detect(
            [target.url],
            [],
            attack_planner=_Planner(),
            session_cookies={"session": "authenticated"},
            browser_available=True,
        )
    )

    assert findings == [confirmed]
    assert browser_calls == [jobs[0]]


def test_browser_execution_keeps_hook_after_navigation_timeout(monkeypatch):
    from app.core.verification import xss_verifier as xv

    class _Page:
        _fired = False

        async def add_init_script(self, _script):
            pass

        def on(self, *_args):
            pass

        async def goto(self, _url, **_kwargs):
            self._fired = True
            raise RuntimeError("navigation timeout after response")

        async def evaluate(self, *_args):
            return self._fired

    class _Context:
        async def add_cookies(self, _cookies):
            pass

        async def new_page(self):
            return _Page()

        async def close(self):
            pass

    class _Browser:
        async def new_context(self, **_kwargs):
            return _Context()

        async def close(self):
            pass

    class _Chromium:
        async def launch(self, **_kwargs):
            return _Browser()

    class _Playwright:
        chromium = _Chromium()

    class _PlaywrightContext:
        async def __aenter__(self):
            return _Playwright()

        async def __aexit__(self, *_args):
            pass

    monkeypatch.setattr(xv, "async_playwright", lambda: _PlaywrightContext())

    verifier = XSSVerifier()
    fired = asyncio.run(
        verifier._verify_browser_execution(
            "http://target.test/xss",
            "name",
            "GET",
            "<script>window.sentry_hook('canary')</script>",
            "canary",
            None,
            None,
            False,
        )
    )

    assert fired is True


# --- multi-vector / multi-surface loop -----------------------------------------


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
    assert result["url"] == probed[-1]
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


# --- API↔SPA route cross-referencing ------------------------------------------


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


# --- Browser-aware stored oracle ---------------------------------------------


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

