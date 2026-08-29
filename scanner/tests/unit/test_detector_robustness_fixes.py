"""Regression tests for the 2026-08-29 assessment against the lab target.

Each test pins a miss or a duplication observed on a real scan:

1. Stored XSS on a POST form parameter observed on the wire was discarded -
   the deferred browser verification got ``form_inputs=None`` and returned
   False instantly, without even sweeping the stored-display URLs.
2. A horizontal IDOR between two real accounts was missed because the
   second-user gate asked "is the content sensitive" (JSON-only extraction)
   instead of "did the second identity receive the owner's object".
3. One Apache install produced two "Vulnerable Component" findings because
   two detection sources spelled the product name differently and the merge
   keyed on exact lowercase names.
4. A full-response SSRF was labeled "Blind" because the OAST confirmation
   path never checked whether the fetched content was rendered back, and the
   in-band signature check was disabled whenever the enclosing page matched
   the signature itself.
5. A classic server-rendered PHP app was routed with pushState (SPA-style),
   so the stale DOM's form was captured under every phantom URL - a false
   CSRF finding and hundreds of wasted requests.

All fixes are target-agnostic: no product names, paths or field names of the
assessed application appear in the detector logic.
"""

from __future__ import annotations

import pytest

from app.core.crawler.browser_engine import BrowserDiscoveryEngine
from app.core.crawler.models import (
    ApiEndpoint,
    CrawlState,
    ParameterCandidate,
    ParameterLocation,
)
from app.core.detectors.access_control import AccessControlDetector
from app.core.detectors.attack_surface import AttackSurface
from app.core.detectors.supply_chain import SupplyChainDetector
from app.core.detectors.xss_detector import XSSDetector
from app.core.verification.response_analyzer import ResponseData
from app.core.verification.verification_framework import HttpVerifier
from app.core.verification.xss_verifier import XSSVerifier
from shared.models.vulnerability import SeverityLevel, TechnologyComponent
from shared.verification.oast import OAST_CALLBACK_BODY, OastClient


def _resp(status: int, body: str, content_type: str = "text/html") -> ResponseData:
    return ResponseData(
        status,
        {"content-type": content_type},
        body,
        1.0,
        request_snippet="POST /x",
        response_snippet=f"HTTP/1.1 {status}",
    )


# ---------------------------------------------------------------------------
# 1. XSS: browser verification survives form_inputs=None
# ---------------------------------------------------------------------------


def test_resolve_form_values_accepts_dataclass_and_dict_inputs():
    """Template recovery yields _ObservedFormInput dataclasses; cluster capture
    yields dicts. The old comprehension filtered on hasattr(item, "get") and
    silently dropped every dataclass, so a recovered template still produced
    an empty fill map."""
    from app.core.detectors.attack_surface import _ObservedFormInput

    resolved = XSSVerifier._resolve_form_values(
        [
            {"name": "message", "value": "hi", "type": "textarea"},
            _ObservedFormInput(name="url", value="http://x"),
            {"id": "q", "value": "search"},
            "garbage",
        ]
    )
    assert resolved == {"message": "hi", "url": "http://x", "q": "search"}


@pytest.mark.asyncio
async def test_browser_verification_fills_parameter_field_without_template(monkeypatch):
    """A POST prepared request with no form template must address the field by
    parameter name and submit, not bail out before the stored sweep."""
    from types import SimpleNamespace

    from app.core.crawler.models import ParameterLocation as PL
    from app.core.detectors.attack_surface import AttackTarget

    verifier = XSSVerifier()
    verifier.http_verifier.cookies = {"session": "abc"}

    filled: list[tuple[str, str]] = []

    class _FakePage:
        url = "http://t.test/feedback"
        _fired = False

        async def add_init_script(self, _script):
            pass

        def on(self, *_a):
            pass

        async def set_extra_http_headers(self, _headers):
            pass

        async def goto(self, _url, **_kwargs):
            pass

        async def evaluate(self, *_a):
            return False

        async def wait_for_load_state(self, *_a, **_kw):
            pass

        async def query_selector(self, _sel):
            return object()

        async def fill(self, sel, value):
            filled.append((sel, value))

        async def click(self, *_a):
            pass

        async def content(self):
            return ""

    class _FakeContext:
        async def add_cookies(self, _cookies):
            pass

        async def new_page(self):
            return _FakePage()

        async def close(self):
            pass

        async def route(self, *_a):
            pass

    class _FakeBrowser:
        async def new_context(self, **_kw):
            return _FakeContext()

        async def close(self):
            pass

    class _FakeChromium:
        async def launch(self, **_kw):
            return _FakeBrowser()

    class _FakePlaywright:
        chromium = _FakeChromium()

    class _FakeCM:
        async def __aenter__(self):
            return _FakePlaywright()

        async def __aexit__(self, *_exc):
            return False

        async def start(self):
            return _FakePlaywright()

        async def stop(self):
            pass

    monkeypatch.setattr(
        "app.core.verification.xss_verifier.async_playwright", lambda: _FakeCM()
    )

    target = AttackTarget(
        url="http://t.test/feedback",
        parameter="message",
        method="POST",
        value="",
        location=PL.form,
        form_inputs=None,
    )
    fired = await verifier._verify_browser_execution(
        "http://t.test/feedback",
        "message",
        "POST",
        "<script>window.sentry_hook('canary1')</script>",
        "canary1",
        None,  # no form template travelled with the candidate
        ["http://t.test/feedback"],
        False,
        target=target,
    )
    assert fired is False  # the fake oracle never fires
    # but the parameter field WAS addressed and the flow completed (no early
    # return): the payload reached the form submission path.
    assert any("message" in sel and "canary1" in value for sel, value in filled)


def test_endpoint_form_templates_recovers_urlencoded_bodies():
    """A browser-observed urlencoded POST is the raw wire string; JSON-only
    template recovery left the form-location candidate with no form_inputs."""
    endpoint = ApiEndpoint(
        url="http://t.test/feedback",
        method="POST",
        content_type="application/x-www-form-urlencoded",
        request_body="message=hello+world",
    )
    parameter = ParameterCandidate(
        name="message",
        location=ParameterLocation.form,
        url="http://t.test/feedback",
        method="POST",
        baseline_value="hello world",
        source="browser_request",
        context={"replayable": True},
    )

    targets = AttackSurface.build(
        [],
        [],
        parameters=[parameter],
        api_endpoints=[endpoint],
    )

    message_targets = [t for t in targets if t.parameter == "message"]
    assert len(message_targets) == 1
    assert message_targets[0].form_inputs, "urlencoded body must recover form inputs"


def test_add_parameter_merges_form_inputs_instead_of_shadowing():
    """First-wins dedup dropped the form-derived candidate's form_inputs when
    the wire-observed (browser_request) candidate landed first."""
    state = CrawlState()
    observed = ParameterCandidate(
        name="message",
        location=ParameterLocation.form,
        url="http://t.test/feedback",
        method="POST",
        baseline_value="observed",
        source="browser_request",
        context={"replayable": True},
    )
    from_form = ParameterCandidate(
        name="message",
        location=ParameterLocation.form,
        url="http://t.test/feedback",
        method="POST",
        baseline_value="",
        source="form",
        context={"form_inputs": [{"name": "message", "value": ""}]},
    )
    state.add_parameter(observed)
    state.add_parameter(from_form)

    assert len(state.parameters) == 1
    assert state.parameters[0].context.get("form_inputs") == [
        {"name": "message", "value": ""}
    ]


# ---------------------------------------------------------------------------
# 2. IDOR: object identity, not content sensitivity
# ---------------------------------------------------------------------------


_OWNER_HTML = (
    "<html><body><nav>@owner</nav><h2>Researcher Profile</h2>"
    "<div>Employee ID: SID10294</div>"
    "<div>Payroll Information: confidential record</div>"
    "</body></html>"
)


@pytest.mark.asyncio
async def test_second_user_idor_on_html_bodies_is_flagged(monkeypatch):
    """Two accounts see byte-identical HTML for the owner's object reference
    while anonymous access is denied. The JSON-only sensitivity gate saw
    nothing; the object-reference echo is the proof."""
    detector = AccessControlDetector()

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        phase = kwargs.get("test_phase")
        if phase == "idor_unauth_own":
            return _resp(302, "<html><body>redirect to login</body></html>")
        if phase == "idor_authed_own":
            return _resp(200, _OWNER_HTML)
        if phase == "idor_second_user_own":
            return _resp(200, _OWNER_HTML)
        return _resp(403, "<html><body>forbidden</body></html>")

    monkeypatch.setattr(HttpVerifier, "send_request", send_request)
    findings = await detector.detect(
        urls=["http://t.test/profile.php?id=SID10294"],
        forms=[],
        session_cookies={"session": "user-a"},
        second_user_cookies={"session": "user-b"},
        root_url="http://t.test/",
    )

    idor = [f for f in findings if "IDOR" in f.vuln_type]
    assert idor, "expected a cross-identity IDOR finding on HTML bodies"
    assert idor[0].detection_method == "second_user_idor"
    assert idor[0].detection_evidence["shared_object_reference"] is True
    assert "SID10294" in idor[0].evidence


@pytest.mark.asyncio
async def test_second_user_idor_html_without_shared_reference_is_not_flagged(monkeypatch):
    """Near-identical HTML alone (a shared template) must not fire: the object
    reference echo is the discriminating evidence."""
    other_page = _OWNER_HTML.replace("SID10294", "SID00000")
    detector = AccessControlDetector()

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        phase = kwargs.get("test_phase")
        if phase == "idor_unauth_own":
            return _resp(302, "<html>login</html>")
        if phase == "idor_authed_own":
            return _resp(200, _OWNER_HTML)
        if phase == "idor_second_user_own":
            return _resp(200, other_page)
        return _resp(403, "<html>forbidden</html>")

    monkeypatch.setattr(HttpVerifier, "send_request", send_request)
    findings = await detector.detect(
        urls=["http://t.test/profile.php?id=SID10294"],
        forms=[],
        session_cookies={"session": "user-a"},
        second_user_cookies={"session": "user-b"},
        root_url="http://t.test/",
    )

    assert [f for f in findings if "IDOR" in f.vuln_type] == []


def test_id_shape_matches_siblings_only():
    from app.core.detectors.access_control.targeting import TargetingMixin
    import re

    shape = TargetingMixin._id_shape("SID10294")
    assert re.fullmatch(shape, "SID10290")
    assert re.fullmatch(shape, "SID10582")
    assert not re.fullmatch(shape, "EMP001")
    assert not re.fullmatch(shape, "2026")
    # UUIDs collapse to the generic pattern - every segment varies.
    uuid_shape = TargetingMixin._id_shape(
        "550e8400-e29b-41d4-a716-446655440000"
    )
    assert re.fullmatch(uuid_shape, "12345678-1234-1234-1234-123456789012")


def test_collect_text_ids_harvests_directory_siblings():
    from app.core.detectors.access_control.targeting import TargetingMixin

    class _Mixin(TargetingMixin):
        pass

    ids = {"*": set()}
    _Mixin()._collect_text_ids(
        '<a href="profile.php?id=SID10290">Alice</a>'
        '<a href="profile.php?id=SID10293">Bob</a>'
        "<span>updated 2026, ref 000</span>",
        ids,
    )
    pool = ids["*"]
    assert "SID10290" in pool
    assert "SID10293" in pool


# ---------------------------------------------------------------------------
# 3. Supply chain: canonical component identity
# ---------------------------------------------------------------------------


async def _detect_supply_chain(*components: TechnologyComponent):
    return await SupplyChainDetector().detect(
        ["https://t.test"], [], technologies=list(components), root_url="https://t.test"
    )


def _assessed(**kwargs) -> TechnologyComponent:
    kwargs.setdefault("cve_assessment", "assessed")
    kwargs.setdefault("cve_source", "nvd-cpe")
    return TechnologyComponent(**kwargs)


@pytest.mark.asyncio
async def test_alias_spelled_components_deduplicate_to_one_finding_per_cve():
    findings = await _detect_supply_chain(
        _assessed(
            name="Apache",
            version="2.4.58",
            category="server",
            cves=["CVE-2023-43622", "CVE-2023-38709"],
            cve_scores={"CVE-2023-43622": 7.5, "CVE-2023-38709": 7.3},
        ),
        _assessed(
            name="Apache HTTP Server",
            version="2.4.58",
            category="server",
            cves=["CVE-2023-43622", "CVE-2023-38709"],
            cve_scores={"CVE-2023-43622": 7.5, "CVE-2023-38709": 7.3},
        ),
    )

    assert len(findings) == 2, "one finding per CVE, not per name spelling"
    assert {f.vuln_type for f in findings} == {
        "Vulnerable Component: Apache HTTP Server"
    }


def test_canonical_component_name_resolves_aliases():
    from app.integrations.wappalyzer_engine import canonical_component_name

    assert (
        canonical_component_name("Apache")
        == canonical_component_name("Apache HTTP Server")
        == canonical_component_name("httpd")
        == "apache http server"
    )
    assert canonical_component_name("WordPress") == "wordpress"
    assert canonical_component_name("") == ""


# ---------------------------------------------------------------------------
# 4. SSRF: blind vs full-response classification
# ---------------------------------------------------------------------------


class _FakeOast(OastClient):
    """OastClient subclass so the detector's isinstance guard keeps it."""

    def __init__(self, interactions: list) -> None:
        super().__init__("https://oast.test", None)
        self._interactions = interactions

    def new_callback_url(self, purpose: str = "ssrf") -> tuple[str, str]:
        return "https://oast.test/ssrf-fixed-id", "ssrf-fixed-id"

    async def poll(self, interaction_id: str):
        return self._interactions


@pytest.mark.asyncio
async def test_ssrf_oast_readback_is_classified_full_response(monkeypatch):
    """When the application renders the fetched collaborator content back in
    its response, the SSRF is NOT blind."""
    from types import SimpleNamespace

    from app.core.detectors.ssrf_detector import SSRFDetector

    parameter = ParameterCandidate(
        name="url",
        location=ParameterLocation.json_body,
        url="http://t.test/api_fetch",
        method="POST",
        baseline_value="http://example.test/x.png",
        parent_path="url",
    )

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        payload = kwargs.get("payload") or ""
        if "oast.test" in payload:
            return _resp(
                200,
                f"<html><body>preview: {OAST_CALLBACK_BODY}</body></html>",
            )
        return _resp(200, '{"ok":true}', "application/json")

    monkeypatch.setattr(HttpVerifier, "send_request", send_request)
    findings = await SSRFDetector().detect(
        urls=[],
        forms=[],
        parameters=[parameter],
        api_endpoints=[],
        oast_client=_FakeOast(
            [SimpleNamespace(interaction_id="ssrf-fixed-id", raw={"id": "ssrf-fixed-id"})]
        ),
    )

    ssrf = [f for f in findings if "SSRF" in f.vuln_type]
    assert ssrf
    assert ssrf[0].vuln_type == "Server-Side Request Forgery (SSRF)"
    assert ssrf[0].detection_method == "ssrf_oast_readback"
    assert ssrf[0].detection_evidence["response_readback"] is True


@pytest.mark.asyncio
async def test_ssrf_oast_without_readback_stays_blind(monkeypatch):
    from types import SimpleNamespace

    from app.core.detectors.ssrf_detector import SSRFDetector

    parameter = ParameterCandidate(
        name="url",
        location=ParameterLocation.json_body,
        url="http://t.test/api_fetch",
        method="POST",
        baseline_value="http://example.test/x.png",
        parent_path="url",
    )

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        return _resp(200, '{"ok":true}', "application/json")

    monkeypatch.setattr(HttpVerifier, "send_request", send_request)
    findings = await SSRFDetector().detect(
        urls=[],
        forms=[],
        parameters=[parameter],
        api_endpoints=[],
        oast_client=_FakeOast(
            [SimpleNamespace(interaction_id="ssrf-fixed-id", raw={"id": "ssrf-fixed-id"})]
        ),
    )

    ssrf = [f for f in findings if "SSRF" in f.vuln_type]
    assert ssrf
    assert ssrf[0].vuln_type == "Blind Server-Side Request Forgery (SSRF)"
    assert ssrf[0].detection_method == "ssrf_oast_callback"
    assert ssrf[0].detection_evidence["response_readback"] is False


@pytest.mark.asyncio
async def test_ssrf_inband_signature_uses_count_differential(monkeypatch):
    """The enclosing page contains the generic signature itself (doctype);
    only an INCREASE in occurrences proves fetched content was rendered."""
    from app.core.detectors.ssrf_detector import SSRFDetector

    parameter = ParameterCandidate(
        name="url",
        location=ParameterLocation.json_body,
        url="http://t.test/api_fetch",
        method="POST",
        baseline_value="http://example.test/x.png",
        parent_path="url",
    )

    baseline_body = "<html><!doctype html><body>avatar sync form</body></html>"
    fetched_body = (
        "<html><!doctype html><body>avatar sync form"
        "<div>&lt;!doctype html&gt;<br>&lt;html&gt;</div>"
        "<div>&lt;!doctype html&gt;</div></body></html>"
    )

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        payload = kwargs.get("payload") or ""
        if "127.0.0.1" in payload or "169.254" in payload:
            return _resp(200, fetched_body)
        return _resp(200, baseline_body)

    monkeypatch.setattr(HttpVerifier, "send_request", send_request)
    findings = await SSRFDetector().detect(
        urls=[],
        forms=[],
        parameters=[parameter],
        api_endpoints=[],
    )

    ssrf = [f for f in findings if f.detection_method == "ssrf_reflection"]
    assert ssrf, "count-differential must fire even though the baseline matches too"
    assert ssrf[0].verified is True
    assert "full-response" in ssrf[0].evidence


# ---------------------------------------------------------------------------
# 5. SPA navigation: stale DOM must not pass as a routed page
# ---------------------------------------------------------------------------


class _StaleShellPage:
    """A page that passes the (lax) shell probe and changes URL on pushState,
    but whose rendered content never changes - a classic server-rendered
    document masquerading as an SPA shell."""

    def __init__(self, url: str, signature: str) -> None:
        self.url = url
        self._signature = signature
        self.pushstate_called = False

    async def evaluate(self, script, *args):
        if "script[src]" in script:  # SPA_SHELL_PROBE_SCRIPT
            return True
        if "pushState" in script:
            self.pushstate_called = True
            # Rewrite the address bar only; the DOM stays untouched.
            path = args[0] if args else "/"
            self.url = f"http://spa.test{path}"
            return None
        if "document.title" in script:  # ROUTE_CONTENT_SIGNATURE_SCRIPT
            return self._signature
        return None

    async def wait_for_timeout(self, timeout):
        return None


@pytest.mark.asyncio
async def test_navigate_spa_route_rejects_unchanged_render():
    engine = BrowserDiscoveryEngine()
    page = _StaleShellPage("http://spa.test/dashboard", signature="title=home|len=12")
    landed = await engine._navigate_spa_route(page, "http://spa.test/feedback")
    assert landed is False, "an un-re-rendered document must fall back to a full load"
    assert page.pushstate_called is True  # the hop was attempted before rejection


@pytest.mark.asyncio
async def test_navigate_spa_route_accepts_when_content_re_renders():
    engine = BrowserDiscoveryEngine()
    page = _StaleShellPage("http://spa.test/dashboard", signature="title=home|len=12")
    reloaded = {"done": False}

    original_evaluate = page.evaluate

    async def evaluate(script, *args):
        if "document.title" in script:
            # The router re-renders after the hop: signature changes.
            return "title=feedback|len=40" if reloaded["done"] else "title=home|len=12"
        if "pushState" in script:
            reloaded["done"] = True
            page.url = "http://spa.test/feedback"
            return None
        return await original_evaluate(script, *args)

    page.evaluate = evaluate
    landed = await engine._navigate_spa_route(page, "http://spa.test/feedback")
    assert landed is True
