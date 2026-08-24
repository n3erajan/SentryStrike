"""Batch stored-XSS discovery: plant every group's canaries, then read once.

Each route group plants a unique canary per parameter in a single request. The
display pages are then fetched **once in total**, not once per group: canaries are
globally unique, so one page body can be attributed to whichever candidates it
contains. Reading per group re-fetched the same pages once per group, which on a
slow target was the dominant cost of the phase.

Candidates are also keyed by ``(url, method, parameter)``. Keying by bare
parameter name made two forms that both have a field called ``email`` overwrite
each other, so one form inherited the other's stored verdict.
"""
from __future__ import annotations

import pytest

from app.core.crawler.models import ParameterLocation
from app.core.detectors.attack_surface import AttackTarget
from app.core.verification.response_analyzer import ResponseData
from app.core.verification.xss_verifier import (
    XSSVerifier,
    stored_override_key,
)


def _resp(body: str, status: int = 200) -> ResponseData:
    return ResponseData(
        status_code=status,
        headers={"Content-Type": "text/html"},
        body=body,
        response_time_ms=1.0,
        request_snippet="req",
        response_snippet="resp",
    )


def _form_target(url: str, parameter: str, method: str = "POST") -> AttackTarget:
    return AttackTarget(
        url=url,
        parameter=parameter,
        method=method,
        value="x",
        location=ParameterLocation.form,
        form_inputs=[],
    )


class _RecordingVerifier(XSSVerifier):
    """Verifier whose ``_send`` records traffic and serves a scripted store."""

    def __init__(self, stored_pages: dict[str, list[str]] | None = None) -> None:
        super().__init__()
        self.sent: list[tuple[str, str]] = []          # (test_phase, url)
        self.planted: dict[str, str] = {}              # parameter -> canary
        # display_url -> parameters whose canary that page renders
        self._stored_pages = stored_pages or {}

        async def fake_send(url, method="GET", params=None, data=None, *, headers=None,
                            cookies=None, json_body=None, test_phase="", payload=""):
            self.sent.append((test_phase, url))
            if test_phase == "batch_stored_inject":
                for param, canary in (data or params or {}).items():
                    self.planted[param] = canary
                return _resp("<html>saved</html>")
            if test_phase in {"batch_stored_check", "stored_pre_test_baseline"}:
                if test_phase == "stored_pre_test_baseline":
                    return _resp("<html>baseline</html>")
                rendered = [
                    self.planted[param]
                    for param in self._stored_pages.get(url, [])
                    if param in self.planted
                ]
                return _resp("<html>" + " ".join(rendered) + "</html>")
            return _resp("<html>clean</html>")

        self._send = fake_send  # type: ignore[assignment]


DISPLAY_URLS = ["http://t/page-a", "http://t/page-b", "http://t/page-c"]


@pytest.mark.asyncio
async def test_plant_returns_one_canary_per_parameter_and_sends_one_request():
    verifier = _RecordingVerifier()
    candidates = [
        _form_target("http://t/comment", "body"),
        _form_target("http://t/comment", "author"),
    ]

    canary_map = await verifier.plant_batch_canaries(candidates)

    assert len(canary_map) == 2
    assert set(canary_map) == {
        stored_override_key("http://t/comment", "POST", "body"),
        stored_override_key("http://t/comment", "POST", "author"),
    }
    # Canaries must be distinct — attribution depends on it.
    assert len(set(canary_map.values())) == 2
    # One injection request carries every canary.
    injections = [p for p, _ in verifier.sent if p == "batch_stored_inject"]
    assert len(injections) == 1
    # Planting must not read display pages.
    assert not [p for p, _ in verifier.sent if p == "batch_stored_check"]


@pytest.mark.asyncio
async def test_rejected_injection_yields_no_canaries():
    """A 400/422 means we cannot attribute anything, so the group falls back."""
    verifier = _RecordingVerifier()

    async def rejecting_send(url, method="GET", params=None, data=None, *, headers=None,
                             cookies=None, json_body=None, test_phase="", payload=""):
        verifier.sent.append((test_phase, url))
        return _resp("validation failed", status=422)

    verifier._send = rejecting_send  # type: ignore[assignment]

    canary_map = await verifier.plant_batch_canaries(
        [_form_target("http://t/comment", "body"), _form_target("http://t/comment", "author")]
    )

    assert canary_map == {}


@pytest.mark.asyncio
async def test_read_pass_fetches_each_display_url_exactly_once():
    """The core fix: N groups' canaries cost one fetch per URL, not N."""
    verifier = _RecordingVerifier(stored_pages={"http://t/page-b": ["body"]})

    # Three groups' worth of canaries, planted separately then read together.
    planted: dict[tuple[str, str, str], str] = {}
    for route in ("http://t/comment", "http://t/profile", "http://t/feedback"):
        planted.update(
            await verifier.plant_batch_canaries(
                [_form_target(route, "body"), _form_target(route, "author")]
            )
        )
    assert len(planted) == 6

    verifier.sent.clear()
    confirmed = await verifier.collect_stored_canaries(planted, DISPLAY_URLS)

    checks = [url for phase, url in verifier.sent if phase == "batch_stored_check"]
    assert len(checks) == len(DISPLAY_URLS), (
        f"expected {len(DISPLAY_URLS)} reads for 3 groups, got {len(checks)}"
    )
    assert sorted(checks) == sorted(DISPLAY_URLS)
    assert confirmed, "the stored canary should have been attributed"


@pytest.mark.asyncio
async def test_read_pass_attributes_each_canary_to_its_own_candidate():
    verifier = _RecordingVerifier(
        stored_pages={
            "http://t/page-a": ["body"],
            "http://t/page-c": ["author"],
        }
    )
    candidates = [
        _form_target("http://t/comment", "body"),
        _form_target("http://t/comment", "author"),
        _form_target("http://t/comment", "subject"),
    ]
    planted = await verifier.plant_batch_canaries(candidates)

    confirmed = await verifier.collect_stored_canaries(planted, DISPLAY_URLS)

    body_key = stored_override_key("http://t/comment", "POST", "body")
    author_key = stored_override_key("http://t/comment", "POST", "author")
    subject_key = stored_override_key("http://t/comment", "POST", "subject")

    assert confirmed[body_key] == {"http://t/page-a"}
    assert confirmed[author_key] == {"http://t/page-c"}
    # Not stored anywhere — absence is the signal that skips its stored probe.
    assert subject_key not in confirmed


@pytest.mark.asyncio
async def test_same_parameter_name_on_two_routes_does_not_collide():
    """The keying bug: both routes have a field called ``email``.

    Keyed by bare parameter name, the second route's canary overwrote the first
    and both inherited a single verdict. Keyed by (url, method, parameter) they
    stay independent — only the route that actually stores is confirmed.
    """
    verifier = _RecordingVerifier(stored_pages={"http://t/page-a": ["email"]})

    newsletter = await verifier.plant_batch_canaries(
        [_form_target("http://t/newsletter", "email"), _form_target("http://t/newsletter", "name")]
    )
    # Planting the second route rebinds "email" in the fake store, so only the
    # most recent route's canary is the one the page renders.
    contact = await verifier.plant_batch_canaries(
        [_form_target("http://t/contact", "email"), _form_target("http://t/contact", "name")]
    )

    planted = {**newsletter, **contact}
    # Four distinct keys survive the merge; bare-name keying would collapse the
    # two "email" entries (and the two "name" entries) down to two.
    assert len(planted) == 4
    assert len(set(planted.values())) == 4

    confirmed = await verifier.collect_stored_canaries(planted, DISPLAY_URLS)

    contact_email = stored_override_key("http://t/contact", "POST", "email")
    newsletter_email = stored_override_key("http://t/newsletter", "POST", "email")
    assert contact_email in confirmed
    assert newsletter_email not in confirmed, (
        "newsletter/email inherited contact/email's verdict — keys are colliding"
    )


def test_stored_override_key_normalises_method_case():
    assert stored_override_key("http://t/a", "post", "p") == stored_override_key(
        "http://t/a", "POST", "p"
    )


def test_sink_urls_are_capped_like_ordinary_urls():
    """Sinks were spliced in uncapped, so a site of sink-shaped routes bypassed
    the cap entirely and returned hundreds of display URLs."""
    sinks = [f"http://t/admin/page-{i}" for i in range(200)]
    others = [f"http://t/article-{i}" for i in range(200)]

    selected = XSSVerifier.select_stored_probe_urls(sinks + others)

    assert len(selected) <= 2 * XSSVerifier._STORED_PROBE_URL_CAP
    # Sinks still get priority.
    assert selected[0].startswith("http://t/admin/")


def test_content_routes_are_not_mistaken_for_sinks():
    """``view`` unanchored matched every ``/contents/html-view/...`` page."""
    pattern = XSSVerifier._HEADER_SINK_PATTERNS
    assert not pattern.search("http://t/contents/html-view/algebraic-expression")
    assert not pattern.search("http://t/accessibility")
    assert not pattern.search("http://t/preview/article")
    # Genuine sink shapes still match.
    assert pattern.search("http://t/admin/users")
    assert pattern.search("http://t/audit-log")
    assert pattern.search("http://t/system.log")
