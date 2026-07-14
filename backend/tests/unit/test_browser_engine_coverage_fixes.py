"""Regression tests for the crawler coverage root-cause fixes.

Each test pins a concrete defect found by auditing the crawler against a live
SPA (OWASP Juice Shop) whose failure silently lost a whole class of coverage:

* ``add_init_script`` bodies were bare ``() => {}`` expressions Playwright never
  invokes, so the SPA route hook (programmatic pushState/hashchange capture) was
  dead code. Both init scripts must be self-invoking IIFEs.
* Playwright's ``storage_state`` drops sessionStorage, so session-scoped ids
  (cart/basket id, CSRF token) were lost and their mutating flows never fired.
  The engine now re-seeds sessionStorage from the storage_state blob.
* The overlay detector flagged the SPA layout shell (a low-z-index, full-
  viewport absolutely-positioned container) as a blocking overlay on every
  route, forcing an expensive dismiss pass each interaction.
* Mutating "action" buttons (add-to-cart/basket, save, post, …) fire via a
  plain click, not a ``<form>`` submit; the action-click script targets them by
  verb while excluding destructive/navigation controls.

These are framework-agnostic: the scripts key on generic DOM/label signals, not
Juice-Shop- or Angular-specific identifiers.
"""

import re

from app.core.crawler.browser_engine import (
    OVERLAY_DETECT_SCRIPT,
    SAFE_ACTION_CLICK_SCRIPT,
    SPA_ROUTE_HOOK_SCRIPT,
    BrowserDiscoveryEngine,
)


# --- Init scripts must be self-invoking (the dead-code bug) -------------------

def test_init_scripts_are_self_invoking_iife():
    """add_init_script injects source verbatim; a bare ``() => {}`` is defined but
    never called. The route hook (and any future init script) must self-invoke,
    else it silently does nothing — the exact regression this guards."""
    # The route hook must call itself: ends with an invoked-IIFE close ``})();``.
    normalized = SPA_ROUTE_HOOK_SCRIPT.strip()
    assert normalized.startswith("(()") or normalized.startswith("(function"), (
        "route hook must be an IIFE wrapper, not a bare arrow expression"
    )
    assert re.search(r"\}\)\s*\(\s*\)\s*;?\s*$", normalized), (
        "route hook must be invoked at its end (})();)"
    )


def test_session_storage_init_script_is_self_invoking_iife():
    script = BrowserDiscoveryEngine._session_storage_init_script(
        {"origins": [{"origin": "http://x", "sessionStorage": [{"name": "a", "value": "1"}]}]}
    )
    assert script is not None
    assert re.search(r"\}\)\s*\(\s*\)\s*;?\s*$", script.strip()), (
        "sessionStorage restore script must be an invoked IIFE"
    )


# --- sessionStorage restore ---------------------------------------------------

def test_session_storage_script_none_without_session_data():
    """The common cookies+localStorage-only blob must add no script (no cost)."""
    assert BrowserDiscoveryEngine._session_storage_init_script(None) is None
    assert BrowserDiscoveryEngine._session_storage_init_script({}) is None
    assert (
        BrowserDiscoveryEngine._session_storage_init_script(
            {"origins": [{"origin": "http://x", "localStorage": [{"name": "t", "value": "1"}]}]}
        )
        is None
    )
    # Empty sessionStorage list also yields nothing.
    assert (
        BrowserDiscoveryEngine._session_storage_init_script(
            {"origins": [{"origin": "http://x", "sessionStorage": []}]}
        )
        is None
    )


def test_session_storage_script_carries_values_and_origin_guard():
    script = BrowserDiscoveryEngine._session_storage_init_script(
        {
            "origins": [
                {
                    "origin": "http://localhost:3000",
                    "sessionStorage": [{"name": "bid", "value": "6"}],
                }
            ]
        }
    )
    assert script is not None
    # The value is embedded, keyed by origin, and only applied to the matching
    # origin at runtime (so one context can hold several origins safely).
    assert "bid" in script and '"6"' in script
    assert "location.origin" in script
    # Never clobbers a value the live app already set.
    assert "getItem" in script and "setItem" in script


def test_session_storage_script_skips_malformed_entries():
    script = BrowserDiscoveryEngine._session_storage_init_script(
        {
            "origins": [
                {
                    "origin": "http://a",
                    "sessionStorage": [
                        {"name": "keep", "value": "yes"},
                        {"value": "no-name-dropped"},
                        "not-a-dict",
                    ],
                }
            ]
        }
    )
    assert script is not None
    assert "keep" in script
    assert "no-name-dropped" not in script


# --- Overlay detector must not flag the structural SPA shell ------------------

def test_overlay_detect_requires_high_zindex_for_cover_rule():
    """A low-z structural shell (mat-sidenav-container: absolute, z-index 1,
    full-viewport) must NOT be treated as a blocking overlay — that false
    positive forced an ~1.8s dismiss pass on every interaction. The cover rule
    now requires a high stacking order; role/class rules still catch real modals."""
    # The absolute/fixed + big cover rule must gate on a high z-index threshold.
    assert "zi >= 100" in OVERLAY_DETECT_SCRIPT
    assert "zi >= 1)" not in OVERLAY_DETECT_SCRIPT.replace("zi >= 100", "")
    # Real modals are still detected structurally, independent of z-index.
    assert "role" in OVERLAY_DETECT_SCRIPT and "dialog" in OVERLAY_DETECT_SCRIPT
    assert re.search(r"overlay\|backdrop\|modal", OVERLAY_DETECT_SCRIPT)


# --- Safe action-button click script -----------------------------------------

def test_action_click_script_targets_verbs_not_nav_nouns():
    """Requires an action VERB (add/save/create/…) so a nav control whose label
    merely contains a noun ("Your Basket", "Show cart") is not clicked — clicking
    it would navigate away and abort the whole in-page action pass."""
    # Action verbs present; bare nav nouns absent from the action matcher.
    assert re.search(r"\\b\(add\|", SAFE_ACTION_CLICK_SCRIPT)
    # Destructive/purchase-completing verbs are excluded, not clicked.
    assert "checkout" in SAFE_ACTION_CLICK_SCRIPT and "pay" in SAFE_ACTION_CLICK_SCRIPT
    assert re.search(r"DESTRUCTIVE\s*=", SAFE_ACTION_CLICK_SCRIPT)
    # Navigation/show controls are excluded so they never consume the pass.
    assert re.search(r"NON\s*=", SAFE_ACTION_CLICK_SCRIPT)
    for token in ("back", "cancel", "logout", "show", "view", "open"):
        assert token in SAFE_ACTION_CLICK_SCRIPT
    # De-dups by label so a grid of identical buttons fires once.
    assert "seen" in SAFE_ACTION_CLICK_SCRIPT and "slice(0, 40)" in SAFE_ACTION_CLICK_SCRIPT


async def _run_action_click(html: str) -> list[str]:
    """Load ``html`` in headless Chromium and run the action-click pass; return
    the labels clicked. Skips if the browser is unavailable."""
    import pytest

    try:
        from playwright.async_api import async_playwright
    except Exception:  # pragma: no cover
        pytest.skip("playwright not installed")

    engine = BrowserDiscoveryEngine()
    clicked_holder: list[str] = []
    async with async_playwright() as pw:
        try:
            browser = await pw.chromium.launch()
        except Exception:  # pragma: no cover
            pytest.skip("chromium unavailable")
        try:
            page = await browser.new_page()
            fired: list[str] = []
            page.on(
                "request",
                lambda r: fired.append(r.method + " " + r.url)
                if r.method in ("POST", "PUT", "DELETE")
                else None,
            )
            await page.set_content(html)
            result = await engine._click_safe_action_buttons(page)
            clicked_holder.extend(result["clicked"])
            clicked_holder.append("__FIRED__:" + ",".join(fired))
        finally:
            await browser.close()
    return clicked_holder


import pytest


@pytest.mark.asyncio
async def test_action_click_fires_action_button_not_nav_button():
    """End-to-end on a synthetic page: the add button is clicked (fires its XHR),
    the 'Your Basket' nav button and the delete button are not."""
    html = """
    <html><body>
      <button aria-label="Your Basket">shopping_cart Show the shopping cart</button>
      <button id="add" onclick="fetch('http://127.0.0.1:9/api/Items', {method:'POST', body:'{}'}).catch(()=>{});">Add to Basket</button>
      <button id="del" onclick="fetch('http://127.0.0.1:9/api/Items/1', {method:'DELETE'}).catch(()=>{});">Delete item</button>
      <button id="pay" onclick="fetch('http://127.0.0.1:9/api/Pay', {method:'POST'}).catch(()=>{});">Checkout</button>
    </body></html>
    """
    result = await _run_action_click(html)
    labels = [r for r in result if not r.startswith("__FIRED__")]
    fired = next((r for r in result if r.startswith("__FIRED__")), "")
    # Exactly the add action was clicked.
    assert any("add to basket" in l for l in labels)
    assert not any("basket" in l and "show" in l for l in labels)
    assert not any("delete" in l or "checkout" in l for l in labels)
    # And its POST fired; the destructive ones did not.
    assert "POST http://127.0.0.1:9/api/Items" in fired
    assert "DELETE http://127.0.0.1:9/api/Items/1" not in fired
    assert "POST http://127.0.0.1:9/api/Pay" not in fired


# --- Button-driven mutation capture (body-coverage #1) ------------------------
#
# These exercise the crawl-side wiring (dict return, mutation counting, cross-
# route dedup, per-route pass loop, deadline) with a fake page — no real browser
# — so they run in the fast unit suite.


class _FakeReq:
    def __init__(self, method: str) -> None:
        self.method = method


class _FakeActionPage:
    """Minimal page double: ``evaluate`` returns the labels not already clicked
    (mirroring the in-page ``seen`` de-dup seeded from ``priorKeys``) and fires a
    simulated request per configured method through the attached ``on('request')``
    watcher, so :meth:`_click_safe_action_buttons` can count mutating XHRs."""

    def __init__(self, labels: list[str], methods_fired: list[str]) -> None:
        self._labels = labels
        self._methods = methods_fired
        self._listeners: dict[str, list] = {}
        self.evaluate_args: list = []
        self.url = ""

    def on(self, event: str, cb) -> None:
        self._listeners.setdefault(event, []).append(cb)

    def remove_listener(self, event: str, cb) -> None:
        try:
            self._listeners.get(event, []).remove(cb)
        except ValueError:
            pass

    async def evaluate(self, script, arg=None):
        self.evaluate_args.append(arg)
        prior = set((arg or {}).get("priorKeys") or [])
        new = [l for l in self._labels if l not in prior]
        if new:
            for method in self._methods:
                for cb in list(self._listeners.get("request", [])):
                    cb(_FakeReq(method))
        return new

    async def wait_for_timeout(self, ms):
        return None


@pytest.mark.asyncio
async def test_click_safe_action_buttons_returns_dict_and_counts_mutations():
    """The helper returns ``{clicked, mutations}`` and counts only mutating
    (non GET/HEAD/OPTIONS) requests fired during the click+settle window."""
    engine = BrowserDiscoveryEngine()
    page = _FakeActionPage(["add item", "save note"], ["POST", "GET", "PUT"])
    result = await engine._click_safe_action_buttons(page)
    assert result["clicked"] == ["add item", "save note"]
    # POST + PUT are mutating; the GET is not.
    assert result["mutations"] == 2
    # The evaluate arg carried the configured limit and an (empty) prior set.
    assert page.evaluate_args[0]["limit"] == engine.settings.crawl_browser_action_click_limit
    assert page.evaluate_args[0]["priorKeys"] == []


@pytest.mark.asyncio
async def test_click_safe_action_buttons_dedups_across_calls():
    """A crawl-wide ``clicked_action_keys`` set is seeded into the in-page de-dup
    so a stable widget is exercised once globally, never re-fired each pass."""
    engine = BrowserDiscoveryEngine()
    keys: set[str] = set()
    page = _FakeActionPage(["add item", "save note"], ["POST"])
    first = await engine._click_safe_action_buttons(page, None, keys)
    assert set(first["clicked"]) == {"add item", "save note"}
    assert keys == {"add item", "save note"}
    # Second pass: everything is already in the shared set → nothing new clicked.
    second = await engine._click_safe_action_buttons(page, None, keys)
    assert second["clicked"] == []
    assert second["mutations"] == 0
    assert page.evaluate_args[1]["priorKeys"] == sorted(keys)


@pytest.mark.asyncio
async def test_exercise_action_buttons_updates_telemetry_and_stops_when_dry():
    """The first-class per-route step accumulates telemetry and stops as soon as
    a pass clicks nothing new (rather than spinning to the pass cap)."""
    from app.core.crawler.models import CrawlState

    engine = BrowserDiscoveryEngine()
    engine.settings.crawl_browser_action_click_passes = 3
    wstate = CrawlState()
    keys: set[str] = set()
    page = _FakeActionPage(["rate product", "redeem coupon"], ["POST", "PATCH"])
    await engine._exercise_action_buttons(page, wstate, keys)
    assert wstate.buttons_clicked == 2
    assert wstate.button_mutations_fired == 2  # POST + PATCH
    # Pass 1 clicked, pass 2 was dry → break; the 3rd pass never ran.
    assert len(page.evaluate_args) == 2


@pytest.mark.asyncio
async def test_exercise_action_buttons_respects_deadline():
    """When the crawl deadline has already passed, the step does no work at all."""
    import asyncio

    from app.core.crawler.models import CrawlState

    engine = BrowserDiscoveryEngine()
    wstate = CrawlState()
    keys: set[str] = set()
    page = _FakeActionPage(["add item"], ["POST"])
    loop = asyncio.get_running_loop()
    await engine._exercise_action_buttons(
        page, wstate, keys, deadline=loop.time() - 1.0, loop=loop
    )
    assert wstate.buttons_clicked == 0
    assert wstate.button_mutations_fired == 0
    assert page.evaluate_args == []


# --- Workflow chaining signature (body-coverage #2) ---------------------------


class _FakeSigPage:
    def __init__(self, sig) -> None:
        self._sig = sig

    async def evaluate(self, script):
        return self._sig


@pytest.mark.asyncio
async def test_interactive_control_signature_returns_string_or_empty():
    """The chaining decision fingerprint returns the page's evaluate result when
    it is a string, and a safe empty string otherwise (a transient eval failure
    must end the chain, not crash the route)."""
    engine = BrowserDiscoveryEngine()
    assert await engine._interactive_control_signature(_FakeSigPage("1:2:3:1")) == "1:2:3:1"
    # Non-string (e.g. eval returned undefined/None) collapses to "" → chain stops.
    assert await engine._interactive_control_signature(_FakeSigPage(None)) == ""


@pytest.mark.asyncio
async def test_control_signature_changes_when_new_controls_appear():
    """A signature that differs between passes is what drives another chaining
    pass; an unchanged signature stops it. This pins the equality semantics the
    worker loop relies on."""
    engine = BrowserDiscoveryEngine()
    before = await engine._interactive_control_signature(_FakeSigPage("1:3:5:1"))
    after_same = await engine._interactive_control_signature(_FakeSigPage("1:3:5:1"))
    after_new = await engine._interactive_control_signature(_FakeSigPage("2:6:8:2"))
    assert before == after_same  # no new surface → chain would stop
    assert before != after_new  # new surface → chain would continue


# --- Dead client-side route suppression (SPA not-found fallback) ----------------------


def test_is_dead_spa_route_matches_not_found_signature():
    """A hash route whose rendered component tree is identical to the app's
    not-found fallback is dead; a distinct route survives. The root is never dead,
    and a missing signature on either side disables suppression (fail-open)."""
    engine = BrowserDiscoveryEngine()
    nf = "not found|1|mat-toolbar,role:navigation"

    # Identical rendered signature on a non-root route → dead.
    assert engine._is_dead_spa_route("http://h/#/wp-admin", "http://h/", nf, nf) is True
    # A genuinely distinct route (different component tree) → live.
    live = "login|3|form,mat-card,mat-toolbar"
    assert engine._is_dead_spa_route("http://h/#/login", "http://h/", live, nf) is False
    # The root itself bootstraps the shell and is never marked dead.
    assert engine._is_dead_spa_route("http://h/", "http://h/", nf, nf) is False
    # No fingerprint on either side → never suppress (fail-open).
    assert engine._is_dead_spa_route("http://h/#/x", "http://h/", nf, None) is False
    assert engine._is_dead_spa_route("http://h/#/x", "http://h/", None, nf) is False


@pytest.mark.asyncio
async def test_route_content_signature_reads_evaluate_result():
    engine = BrowserDiscoveryEngine()
    assert await engine._route_content_signature(_FakeSigPage("title|2|mat-toolbar")) == "title|2|mat-toolbar"
    # A non-string / failed eval collapses to None so suppression fails open.
    assert await engine._route_content_signature(_FakeSigPage(None)) is None
    assert await engine._route_content_signature(_FakeSigPage("")) is None


