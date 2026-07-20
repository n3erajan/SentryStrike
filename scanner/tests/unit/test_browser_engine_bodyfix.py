"""Regression tests for the browser-discovery replayable-JSON-body fixes.

These cover the concrete generic defects that collapsed ``replayable_json_bodies``
to ~1 despite many "submitted" forms: <select> never filled, confirm/repeat
fields not matching, type-constrained fields left invalid, and disabled submit
controls clicked-and-timed-out instead of skipped. The final two tests drive a
real headless Chromium end-to-end (skipped when the browser is unavailable).
"""

import contextlib
import http.server
import socketserver
import threading

import pytest

from app.core.crawler.browser_engine import BrowserDiscoveryEngine


def test_typed_placeholder_returns_format_valid_values():
    tp = BrowserDiscoveryEngine._typed_placeholder
    assert tp("date") == "2020-01-01"
    assert tp("datetime-local") == "2020-01-01T12:00"
    assert tp("number") == "1"
    assert tp("range") == "1"
    assert tp("url") == "https://example.com/"
    assert tp("email") == "scanner@example.com"
    assert tp("tel").startswith("+")
    assert tp("color").startswith("#")
    # Plain text carries no format constraint -> None (name hint handles it).
    assert tp("text") is None
    assert tp("") is None


def test_observation_key_collapses_volatile_timestamp_only_bodies():
    """Two submits of the same form to the same endpoint that differ ONLY by a
    server-stamped ISO-8601 timestamp echoed into the body must share a dedup
    key (else the identical replayable body is counted twice as a phantom
    double-submit). Bodies that differ in a real value stay distinct."""
    key = BrowserDiscoveryEngine._observation_key
    a = key("http://t/api/Users/", "POST",
            '{"email":"e","q":{"createdAt":"2026-07-08T04:39:25.323Z"}}')
    b = key("http://t/api/Users/", "POST",
            '{"email":"e","q":{"createdAt":"2026-07-08T04:39:26.999Z"}}')
    assert a == b
    # A different real value (credentials) is NOT collapsed.
    c = key("http://t/api/Users/", "POST",
            '{"email":"OTHER","q":{"createdAt":"2026-07-08T04:39:26.999Z"}}')
    assert a != c
    # A different endpoint is never collapsed.
    d = key("http://t/api/Other/", "POST",
            '{"email":"e","q":{"createdAt":"2026-07-08T04:39:25.323Z"}}')
    assert a != d
    # No body at all still keys cleanly (empty string, no crash).
    assert key("http://t/x", "GET", None) == ("GET", "http://t/x", "")


def test_synthetic_value_uses_typed_format_for_constrained_types():
    engine = BrowserDiscoveryEngine()
    engine._auth_username = ""
    engine._auth_password = ""
    assert engine._synthetic_value("dob", "date") == "2020-01-01"
    assert engine._synthetic_value("age", "number") == "1"
    assert engine._synthetic_value("homepage", "url") == "https://example.com/"


class _RecordFillPage:
    """Accepts every fill/check/select and records the value used."""

    def __init__(self):
        self.fills = []

    async def fill(self, selector, value, timeout=None):
        self.fills.append((selector, value))

    async def check(self, selector, timeout=None):
        self.fills.append((selector, "checked"))

    async def evaluate(self, script, *args):
        # The fill path dispatches a blur via page.evaluate after filling so
        # reactive frameworks run change detection; the stub has no live DOM,
        # so this is a no-op that must simply not raise.
        return None

    async def wait_for_timeout(self, ms):
        return None

    def locator(self, selector):
        page = self

        class _L:
            def __init__(self, sel):
                self._sel = sel
                self.first = self

            async def evaluate(self, script):
                return ["", "user", "admin"]

            async def select_option(self, value=None, index=None, timeout=None):
                page.fills.append((self._sel, value if value is not None else f"index={index}"))

        return _L(selector)


@pytest.mark.asyncio
async def test_select_field_uses_select_option_not_fill():
    """A <select> is driven through select_option (page.fill raises on it); the
    first non-placeholder option is chosen so a required dropdown becomes valid."""
    engine = BrowserDiscoveryEngine()
    page = _RecordFillPage()
    form = {"cluster_id": 3, "inputs": [{"name": "role", "type": "select", "field_id": "3:0"}]}
    filled = await engine._fill_form_fields(page, form)
    assert filled is True
    assert page.fills == [("[data-sentry-field='3:0']", "user")]


@pytest.mark.asyncio
async def test_select_field_preserves_existing_non_placeholder_value():
    engine = BrowserDiscoveryEngine()

    class _SelectedPage(_RecordFillPage):
        def locator(self, selector):
            page = self

            class _L:
                def __init__(self, sel):
                    self._sel = sel
                    self.first = self

                async def evaluate(self, script):
                    return {"current": "low", "values": ["high", "medium", "low"]}

                async def select_option(self, value=None, index=None, timeout=None):
                    page.fills.append((self._sel, value if value is not None else f"index={index}"))

            return _L(selector)

    page = _SelectedPage()
    form = {"cluster_id": 4, "inputs": [{"name": "security", "type": "select", "field_id": "4:0"}]}

    filled = await engine._fill_form_fields(page, form)

    assert filled is True
    assert page.fills == []


@pytest.mark.asyncio
async def test_confirm_field_echoes_primary_value():
    """A confirm/repeat field echoes the primary same-type value so generic
    'must match' validators pass."""
    engine = BrowserDiscoveryEngine()
    engine._auth_username = ""
    engine._auth_password = ""
    page = _RecordFillPage()
    form = {
        "cluster_id": 5,
        "inputs": [
            {"name": "password", "type": "password", "field_id": "5:0"},
            {"name": "passwordRepeat", "type": "password", "field_id": "5:1"},
        ],
    }
    await engine._fill_form_fields(page, form)
    values = [v for _, v in page.fills]
    assert len(values) == 2 and values[0] == values[1] and values[0]


class _DisabledSubmitPage:
    """A cluster whose only submit control is permanently disabled and which has
    no <form> and no Enter-eligible field — the pure disabled-form no-op."""

    def __init__(self):
        self.clicks = 0

    def locator(self, selector):
        page = self

        class _L:
            def __init__(self, sel):
                self._sel = sel
                self.first = self

            async def count(self):
                return 1 if ("submit" in self._sel or "button" in self._sel) else 0

            def nth(self, index):
                return self

            async def is_enabled(self, timeout=None):
                return False

            async def click(self, timeout=None):
                page.clicks += 1

        return _L(selector)

    async def evaluate(self, script, *args):
        return False

    async def check(self, selector, timeout=None):
        return None

    async def fill(self, selector, value, timeout=None):
        return None


@pytest.mark.asyncio
async def test_submit_form_skips_disabled_control_and_reports_no_fire():
    """A disabled submit control is skipped via a fast is_enabled probe (never
    clicked-and-timed-out), and _submit_form reports no fire so the caller does
    not count a doomed no-op as a submission."""
    engine = BrowserDiscoveryEngine()
    page = _DisabledSubmitPage()
    form = {
        "cluster_id": 9,
        "has_form": False,
        "inputs": [{"name": "agree", "type": "checkbox", "field_id": "9:0"}],
    }
    fired = await engine._submit_form(page, form)
    assert fired is False
    assert page.clicks == 0


@pytest.mark.asyncio
async def test_click_first_enabled_prefers_enabled_over_disabled():
    """The enabled control is clicked; disabled ones are never clicked (so no
    actionability-timeout is ever paid on a disabled reactive submit)."""
    clicked = {"n": 0}
    enabled_states = [False, True]

    class _El:
        def __init__(self, enabled):
            self._enabled = enabled

        async def is_enabled(self, timeout=None):
            return self._enabled

        async def click(self, timeout=None):
            clicked["n"] += 1

    class _Page:
        def locator(self, selector):
            class _L:
                def __init__(self, sel):
                    self._sel = sel
                    self.first = _El(True)

                async def count(self):
                    return 2 if "submit" in self._sel else 0

                def nth(self, index):
                    return _El(enabled_states[index])

            return _L(selector)

    engine = BrowserDiscoveryEngine()
    ok = await engine._click_first_enabled(_Page(), ("button[type=submit]",))
    assert ok is True
    assert clicked["n"] == 1


@pytest.mark.asyncio
async def test_capture_forms_never_emits_empty_field_name():
    """A field whose name cascade fails must fall back to a stable positional
    field_id token, never an empty name (which is unaddressable downstream)."""

    class _Page:
        async def evaluate(self, script, *args):
            return [
                {
                    "cluster_id": 0,
                    "action": "/x",
                    "method": "POST",
                    # Simulate the capture script's own fallback: name resolved to
                    # the positional token, named=False.
                    "inputs": [{"name": "field_0_0", "type": "text", "field_id": "0:0", "named": False}],
                    "has_form": False,
                    "file_inputs": 0,
                    "action_controls": 1,
                    "all_named": False,
                }
            ]

    engine = BrowserDiscoveryEngine()
    forms = await engine._capture_forms(_Page(), "http://spa.test/")
    assert forms and forms[0]["inputs"][0]["name"] == "field_0_0"
    assert forms[0]["inputs"][0]["name"] != ""
    # A cluster with no real framework names is flagged for hydration recapture.
    assert engine._forms_need_hydration_recapture(forms) is True


def test_forms_need_hydration_recapture_false_when_all_named():
    engine = BrowserDiscoveryEngine()
    forms = [{"all_named": True, "inputs": [{"name": "email", "named": True}]}]
    assert engine._forms_need_hydration_recapture(forms) is False


@pytest.mark.asyncio
async def test_reacquire_cluster_matches_by_cluster_id_when_names_change():
    """Re-capture must match on the DOM-anchored cluster_id even when framework
    field names arrived late (so the name-derived _form_key differs)."""

    engine = BrowserDiscoveryEngine()
    original = {
        "cluster_id": 7,
        "action": "http://spa.test/r",
        "method": "POST",
        "inputs": [{"name": "field_7_0", "type": "text", "field_id": "7:0", "named": False}],
        "has_form": False,
    }
    hydrated = {
        "cluster_id": 7,
        "action": "http://spa.test/r",
        "method": "POST",
        "inputs": [{"name": "username", "type": "text", "field_id": "7:0", "named": True}],
        "has_form": False,
    }

    async def _fake_capture(page, url):
        return [hydrated]

    engine._capture_forms = _fake_capture  # type: ignore[assignment]
    engine._current_url = lambda page, route: route  # no navigation

    matched = await engine._reacquire_cluster(
        None, "http://spa.test/", "http://spa.test/r", original, {"count": 0}
    )
    assert matched is hydrated


# --- End-to-end validation against real Chromium (skips if unavailable) -------


_REACTIVE_FORM_HTML = """<!doctype html><html><body>
<form id="reg">
  <input id="email" name="email" type="email" required>
  <input id="pw" name="password" type="password" minlength="6" required>
  <input id="pw2" name="passwordRepeat" type="password" required>
  <select id="role" name="role" required>
    <option value="">--</option><option value="user">User</option>
  </select>
  <label><input id="terms" name="terms" type="checkbox" required> agree</label>
  <button id="submit" type="submit" disabled>Register</button>
</form>
<script>
  const f = document.getElementById('reg'), b = document.getElementById('submit');
  const pw = document.getElementById('pw'), pw2 = document.getElementById('pw2');
  function ok() { return f.checkValidity() && pw.value === pw2.value; }
  function upd() { b.disabled = !ok(); }
  f.addEventListener('input', upd); f.addEventListener('change', upd);
  f.addEventListener('submit', async (e) => {
    e.preventDefault();
    await fetch('/api/register', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({email: document.getElementById('email').value,
                            password: pw.value, role: document.getElementById('role').value})
    });
  });
</script></body></html>"""


_IMPOSSIBLE_FORM_HTML = """<!doctype html><html><body>
<form id="f">
  <input id="x" name="x" type="text" pattern="a(?!a)a" required>
  <button id="s" type="submit" disabled>Go</button>
</form>
<script>
  const f = document.getElementById('f'), b = document.getElementById('s');
  f.addEventListener('input', () => b.disabled = !f.checkValidity());
  f.addEventListener('submit', async (e) => {
    e.preventDefault();
    await fetch('/api/x', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: '{}'});
  });
</script></body></html>"""


# A reactive form gated on a CUSTOM ARIA dropdown (role=combobox + a portalled
# role=listbox of role=option), the shape Angular Material's <mat-select> takes.
# Native fill/select_option cannot satisfy it — only opening the widget and
# clicking an option does — so the submit stays disabled until it is engaged.
_ARIA_COMBOBOX_FORM_HTML = """<!doctype html><html><body>
<form id="reg">
  <input id="email" name="email" type="email" required>
  <div id="combo" role="combobox" aria-haspopup="listbox" tabindex="0">Choose…</div>
  <button id="submit" type="submit" disabled>Register</button>
</form>
<div id="panel" role="listbox" style="display:none">
  <div role="option" data-value="">--</div>
  <div role="option" data-value="q1">Question One</div>
</div>
<script>
  const f = document.getElementById('reg'), b = document.getElementById('submit');
  const combo = document.getElementById('combo'), panel = document.getElementById('panel');
  let picked = '';
  function ok() { return f.checkValidity() && picked !== ''; }
  function upd() { b.disabled = !ok(); }
  f.addEventListener('input', upd);
  combo.addEventListener('click', () => { panel.style.display = 'block'; });
  panel.querySelectorAll('[role=option]').forEach((o) => o.addEventListener('click', () => {
    picked = o.getAttribute('data-value'); combo.textContent = o.textContent;
    panel.style.display = 'none'; upd();
  }));
  f.addEventListener('submit', async (e) => {
    e.preventDefault();
    await fetch('/api/register', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({email: document.getElementById('email').value, question: picked})
    });
  });
</script></body></html>"""


@contextlib.contextmanager
def _serve(html):
    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            return None

        def do_GET(self):
            body = html.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0) or 0)
            self.rfile.read(length)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok":true}')

    server = socketserver.TCPServer(("127.0.0.1", 0), _H)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}/"
    finally:
        server.shutdown()


async def _drive(html):
    """Serve ``html``, capture forms, submit them with a real Chromium page, and
    return ``(submitted_count, [(url, post_data, content_type), ...])``."""
    from playwright.async_api import async_playwright

    posts: list = []
    with _serve(html) as url:
        engine = BrowserDiscoveryEngine()
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            page = await (await browser.new_context()).new_page()
            page.on(
                "request",
                lambda r: posts.append((r.url, r.post_data, (r.headers or {}).get("content-type", "")))
                if r.method == "POST"
                else None,
            )
            await page.goto(url)
            forms = await engine._capture_forms(page, url)
            submitted = await engine._submit_discovered_forms(
                page, forms, url, url, set(), inflight={"count": 0}
            )
            await browser.close()
    return submitted, posts


@pytest.mark.asyncio
async def test_real_chromium_reactive_form_yields_replayable_json_body():
    """A reactive form with a disabled submit (required email, password + matching
    confirm, required <select>, required checkbox) must be filled to validity, its
    submit enabled and clicked, and its POST JSON body captured — the exact shape
    that previously produced replayable_json_bodies == 0."""
    ready, _reason = await BrowserDiscoveryEngine.check_readiness()
    if not ready:
        pytest.skip("Playwright browser not available")
    submitted, posts = await _drive(_REACTIVE_FORM_HTML)
    assert submitted >= 1, "the reactive form should have been submitted"
    json_posts = [pd for (_u, pd, ct) in posts if pd and "json" in (ct or "").lower()]
    assert json_posts, f"expected a captured JSON POST body, got {posts!r}"
    assert "password" in json_posts[0]
    # The required <select> was chosen (not left at the empty placeholder).
    assert '"role":"user"' in json_posts[0].replace(" ", "")


@pytest.mark.asyncio
async def test_real_chromium_impossible_form_wastes_no_click_and_captures_nothing():
    """A form that can never be made valid must not be counted as submitted and
    must fire no body — proving the disabled-control fast-skip works end-to-end
    (and does not stall on the click-actionability timeout)."""
    ready, _reason = await BrowserDiscoveryEngine.check_readiness()
    if not ready:
        pytest.skip("Playwright browser not available")
    submitted, posts = await _drive(_IMPOSSIBLE_FORM_HTML)
    assert submitted == 0
    assert posts == []


@pytest.mark.asyncio
async def test_real_chromium_aria_combobox_form_yields_replayable_json_body():
    """A reactive form gated on a CUSTOM ARIA dropdown (mat-select shape: a
    role=combobox trigger + a portalled role=listbox) must be engaged — opened and
    an option chosen — so the submit enables and its POST JSON body is captured.
    Native fill/select_option cannot satisfy such a widget, which left Juice Shop's
    registration (and any framework kit's custom dropdown) unsubmittable."""
    ready, _reason = await BrowserDiscoveryEngine.check_readiness()
    if not ready:
        pytest.skip("Playwright browser not available")
    submitted, posts = await _drive(_ARIA_COMBOBOX_FORM_HTML)
    assert submitted >= 1, "the ARIA-combobox form should have been submitted"
    json_posts = [pd for (_u, pd, ct) in posts if pd and "json" in (ct or "").lower()]
    assert json_posts, f"expected a captured JSON POST body, got {posts!r}"
    # The dropdown was engaged (a non-placeholder option selected), not left empty.
    assert '"question":"q1"' in json_posts[0].replace(" ", "")


class _StubShellPage:
    """Minimal page whose SPA-shell probe result is configurable, used to assert
    the client-side-routing guard without a real browser."""

    def __init__(self, is_shell: bool, url: str) -> None:
        self._is_shell = is_shell
        self.url = url
        self.hash_set = False
        self.pushstate_called = False

    async def evaluate(self, script, *args):
        if "script[src]" in script:  # SPA_SHELL_PROBE_SCRIPT
            return self._is_shell
        if "location.hash" in script:  # hash routing
            self.hash_set = True
            frag = args[0] if args else ""
            base = self.url.split("#", 1)[0]
            self.url = f"{base}#{frag}"
            return None
        if "pushState" in script:
            self.pushstate_called = True
            return None
        return None

    async def wait_for_timeout(self, timeout):
        return None


@pytest.mark.asyncio
async def test_navigate_spa_route_refused_on_non_shell_document():
    """The poisoning-bug regression: client-side routing must be REFUSED when the
    page currently holds a non-SPA document (a raw JSON/file/error body). Routing
    such a document only rewrites a dead URL and the framework router never reacts,
    which produced browser_requests_observed low and replayable_json_bodies == 0
    in production. The engine must instead report failure so the caller full-loads.
    """
    engine = BrowserDiscoveryEngine()
    page = _StubShellPage(is_shell=False, url="http://spa.test/api/Feedbacks")
    landed = await engine._navigate_spa_route(page, "http://spa.test/#/login")
    assert landed is False, "routing a non-shell document must be refused"
    assert page.hash_set is False, "the dead document's URL must not be mutated"
    assert page.url == "http://spa.test/api/Feedbacks"


@pytest.mark.asyncio
async def test_navigate_spa_route_applied_on_live_shell():
    """On a live SPA shell, hash routing is applied and reported as landed."""
    engine = BrowserDiscoveryEngine()
    page = _StubShellPage(is_shell=True, url="http://spa.test/")
    landed = await engine._navigate_spa_route(page, "http://spa.test/#/login")
    assert landed is True
    assert page.hash_set is True
    assert page.url.endswith("#/login")


@pytest.mark.asyncio
async def test_real_chromium_recovers_from_non_spa_document_to_spa_route():
    """End-to-end: a worker page that currently holds a raw JSON body must still
    reach an SPA route's forms on the next navigation (via full-load fallback),
    rather than being poisoned for the rest of its life."""
    ready, _reason = await BrowserDiscoveryEngine.check_readiness()
    if not ready:
        pytest.skip("Playwright browser not available")
    from playwright.async_api import async_playwright

    shell = (
        "<!doctype html><html><head><script src='/app.js'></script></head>"
        "<body><app-root>"
        "<input name='email' type='email' required>"
        "<input name='password' type='password' required>"
        "<button type='submit'>Go</button>"
        "</app-root></body></html>"
    )

    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            return None

        def do_GET(self):
            if self.path.startswith("/api/"):
                body, ctype = b'{"status":"ok","data":[]}', "application/json"
            elif self.path.endswith(".js"):
                body, ctype = b"", "application/javascript"
            else:
                body, ctype = shell.encode(), "text/html"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = socketserver.TCPServer(("127.0.0.1", 0), _H)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{port}"
        engine = BrowserDiscoveryEngine()
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            page = await (await browser.new_context()).new_page()
            # Poison the page: full-load a raw JSON document first.
            await page.goto(f"{base}/api/Feedbacks")
            # Client-side routing must be refused on the JSON doc...
            assert await engine._navigate_spa_route(page, f"{base}/#/login") is False
            # ...and the full-load fallback in _navigate must recover the shell.
            await engine._navigate(page, f"{base}/#/login", base + "/", allow_spa=True)
            forms = await engine._capture_forms(page, f"{base}/#/login")
            await browser.close()
        assert forms, "forms must be reachable after recovering from a non-SPA document"
    finally:
        server.shutdown()
