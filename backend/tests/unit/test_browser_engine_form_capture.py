"""Form-capture robustness against a live headless page (real Chromium).

These tests drive the actual FORM_CAPTURE_SCRIPT so the DOM heuristics are
exercised for real, not stubbed — covering submit-less framework clusters and
standalone file inputs. Skipped cleanly when a browser cannot be launched (CI
without the chromium binary).
"""
import pytest

from app.core.crawler.browser_engine import BrowserDiscoveryEngine

pytestmark = pytest.mark.asyncio


async def _launch():
    try:
        from playwright.async_api import async_playwright
    except Exception:
        return None
    try:
        pw = await async_playwright().start()
        browser = await pw.chromium.launch()
        return pw, browser
    except Exception:
        return None


async def _capture(html: str):
    launched = await _launch()
    if launched is None:
        pytest.skip("chromium not available")
    pw, browser = launched
    try:
        page = await browser.new_page()
        await page.set_content(html)
        engine = BrowserDiscoveryEngine()
        return await engine._capture_forms(page, "http://spa.test/")
    finally:
        await browser.close()
        await pw.stop()


async def test_submitless_multifield_cluster_is_captured():
    """A framework form with two named fields and NO submit button is captured."""
    html = """
      <div id="reg">
        <input name="email" type="email">
        <input name="password" type="password">
      </div>
    """
    forms = await _capture(html)
    names = {i["name"] for f in forms for i in f["inputs"]}
    assert "email" in names and "password" in names
    # Recorded as a button-less cluster (fallback candidate body downstream).
    assert any(f.get("no_submit") for f in forms)


async def test_standalone_file_input_is_captured():
    """A bare file-upload input with no button and no siblings is discovered."""
    html = '<div><input type="file" name="avatar"></div>'
    forms = await _capture(html)
    file_forms = [f for f in forms if f.get("file_inputs", 0) >= 1]
    assert file_forms, forms
    assert any(i["type"] == "file" for f in file_forms for i in f["inputs"])


async def test_lone_search_box_is_not_captured():
    """A single unnamed/lone field with no submit control stays dropped (noise)."""
    html = '<div><input type="search" aria-label="Search site"></div>'
    forms = await _capture(html)
    # No password, no file, fewer than two named fields → not a form cluster.
    assert forms == [] or all(not f.get("no_submit") for f in forms)


async def test_classic_form_with_button_still_captured():
    """Regression: a normal <form> with a submit button is unaffected."""
    html = """
      <form action="/api/login" method="post">
        <input name="user" type="text">
        <input name="pass" type="password">
        <button type="submit">Sign in</button>
      </form>
    """
    forms = await _capture(html)
    assert any(f.get("has_form") for f in forms)
    names = {i["name"] for f in forms for i in f["inputs"]}
    assert "user" in names and "pass" in names
