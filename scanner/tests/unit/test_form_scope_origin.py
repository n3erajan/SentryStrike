"""Issue 2 — form scope filter must key on the RESOLVED action, not page_url.

A form is an attack target because of where it SUBMITS (its action), not the
page it appears on. The old filter accepted a form when either its action OR its
page_url was same-origin, so a same-origin page carrying an off-origin action
survived and later drove active payloads (and any auth) at a third party.
_scope_forms_to_origin now decides scope from the resolved action alone;
page_url is used only to resolve a relative/empty action.
"""
from urllib.parse import urlparse

from app.core.crawler.spider import FormInput, HtmlForm
from app.core.scanner import ScanOrchestrator


def _is_same_origin(url_a: str, url_b: str) -> bool:
    """Mirror of the run_scan local origin check (scheme + host + effective port)."""
    try:
        p_a = urlparse(url_a)
        p_b = urlparse(url_b)
        port_a = p_a.port or (80 if p_a.scheme == "http" else 443 if p_a.scheme == "https" else None)
        port_b = p_b.port or (80 if p_b.scheme == "http" else 443 if p_b.scheme == "https" else None)
        return p_a.scheme == p_b.scheme and p_a.hostname == p_b.hostname and port_a == port_b
    except Exception:
        return False


TARGET = "http://localhost:3000/"


def _form(page_url: str, action: str) -> HtmlForm:
    return HtmlForm(
        page_url=page_url,
        action=action,
        method="POST",
        inputs=[FormInput("q", "text")],
    )


def test_off_origin_action_on_same_origin_page_is_dropped():
    """The core bug: same-origin page, off-origin action. Must be rejected so
    payloads never reach the third party."""
    form = _form("http://localhost:3000/contact", "https://evil.example/collect")

    scoped = ScanOrchestrator._scope_forms_to_origin(TARGET, [form], _is_same_origin)

    assert scoped == []


def test_same_origin_absolute_action_is_kept():
    form = _form("http://localhost:3000/contact", "http://localhost:3000/api/Feedbacks")

    scoped = ScanOrchestrator._scope_forms_to_origin(TARGET, [form], _is_same_origin)

    assert len(scoped) == 1
    assert scoped[0].action == "http://localhost:3000/api/Feedbacks"


def test_relative_action_is_resolved_against_page_url_and_kept():
    """A relative/empty action is legitimate — resolve it against page_url, and
    the resolved absolute action is written back for downstream targeting."""
    form = _form("http://localhost:3000/contact", "/api/Feedbacks")

    scoped = ScanOrchestrator._scope_forms_to_origin(TARGET, [form], _is_same_origin)

    assert len(scoped) == 1
    assert scoped[0].action == "http://localhost:3000/api/Feedbacks"


def test_empty_action_falls_back_to_page_url():
    form = _form("http://localhost:3000/login", "")

    scoped = ScanOrchestrator._scope_forms_to_origin(TARGET, [form], _is_same_origin)

    assert len(scoped) == 1
    assert scoped[0].action == "http://localhost:3000/login"


def test_off_origin_page_with_relative_action_is_dropped():
    """A relative action on an off-origin page resolves to that off-origin host,
    so it stays out of scope."""
    form = _form("https://cdn.example/widget", "/submit")

    scoped = ScanOrchestrator._scope_forms_to_origin(TARGET, [form], _is_same_origin)

    assert scoped == []


def test_cross_scheme_action_is_dropped():
    """Same host, different scheme is a different origin (http vs https)."""
    form = _form("http://localhost:3000/contact", "https://localhost:3000/api/Feedbacks")

    scoped = ScanOrchestrator._scope_forms_to_origin(TARGET, [form], _is_same_origin)

    assert scoped == []
