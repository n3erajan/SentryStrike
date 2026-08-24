"""Browser form submission must reach the application the way a user does.

Two defects made browser-confirmed XSS on POST forms fail wholesale against a
live target, and both are generic to real-world forms:

1. The fill loop called ``page.fill`` on every named input, including the submit
   button. Playwright raises ``Input of type "submit" cannot be filled`` and,
   with no per-field guard, that aborted the entire verification.

2. Submission used ``form.submit()``, which omits the submit button's name/value
   from the request body. Most handlers gate the write on exactly that key -
   verified live: the POST carrying ``btnSign`` stored the entry, the identical
   POST without it was ignored, so nothing was ever stored to execute.
"""

import pytest

from app.core.verification.xss_verifier import XSSVerifier

PAYLOAD = "<script>window.sentry_hook('sentryprobe_abc12345')</script>"

FORM_INPUTS = [
    {"name": "txtName", "input_type": "text", "value": ""},
    {"name": "mtxMessage", "input_type": "textarea", "value": "hello"},
    {"name": "btnSign", "input_type": "submit", "value": "Sign Guestbook"},
]


class _FakeElement:
    def __init__(self) -> None:
        self.clicked = False

    async def click(self) -> None:
        self.clicked = True


class _FakePage:
    """Models Playwright's refusal to fill non-text inputs."""

    def __init__(self, *, submit_button: bool = True) -> None:
        self.filled: dict[str, str] = {}
        self.evaluated: list[str] = []
        self.button = _FakeElement() if submit_button else None

    async def query_selector(self, selector: str):
        if "submit" in selector or "button" in selector:
            return self.button
        return object()

    async def fill(self, selector: str, value: str) -> None:
        name = selector.split("name='")[1].split("'")[0]
        if name == "btnSign":
            raise ValueError('Input of type "submit" cannot be filled')
        self.filled[name] = value

    async def evaluate(self, script: str, *_args):
        self.evaluated.append(script)
        return None


@pytest.mark.asyncio
async def test_submit_button_does_not_abort_the_fill_loop():
    page = _FakePage()
    verifier = XSSVerifier()
    resolved = {i["name"]: i["value"] for i in FORM_INPUTS}

    await verifier._fill_form_fields(page, resolved, FORM_INPUTS, "txtName", PAYLOAD)

    assert page.filled["txtName"] == PAYLOAD, "the injected field was never filled"
    assert page.filled["mtxMessage"] == "hello", "sibling fields must keep their values"
    assert "btnSign" not in page.filled


@pytest.mark.asyncio
async def test_unfillable_field_types_are_skipped():
    for input_type in ("submit", "reset", "button", "image", "file", "checkbox", "radio"):
        inputs = [{"name": "widget", "input_type": input_type, "value": "x"}]
        assert not XSSVerifier._is_fillable_input(inputs, "widget"), input_type


@pytest.mark.asyncio
async def test_text_like_and_unknown_fields_stay_fillable():
    for input_type in ("text", "textarea", "email", "search", "url", "password", ""):
        inputs = [{"name": "field", "input_type": input_type, "value": ""}]
        assert XSSVerifier._is_fillable_input(inputs, "field"), input_type
    # No recorded type at all - the crawler does not always know one.
    assert XSSVerifier._is_fillable_input(None, "field")


@pytest.mark.asyncio
async def test_injected_field_is_filled_even_if_typed_unfillable():
    """The parameter under test is always filled; skipping it would test nothing."""
    inputs = [{"name": "target", "input_type": "hidden", "value": ""}]
    page = _FakePage()
    verifier = XSSVerifier()

    await verifier._fill_form_fields(page, {"target": ""}, inputs, "target", PAYLOAD)

    assert page.filled["target"] == PAYLOAD


@pytest.mark.asyncio
async def test_submission_clicks_the_button_so_its_name_is_sent():
    page = _FakePage(submit_button=True)

    await XSSVerifier._submit_form(page)

    assert page.button.clicked, "form.submit() omits the button name the handler gates on"
    assert not page.evaluated, "should not fall back to form.submit() when a button exists"


@pytest.mark.asyncio
async def test_submission_falls_back_when_there_is_no_button():
    page = _FakePage(submit_button=False)

    await XSSVerifier._submit_form(page)

    assert any("submit()" in script for script in page.evaluated)
