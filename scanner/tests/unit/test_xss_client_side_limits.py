"""Client-side input limits must not truncate a browser-submitted payload.

DVWA's guestbook name field is ``<input name="txtName" maxlength="10">``. The
browser-driven confirmation path fills the form through the DOM, so Chromium
enforced ``maxlength`` and a 59-character canary payload was stored as
``'<script>wi'``. Nothing executed, the finding was dropped as "browser did not
confirm execution", and a genuine Stored XSS vanished from the report - while the
same payload submitted over HTTP stored and rendered intact.

``maxlength``/``pattern``/``readonly``/``disabled`` are all client-side hints. An
attacker submits the request directly, so verification must too.
"""

import pytest

from app.core.verification.xss_verifier import XSSVerifier

PAYLOAD = "<script>window.sentry_hook('sentryprobe_abc12345')</script>"


class _FakePage:
    """Minimal page that models DOM maxlength enforcement on fill()."""

    def __init__(self, *, maxlength: int | None) -> None:
        self.maxlength = maxlength
        self.value = ""
        self.evaluated: list[str] = []

    async def evaluate(self, script: str, *_args):
        self.evaluated.append(script)
        if "removeAttribute" in script and "maxlength" in script:
            self.maxlength = None
        return None

    async def fill(self, _selector: str, value: str) -> None:
        self.value = value if self.maxlength is None else value[: self.maxlength]


@pytest.mark.asyncio
async def test_fill_is_truncated_while_maxlength_stands():
    """Guard on the fake itself - without the fix the payload really is cut."""
    page = _FakePage(maxlength=10)
    await page.fill("[name=txtName]", PAYLOAD)
    assert page.value == "<script>wi"


@pytest.mark.asyncio
async def test_dropping_limits_preserves_the_payload():
    page = _FakePage(maxlength=10)
    await XSSVerifier._drop_client_side_input_limits(page)
    await page.fill("[name=txtName]", PAYLOAD)

    assert page.value == PAYLOAD, "payload was still truncated after dropping limits"


@pytest.mark.asyncio
async def test_all_client_side_guards_are_dropped():
    page = _FakePage(maxlength=10)
    await XSSVerifier._drop_client_side_input_limits(page)

    script = "\n".join(page.evaluated)
    for attribute in ("maxlength", "pattern", "readonly", "disabled"):
        assert attribute in script, f"{attribute} is not being removed"


@pytest.mark.asyncio
async def test_evaluation_failure_does_not_break_verification():
    """A page that refuses evaluation must not fail the whole check."""

    class _Hostile:
        async def evaluate(self, *_args, **_kwargs):
            raise RuntimeError("execution context destroyed")

    await XSSVerifier._drop_client_side_input_limits(_Hostile())
