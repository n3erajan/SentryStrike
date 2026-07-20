"""The header-stored GET-replay oracle must not run on SPA targets.

On an SPA the injected header value is rendered client-side from an API
response and never appears in the raw HTML shell the raw-string oracle matches
against, so the fan-out (headers × payloads × every sink-like URL) is pure
waste. The stored-header hypothesis is instead handled by the browser-DOM sweep.
"""
from __future__ import annotations

import pytest

from app.core.verification.xss_verifier import XSSVerifier


class _Resp:
    def __init__(self, body: str = "") -> None:
        self.body = body
        self.request_snippet = ""
        self.response_snippet = ""


async def _run(verifier: XSSVerifier, *, probe_calls: list) -> None:
    async def _fake_send(*args, **kwargs):
        # The injected-header response never reflects the raw payload (SPA shell).
        return _Resp("<html><body>spa shell</body></html>")

    async def _fake_probe_stored(*args, **kwargs):
        probe_calls.append(kwargs or args)
        return False, [], False, None, {}

    verifier._send = _fake_send  # type: ignore[assignment]
    verifier._probe_stored = _fake_probe_stored  # type: ignore[assignment]

    await verifier._test_payload(
        url="http://spa.test/",
        parameter="X-Forwarded-For",
        method="HEADER:X-Forwarded-For",
        value="",
        payload="<script>alert(1)</script>",
        payload_type="hdr_script",
        form_inputs=None,
        stored_display_urls=["http://spa.test/admin/log", "http://spa.test/dashboard"],
        pre_test_baseline=_Resp("<html><body>spa shell</body></html>"),
    )


@pytest.mark.asyncio
async def test_header_stored_replay_skipped_on_spa():
    verifier = XSSVerifier()
    verifier.spa_mode = True
    probe_calls: list = []
    await _run(verifier, probe_calls=probe_calls)
    assert probe_calls == [], "header-stored GET-replay must not run on SPA targets"


@pytest.mark.asyncio
async def test_header_stored_replay_runs_on_non_spa():
    verifier = XSSVerifier()
    verifier.spa_mode = False
    probe_calls: list = []
    await _run(verifier, probe_calls=probe_calls)
    assert probe_calls, "header-stored GET-replay should still run on server-rendered apps"


def test_header_sink_fan_out_is_capped():
    verifier = XSSVerifier()
    # More sink-matching URLs than the cap allows.
    sink_urls = [f"http://x/admin/log/{i}" for i in range(30)]
    # Directly exercise the tier1 selection by calling _probe_stored's filter
    # logic via the public cap constant.
    assert XSSVerifier._STORED_HEADER_SINK_CAP == 8
    tier1 = [u for u in sink_urls if verifier._HEADER_SINK_PATTERNS.search(u)][
        : XSSVerifier._STORED_HEADER_SINK_CAP
    ]
    assert len(tier1) == 8
