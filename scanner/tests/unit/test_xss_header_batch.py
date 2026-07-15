"""Batched header-injection XSS: all non-routing headers are probed in a single
request per payload (each with its own canary), and reflection is attributed to
the exact header that carried it.

This replaces the previous one-request-per-(header, payload) fan-out. For the
three batched headers that is a 3x reduction on the direct-reflection probes.
"""
from __future__ import annotations

import html

import pytest

from app.core.detectors.xss_detector import XSSDetector
from app.core.verification.response_analyzer import ResponseData
from app.core.verification.xss_verifier import XSSVerifier

BATCH_HEADERS = ("Referer", "User-Agent", "X-Forwarded-For")


def _resp(body: str, *, json: bool = False) -> ResponseData:
    return ResponseData(
        status_code=200,
        headers={"Content-Type": "application/json"} if json else {"Content-Type": "text/html"},
        body=body,
        response_time_ms=1.0,
        request_snippet="req",
        response_snippet="resp",
    )


def test_build_header_candidates_batches_non_routing_headers():
    detector = XSSDetector()
    candidates = detector._build_header_candidates(["http://t/redirect"])

    methods = [c[2] for c in candidates]
    # Exactly one batched marker carrying the three non-routing headers…
    batch = [m for m in methods if m.startswith("HEADER_BATCH:")]
    assert len(batch) == 1
    assert batch[0] == "HEADER_BATCH:" + ",".join(BATCH_HEADERS)
    # …and X-Original-URL isolated on its own request.
    assert "HEADER:X-Original-URL" in methods
    # No per-header markers for the batched headers.
    assert not any(m == f"HEADER:{h}" for h in BATCH_HEADERS for m in methods)


@pytest.mark.asyncio
async def test_header_batch_one_request_per_payload_carries_all_headers():
    verifier = XSSVerifier()
    verifier.spa_mode = True  # skip stored-replay fan-out; isolate the direct probe
    injection_calls: list[dict] = []

    async def fake_send(url, method="GET", params=None, data=None, *, headers=None,
                        cookies=None, json_body=None, test_phase="", payload=""):
        if headers and any(h in headers for h in BATCH_HEADERS):
            injection_calls.append(dict(headers))
        return _resp("<html><body>clean</body></html>")

    verifier._send = fake_send  # type: ignore[assignment]

    await verifier._verify_header_batch(
        "http://t/redirect", "HEADER_BATCH:" + ",".join(BATCH_HEADERS),
    )

    # One injection request per header payload (3), not one per (header, payload).
    assert len(injection_calls) == len(XSSVerifier.HEADER_PAYLOADS)
    # Every injection request carries all batched headers, each with a distinct
    # canaried payload (attribution depends on the canaries differing).
    for sent in injection_calls:
        for h in BATCH_HEADERS:
            assert h in sent
        values = [sent[h] for h in BATCH_HEADERS]
        assert len(set(values)) == len(values)


@pytest.mark.asyncio
async def test_header_batch_attributes_reflection_to_correct_header():
    verifier = XSSVerifier()
    verifier.spa_mode = True

    async def fake_send(url, method="GET", params=None, data=None, *, headers=None,
                        cookies=None, json_body=None, test_phase="", payload=""):
        if headers and "User-Agent" in headers and headers["User-Agent"].startswith("<"):
            # Only the User-Agent value is reflected (HTML-encoded, non-executable)
            # into an API/JSON response — the other headers are dropped.
            reflected = html.escape(headers["User-Agent"])
            return _resp(f'{{"echo":"{reflected}"}}', json=True)
        return _resp("<html><body>clean</body></html>")

    verifier._send = fake_send  # type: ignore[assignment]

    result = await verifier._verify_header_batch(
        "http://t/redirect", "HEADER_BATCH:" + ",".join(BATCH_HEADERS),
    )

    assert result.is_vulnerable
    params = {f.parameter for f in result.findings}
    assert params == {"User-Agent"}, f"only User-Agent should be flagged, got {params}"
