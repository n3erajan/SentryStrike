"""Guards for the event-loop stall that made healthy scans get reaped.

A boolean-SQLi differential ran three ``difflib.SequenceMatcher`` comparisons
over full response bodies. On 350 KB of real page content a single call measured
505s, so one differential was minutes of uninterruptible CPU on the event loop.
That starved the scan worker's lease-renewal task past its TTL, the backend
reconciled the scan as orphaned, and the UI reported "Scan worker stopped
unexpectedly" while the worker was still happily running.

These tests pin the three properties that fix it and keep it fixed:
bounded cost, whole-document sensitivity, and no event-loop blocking.
"""

import asyncio
import random
import threading
import time
from unittest import mock
from zlib import crc32

import pytest

from app.core.verification.response_analyzer import (
    ResponseAnalyzer,
    ResponseData,
    _chunk_modulus,
    _content_defined_chunks,
)


def realistic_body(seed: int, size: int) -> str:
    """Varied markup of roughly ``size`` chars.

    Deliberately not repetitive filler: ``SequenceMatcher``'s ``autojunk``
    heuristic makes degenerate repeated content fast, which would hide the very
    regression these tests exist to catch.
    """
    rng = random.Random(seed)
    words = [
        "".join(rng.choices("abcdefghijklmnopqrstuvwxyz", k=rng.randint(3, 12)))
        for _ in range(2000)
    ]
    out: list[str] = []
    total = 0
    while total < size:
        chunk = f"<p class='{rng.choice(words)}'>{' '.join(rng.choices(words, k=12))}</p>"
        out.append(chunk)
        total += len(chunk)
    return "".join(out)[:size]


def _response(body: str, status: int = 200) -> ResponseData:
    return ResponseData(status_code=status, headers={}, body=body, response_time_ms=1.0)


LARGE = 350_000


def test_chunking_bounds_the_element_count():
    body = realistic_body(1, LARGE)
    chunks = _content_defined_chunks(body, _chunk_modulus(len(body), len(body)))

    # Cost is O(chunks^2); the whole point is that this does not grow with page
    # size. A few thousand elements is fine, hundreds of thousands is not.
    assert 100 < len(chunks) < 6000, f"{len(chunks)} chunks - is the count still unbounded?"
    # Compare lengths and a checksum rather than the strings themselves: a failed
    # equality assertion on two 350 KB values takes pytest minutes to render.
    rejoined = "".join(chunks)
    assert len(rejoined) == len(body), "chunking dropped content"
    assert crc32(rejoined.encode()) == crc32(body.encode()), "chunking altered content"


def test_chunk_boundaries_are_deterministic_across_calls():
    """Evidence must be reproducible, so boundaries cannot depend on PYTHONHASHSEED."""
    body = realistic_body(2, 50_000)
    modulus = _chunk_modulus(len(body), len(body))
    assert _content_defined_chunks(body, modulus) == _content_defined_chunks(body, modulus)


def test_similarity_is_fast_on_large_bodies():
    """The unbounded version took 505s per call. Threshold is loose on purpose:
    it only has to fail if the quadratic character comparison comes back."""
    baseline = realistic_body(1, LARGE)
    other = realistic_body(2, LARGE)  # worst case: nothing matches

    start = time.perf_counter()
    ratio = ResponseAnalyzer.calculate_similarity(baseline, other)
    elapsed = time.perf_counter() - start

    assert 0.0 <= ratio <= 1.0
    assert elapsed < 5.0, f"similarity took {elapsed:.1f}s - is the input still unbounded?"


def test_similarity_detects_a_mid_page_block_change():
    """The regression a head/tail window would introduce.

    Boolean-blind SQLi toggles a content block in the middle of the page. If the
    comparison only looks at the head and tail, that reads as 1.0 (identical) and
    the TRUE/FALSE separation the detector needs disappears entirely.
    """
    baseline = realistic_body(1, LARGE)
    half = len(baseline) // 2
    block_removed = baseline[:half] + baseline[half + 4000 :]

    ratio = ResponseAnalyzer.calculate_similarity(baseline, block_removed)
    assert ratio < 1.0, "a mid-page block change must register as a difference"


def test_similarity_tolerates_a_small_insertion_anywhere():
    """The regression fixed-offset chunking would introduce.

    A per-request nonce or CSRF token near the top of the page shifts every later
    offset. Under fixed-offset chunking that scored 0.0 - an ordinary page would
    look "completely different" and wreck the noise calibration that the boolean
    thresholds are measured against.
    """
    baseline = realistic_body(1, LARGE)
    half = len(baseline) // 2
    nonce = realistic_body(99, 200)

    for label, mutated in (
        ("head", nonce + baseline),
        ("middle", baseline[:half] + nonce + baseline[half:]),
        ("tail", baseline + nonce),
    ):
        ratio = ResponseAnalyzer.calculate_similarity(baseline, mutated)
        assert ratio > 0.95, f"a 200-char {label} insertion scored {ratio:.4f} - shift intolerant"
        assert ratio < 1.0, f"a 200-char {label} insertion must still register"


def test_similarity_keeps_identical_and_disjoint_verdicts():
    body = realistic_body(1, LARGE)
    assert ResponseAnalyzer.calculate_similarity(body, body) == pytest.approx(1.0)
    assert ResponseAnalyzer.calculate_similarity("", "") == pytest.approx(1.0)
    assert ResponseAnalyzer.calculate_similarity("abc", "") == pytest.approx(0.0)


def test_small_bodies_keep_exact_character_similarity():
    """Short bodies are the common case and stay maximally precise."""
    assert ResponseAnalyzer.calculate_similarity("hello world", "hello worlt") == pytest.approx(
        20 / 22
    )


@pytest.mark.asyncio
async def test_async_boolean_differential_matches_sync_result():
    baseline = _response(realistic_body(1, 20_000))
    true_resp = _response(realistic_body(1, 20_000))
    false_resp = _response(realistic_body(2, 20_000))

    sync_verdict, sync_analysis = ResponseAnalyzer.analyze_boolean_differential(
        baseline, true_resp, false_resp
    )
    async_verdict, async_analysis = await ResponseAnalyzer.analyze_boolean_differential_async(
        baseline, true_resp, false_resp
    )

    assert sync_verdict == async_verdict
    assert sync_analysis == async_analysis


@pytest.mark.asyncio
async def test_similarity_async_runs_off_the_calling_thread():
    """The offload guard, stated precisely.

    Bounding the comparison made it fast, but "fast" is not "interruptible": the
    lease-renewal task can only run when the event loop thread is free. Assert
    the computation happens on a worker thread so any future growth in the
    comparison cost cannot stall the loop again.
    """
    seen: dict[str, int] = {}
    real = ResponseAnalyzer.calculate_similarity

    def recording(text1: str, text2: str) -> float:
        seen["thread"] = threading.get_ident()
        return real(text1, text2)

    with mock.patch.object(ResponseAnalyzer, "calculate_similarity", recording):
        await ResponseAnalyzer.calculate_similarity_async("alpha beta", "alpha gamma")

    assert seen["thread"] != threading.get_ident(), "similarity still runs on the event loop thread"


@pytest.mark.asyncio
async def test_event_loop_keeps_running_during_a_slow_comparison():
    """A slow comparison must not freeze the lease-renewal timer.

    ``scanner.app.worker._lease_loop`` is an ``asyncio.sleep`` loop that only
    advances when the event loop is free; when the comparison ran inline the loop
    froze for its entire duration and the lease expired mid-scan. The payload here
    is a deliberately slow stand-in rather than a real body, so the guard holds
    whatever the real comparison happens to cost.
    """
    def slow_similarity(text1: str, text2: str) -> float:
        deadline = time.perf_counter() + 0.6
        total = 0
        while time.perf_counter() < deadline:
            total += sum(ord(c) for c in text1)  # pure-Python CPU, releases the GIL
        return 1.0 if total else 0.0

    ticks = 0
    stop = False

    async def ticker() -> None:
        nonlocal ticks
        while not stop:
            ticks += 1
            await asyncio.sleep(0.01)

    ticker_task = asyncio.create_task(ticker())
    await asyncio.sleep(0.05)  # let the ticker get going
    ticks_before = ticks

    with mock.patch.object(ResponseAnalyzer, "calculate_similarity", slow_similarity):
        await ResponseAnalyzer.calculate_similarity_async("a" * 500, "b" * 500)

    ticks_during = ticks - ticks_before
    stop = True
    ticker_task.cancel()
    try:
        await ticker_task
    except asyncio.CancelledError:
        pass

    # ~0.6s of work at a 10ms tick would be ~60 ticks if the loop stays live, and
    # 0-1 if it is blocked. Assert well clear of the blocked case.
    assert ticks_during > 10, (
        f"only {ticks_during} ticks ran during a 0.6s comparison - "
        "the work is blocking the event loop again"
    )
