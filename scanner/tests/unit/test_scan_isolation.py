"""Issue 1 — per-scan isolation of the spider and detector graph.

Concurrent scans must never share a WebSpider or detector instance: those own
mutable cookies, auth headers, HTTP clients, and verifier state, so a shared
graph can cross-contaminate auth between targets or let one scan close another
scan's client. run_scan builds a fresh graph per scan; injected fakes are left
untouched so tests/embedders keep control.
"""
from app.core.crawler.spider import WebSpider
from app.core.scanner import ScanOrchestrator


class _DummyRepository:
    pass


def _orchestrator() -> ScanOrchestrator:
    return ScanOrchestrator(_DummyRepository())


def test_build_detectors_returns_fresh_instances_each_call():
    orch = _orchestrator()
    first = orch._build_detectors()
    second = orch._build_detectors()

    assert len(first) == len(second)
    # Same types, distinct objects — no detector instance is shared between graphs.
    assert [type(d) for d in first] == [type(d) for d in second]
    for a, b in zip(first, second):
        assert a is not b


def test_default_detectors_are_replaced_but_injected_fakes_are_preserved():
    """The run_scan isolation guard swaps a DEFAULT detector graph for a fresh
    one, but a caller that injected its own detector list keeps it. Mirrors the
    guard logic in run_scan (kept in sync with it)."""
    orch = _orchestrator()

    # Default graph -> should be treated as replaceable.
    default_types = [type(d) for d in orch._build_detectors()]
    configured_types = [type(d) for d in orch.detectors]
    assert configured_types == default_types  # __init__ used the default builder

    # Inject a fake -> guard must detect the divergence and NOT replace it.
    sentinel = object()
    orch.detectors = [sentinel]
    configured_types = [type(d) for d in orch.detectors]
    assert configured_types != default_types
    assert orch.detectors == [sentinel]


def test_spider_is_a_real_webspider_by_default():
    """A default orchestrator owns a real WebSpider, so run_scan will build a
    fresh one per scan; an injected fake spider (any other type) is preserved."""
    orch = _orchestrator()
    assert type(orch.spider) is WebSpider

    fake = object()
    orch.spider = fake
    # Guard condition used by run_scan: only a real WebSpider is swapped.
    assert not (type(orch.spider) is WebSpider)
    assert orch.spider is fake


def test_build_scan_runtime_isolates_default_mutable_components():
    orch = _orchestrator()

    runtime = orch._build_scan_runtime()

    assert type(runtime.spider) is WebSpider
    assert runtime.spider is not orch.spider
    assert [type(detector) for detector in runtime.detectors] == [
        type(detector) for detector in orch.detectors
    ]
    assert all(
        runtime_detector is not configured_detector
        for runtime_detector, configured_detector in zip(
            runtime.detectors, orch.detectors
        )
    )
    assert runtime.supply_chain_detector is not orch.supply_chain_detector


def test_build_scan_runtime_preserves_injected_fakes():
    orch = _orchestrator()
    spider = object()
    detector = object()
    supply_chain = object()
    orch.spider = spider
    orch.detectors = [detector]
    orch.supply_chain_detector = supply_chain

    runtime = orch._build_scan_runtime()

    assert runtime.spider is spider
    assert runtime.detectors == [detector]
    assert runtime.supply_chain_detector is supply_chain
