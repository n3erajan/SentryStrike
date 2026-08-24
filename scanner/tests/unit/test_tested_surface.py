"""Coverage honesty: the tested-surface ledger and the inventory built from it.

The report's "what was tested" section must be a record of requests that
actually went out - never an estimate from discovered surface, and never
inflated by probes the budget governor refused. These tests pin both halves:
the ledger writes only real exchanges, and the aggregation preserves the totals
truthfully (including what it had to leave out).
"""
import pytest

from app.core.scan_orchestration.coverage import (
    MAX_PARAMETERS_PER_PATH,
    MAX_TESTED_PATHS,
    build_tested_surface,
    canonical_detector,
)
from app.utils import scan_metrics
from app.utils.http_logging import log_http_response
from app.utils.scan_metrics import (
    LEDGER_MAX_ENTRIES,
    TestedSurfaceEntry,
    begin_request_counting,
    end_request_counting,
    normalize_tested_path,
    record_tested_surface,
    snapshot_tested_surface,
    tested_surface_totals,
)


@pytest.fixture
def ledger():
    """A live per-scan ledger, torn down after the test."""
    begin_request_counting()
    yield
    end_request_counting()


def _entry(module, method, path, parameter="", requests=1, statuses=(200,), no_response=0):
    return TestedSurfaceEntry(
        module=module,
        method=method,
        path=path,
        parameter=parameter,
        requests=requests,
        status_codes=set(statuses),
        no_response=no_response,
    )


# --------------------------------------------------------------------------
# Ledger
# --------------------------------------------------------------------------


def test_ledger_is_noop_outside_a_scan():
    """No scan context means no ledger - recording must not raise or leak state."""
    record_tested_surface(module="sqli", method="GET", url="http://t/a?x=1")
    assert snapshot_tested_surface() == []
    assert tested_surface_totals() == {
        "total_requests": 0,
        "total_no_response": 0,
        "omitted": 0,
    }


def test_query_string_is_stripped_but_parameter_is_kept(ledger):
    """?id=1 and ?id=2 are one tested surface; the parameter name is what matters."""
    record_tested_surface(module="sqli", method="GET", url="http://t/api/x?id=1", parameter="id")
    record_tested_surface(module="sqli", method="GET", url="http://t/api/x?id=2", parameter="id")

    entries = snapshot_tested_surface()
    assert len(entries) == 1
    assert entries[0].path == "http://t/api/x"
    assert entries[0].parameter == "id"
    assert entries[0].requests == 2


def test_fragment_is_stripped_and_empty_path_normalizes_to_root():
    assert normalize_tested_path("http://t/a/b?q=1#frag") == "http://t/a/b"
    assert normalize_tested_path("http://t") == "http://t/"
    assert normalize_tested_path("") == ""


def test_distinct_detector_method_and_parameter_are_separate_entries(ledger):
    """Coverage is per (detector, method, path, parameter) - none of them collapse."""
    record_tested_surface(module="sqli", method="GET", url="http://t/a", parameter="q")
    record_tested_surface(module="xss", method="GET", url="http://t/a", parameter="q")
    record_tested_surface(module="sqli", method="POST", url="http://t/a", parameter="q")
    record_tested_surface(module="sqli", method="GET", url="http://t/a", parameter="page")

    assert len(snapshot_tested_surface()) == 4


def test_unattributed_requests_are_not_recorded_as_coverage(ledger):
    """A request with no module cannot be claimed as coverage of any detector."""
    record_tested_surface(module="", method="GET", url="http://t/a", parameter="q")
    assert snapshot_tested_surface() == []


def test_no_response_is_tracked_apart_from_answered_probes(ledger):
    """status 0 means sent-but-unanswered; it must not read as a tested-and-clean 200."""
    record_tested_surface(module="sqli", method="GET", url="http://t/a", parameter="q", status_code=200)
    record_tested_surface(module="sqli", method="GET", url="http://t/a", parameter="q", status_code=0)

    entry = snapshot_tested_surface()[0]
    assert entry.requests == 2
    assert entry.no_response == 1
    assert entry.status_codes == {200}
    assert tested_surface_totals()["total_no_response"] == 1


def test_ledger_cap_counts_omissions_instead_of_understating(ledger):
    """Past the entry ceiling the ledger reports how much it left out."""
    for index in range(LEDGER_MAX_ENTRIES + 25):
        record_tested_surface(
            module="sqli", method="GET", url=f"http://t/p{index}", parameter="q", status_code=200
        )

    assert len(snapshot_tested_surface()) == LEDGER_MAX_ENTRIES
    totals = tested_surface_totals()
    assert totals["omitted"] == 25
    # Every request still counts toward the total, capped or not.
    assert totals["total_requests"] == LEDGER_MAX_ENTRIES + 25


def test_log_http_response_feeds_the_ledger(ledger):
    """The single logging chokepoint is what writes coverage, so detectors and raw
    httpx clients are both captured without per-caller wiring."""
    log_http_response(
        "GET",
        "http://t/api/items?id=7",
        200,
        module="sqli",
        parameter="id",
        test_phase="verify",
    )

    entries = snapshot_tested_surface()
    assert len(entries) == 1
    assert (entries[0].module, entries[0].method, entries[0].path, entries[0].parameter) == (
        "sqli",
        "GET",
        "http://t/api/items",
        "id",
    )


@pytest.mark.asyncio
async def test_budget_denied_probe_is_never_recorded_as_tested(ledger):
    """The governor refuses the probe before the network call, so it adds nothing
    to the tested inventory - a denied tail probe is untested, not clean."""
    from app.core.request_governor import begin_governor, end_governor
    from app.core.verification.verification_framework import HttpVerifier

    verifier = HttpVerifier(timeout_seconds=5.0)
    sent = 0

    async def mock_request(**kwargs):
        nonlocal sent
        sent += 1

        class FakeResponse:
            status_code = 200
            reason_phrase = "OK"
            headers = {}
            text = "ok"

            @property
            def url(self):
                return kwargs["url"]

        return FakeResponse()

    client = await verifier.get_client()
    client.request = mock_request  # type: ignore[method-assign]

    begin_governor(per_detector_cap=1, per_parameter_cap=0)
    try:
        admitted = await verifier.send_request(
            "http://t/a", module="sqli", parameter="q", capture_timing=False
        )
        denied = await verifier.send_request(
            "http://t/a", module="sqli", parameter="q", capture_timing=False
        )
    finally:
        end_governor()
        await verifier.close()

    assert admitted.status_code == 200
    assert denied.status_code == -1, "expected the second probe to be budget-denied"
    assert sent == 1, "the denied probe must not reach the network"

    # Only the admitted probe is coverage. The denied one leaves no trace.
    entries = snapshot_tested_surface()
    assert len(entries) == 1
    assert entries[0].requests == 1
    assert entries[0].no_response == 0
    assert tested_surface_totals()["total_requests"] == 1


# --------------------------------------------------------------------------
# Inventory aggregation
# --------------------------------------------------------------------------


def test_module_labels_normalize_to_detector_names():
    """The ledger records the request's module tag; the report names the detector."""
    assert canonical_detector("sqli") == "injection_sql_command"
    assert canonical_detector("lfi") == "file_inclusion"
    assert canonical_detector("auth") == "authentication_failures"
    assert canonical_detector("xss") == "xss"


def test_paths_aggregate_methods_parameters_and_detectors():
    coverage = build_tested_surface(
        [
            _entry("sqli", "GET", "http://t/api/x", "id", requests=3, statuses=(200,)),
            _entry("xss", "GET", "http://t/api/x", "id", requests=2, statuses=(200, 500)),
            _entry("sqli", "POST", "http://t/api/x", "name", requests=1),
        ],
        totals={"total_requests": 6, "total_no_response": 0, "omitted": 0},
    )

    assert coverage.paths_tested == 1
    assert coverage.parameters_tested == 2
    assert coverage.requests_sent == 6
    assert coverage.detectors_exercised == ["injection_sql_command", "xss"]

    path = coverage.tested_paths[0]
    assert path.methods == ["GET", "POST"]
    assert path.detectors == ["injection_sql_command", "xss"]
    assert path.status_codes == [200, 500]
    assert [(p.name, p.requests) for p in path.parameters] == [("id", 5), ("name", 1)]
    assert [p.detectors for p in path.parameters][0] == ["injection_sql_command", "xss"]


def test_paths_answered_only_with_404_are_not_counted_as_tested_surface():
    """Path-guessing detectors probe thousands of candidate URLs. A 404 proves the
    resource is absent, so counting it as a tested path turns a DVWA scan into a
    claimed 2,873-path assessment. Absent paths are counted apart and not listed."""
    entries = [
        # Real surface.
        _entry("sqli", "GET", "http://t/dvwa/vulnerabilities/sqli/", "id", statuses=(200,)),
        # Path-guessing misses.
        *[
            _entry("sensitive_paths", "GET", f"http://t/dvwa/.git/hooks/f{i}", statuses=(404,))
            for i in range(50)
        ],
        # Gone is also absent.
        _entry("sensitive_paths", "GET", "http://t/old", statuses=(410,)),
    ]

    coverage = build_tested_surface(entries)

    assert coverage.paths_tested == 1
    assert coverage.paths_probed_by_detector == 1
    assert coverage.paths_absent == 51
    assert coverage.requests_to_absent_paths == 51
    # The inventory lists the one real path, not the 51 misses.
    assert [path.path for path in coverage.tested_paths] == [
        "http://t/dvwa/vulnerabilities/sqli/"
    ]
    # Requests sent stays the honest total of everything dispatched.
    assert coverage.requests_sent == 52


def test_a_path_that_ever_answered_is_real_even_if_it_also_404s():
    """404 on one probe and 200 on another means the path exists - it must not be
    written off as absent."""
    coverage = build_tested_surface(
        [
            _entry("sqli", "GET", "http://t/api/item", "id", statuses=(404,)),
            _entry("sqli", "GET", "http://t/api/item", "id", statuses=(200,)),
        ]
    )

    assert coverage.paths_tested == 1
    assert coverage.paths_absent == 0


def test_protected_and_erroring_paths_count_as_existing_surface():
    """401/403/405/500 all mean the path exists - auth-gated surface is exactly
    what a reader most needs to see was reached."""
    coverage = build_tested_surface(
        [
            _entry("access_control", "GET", "http://t/admin", statuses=(403,)),
            _entry("access_control", "GET", "http://t/account", statuses=(401,)),
            _entry("sqli", "POST", "http://t/api/x", "q", statuses=(405,)),
            _entry("sqli", "GET", "http://t/api/y", "q", statuses=(500,)),
        ]
    )

    assert coverage.paths_tested == 4
    assert coverage.paths_absent == 0


def test_parameters_on_absent_paths_are_not_counted_as_tested():
    """A parameter injected into a path that does not exist was never tested
    against anything."""
    coverage = build_tested_surface(
        [
            _entry("sqli", "GET", "http://t/real", "id", statuses=(200,)),
            _entry("sqli", "GET", "http://t/ghost", "id", statuses=(404,)),
            _entry("sqli", "GET", "http://t/ghost", "name", statuses=(404,)),
        ]
    )

    assert coverage.parameters_tested == 1


def test_unanswered_paths_are_reported_as_existence_unconfirmed():
    """No response at all establishes nothing either way; such a path is neither
    tested surface nor proven absent."""
    coverage = build_tested_surface(
        [_entry("ssrf", "GET", "http://t/timeout", "url", statuses=(), no_response=3)],
        totals={"total_requests": 3, "total_no_response": 3, "omitted": 0},
    )

    assert coverage.paths_tested == 0
    assert coverage.paths_absent == 0
    assert coverage.paths_existence_unconfirmed == 1
    assert coverage.tested_paths == []


def test_crawler_only_paths_are_listed_but_not_counted_as_probed():
    coverage = build_tested_surface(
        [
            _entry("crawler", "GET", "http://t/about"),
            _entry("crawler", "GET", "http://t/api/x"),
            _entry("sqli", "GET", "http://t/api/x", "id"),
        ]
    )

    assert coverage.paths_tested == 2
    assert coverage.paths_probed_by_detector == 1
    # "crawler" is not a detector and must not be advertised as one.
    assert coverage.detectors_exercised == ["injection_sql_command"]
    about = next(p for p in coverage.tested_paths if p.path.endswith("/about"))
    assert about.detectors == ["crawler"]


def test_requests_without_response_carry_into_the_inventory():
    """An existing path with some unanswered probes keeps the unanswered count, so
    a reader can see the coverage on it is partial."""
    coverage = build_tested_surface(
        [
            _entry("ssrf", "GET", "http://t/fetch", "url", requests=2, statuses=(200,)),
            _entry("ssrf", "GET", "http://t/fetch", "target", requests=4, statuses=(), no_response=4),
        ],
        totals={"total_requests": 6, "total_no_response": 4, "omitted": 0},
    )

    assert coverage.requests_without_response == 4
    assert coverage.paths_tested == 1
    assert coverage.tested_paths[0].no_response == 4
    assert coverage.tested_paths[0].status_codes == [200]


def test_budget_denials_are_reported_alongside_the_inventory():
    coverage = build_tested_surface(
        [_entry("xss", "GET", "http://t/a", "q")], requests_denied_by_budget=41
    )
    assert coverage.requests_denied_by_budget == 41


def test_browser_probes_are_declared_unitemised():
    """Playwright probes bypass the HTTP ledger; the report must say so rather
    than let a reader assume DOM coverage is listed here."""
    assert build_tested_surface([]).browser_probes_itemised is False


def test_path_truncation_keeps_best_covered_and_reports_the_remainder():
    entries = []
    for index in range(MAX_TESTED_PATHS + 7):
        # Give one path many parameters so it must survive the ranking.
        params = 3 if index == 500 else 1
        for param_index in range(params):
            entries.append(_entry("sqli", "GET", f"http://t/p{index}", f"q{param_index}"))

    coverage = build_tested_surface(entries)

    assert coverage.paths_tested == MAX_TESTED_PATHS + 7
    assert len(coverage.tested_paths) == MAX_TESTED_PATHS
    assert coverage.tested_paths_truncated is True
    assert coverage.tested_paths_omitted == 7
    # The richest path is ranked first, so truncation never drops it.
    assert coverage.tested_paths[0].path == "http://t/p500"


def test_parameter_truncation_is_counted_per_path():
    entries = [
        _entry("sqli", "GET", "http://t/wide", f"q{index}")
        for index in range(MAX_PARAMETERS_PER_PATH + 5)
    ]
    coverage = build_tested_surface(entries)

    path = coverage.tested_paths[0]
    assert len(path.parameters) == MAX_PARAMETERS_PER_PATH
    assert path.parameters_omitted == 5
    # The count of what was tested stays whole even when the listing is clipped.
    assert coverage.parameters_tested == MAX_PARAMETERS_PER_PATH + 5


def test_empty_ledger_produces_an_empty_but_valid_inventory():
    coverage = build_tested_surface([])
    assert coverage.paths_tested == 0
    assert coverage.parameters_tested == 0
    assert coverage.requests_sent == 0
    assert coverage.tested_paths == []
    assert coverage.tested_paths_truncated is False


def test_ledger_snapshot_is_a_copy(ledger):
    """Callers must not be able to mutate live scan state through the snapshot."""
    record_tested_surface(module="sqli", method="GET", url="http://t/a", parameter="q")
    snapshot = snapshot_tested_surface()
    snapshot[0].requests = 999
    snapshot[0].status_codes.add(418)

    fresh = snapshot_tested_surface()[0]
    assert fresh.requests == 1
    assert 418 not in fresh.status_codes


def test_end_request_counting_clears_the_ledger():
    begin_request_counting()
    record_tested_surface(module="sqli", method="GET", url="http://t/a")
    assert snapshot_tested_surface()
    end_request_counting()
    assert snapshot_tested_surface() == []
    assert scan_metrics._tested_surface.get() is None
