"""Aggregate risk-score model: max-anchored + bounded severity-weighted breadth.

Standards-aligned properties under test (CVSS base scores must not be averaged —
averaging dilutes the worst finding, and an attacker only needs one):
  * the worst finding anchors the score and is never diluted by lower-severity noise
  * additional findings add bounded, saturating, severity-weighted breadth
  * unverified findings weigh less; the score is bounded to 100
"""

from uuid import uuid4

from app.core.scanner import ScanOrchestrator
from app.models.vulnerability import (
    Evidence,
    LocationInfo,
    OwaspCategory,
    SeverityLevel,
    Vulnerability,
)

C, H, M, L = (
    SeverityLevel.critical,
    SeverityLevel.high,
    SeverityLevel.medium,
    SeverityLevel.low,
)


def mk(cvss: float, severity: SeverityLevel, verified: bool = True, fp: bool = False) -> Vulnerability:
    return Vulnerability(
        id=str(uuid4()),
        category=OwaspCategory.a05,
        vuln_type="SQL Injection (Error-Based)",
        severity=severity,
        cvss_score=cvss,
        location=LocationInfo(url="http://target.test/"),
        evidence=Evidence(verified=verified),
        is_false_positive=fp,
    )


def agg(vulns):
    return ScanOrchestrator._calculate_aggregate_risk(vulns)


def test_empty_is_zero_info() -> None:
    assert agg([]) == (0.0, "Info")


def test_all_false_positives_scored_zero() -> None:
    assert agg([mk(9.1, C, fp=True), mk(8.0, H, fp=True)]) == (0.0, "Info")


def test_worst_finding_is_not_diluted_by_low_severity_noise() -> None:
    """The core fix: one confirmed Critical among 20 mediums must stay Critical.
    A simple average would drag it into the Medium band; max-anchoring must not."""
    score_solo, band_solo = agg([mk(9.1, C)])
    score_noisy, band_noisy = agg([mk(9.1, C)] + [mk(5.0, M)] * 20)

    assert band_solo == "Critical"
    assert band_noisy == "Critical"
    # Noise only adds breadth on top of the anchor — it can never lower the score.
    assert score_noisy >= score_solo
    assert score_noisy >= 90.0


def test_discriminates_presence_of_a_critical() -> None:
    """Same breadth of findings scores lower without a Critical (High) than with one
    (Critical) — the old averaging-times-volume formula saturated both near 100."""
    no_crit = [mk(8.0, H)] * 8 + [mk(5.5, M)] * 13 + [mk(2.5, L)] * 4
    with_crit = [mk(9.1, C), mk(9.1, C)] + no_crit

    s_nc, b_nc = agg(no_crit)
    s_c, b_c = agg(with_crit)

    assert b_nc == "High" and s_nc < 90.0
    assert b_c == "Critical" and s_c > s_nc


def test_report_scenario_stays_critical_for_the_right_reason() -> None:
    """Regression pin for the real report (2 confirmed critical SQLi + 6H/13M/4L):
    still Critical (~95), now anchored by the confirmed critical rather than a
    coincidentally-high diluted average."""
    vulns = (
        [mk(9.1, C), mk(9.1, C)]
        + [mk(7.5, H)] * 6
        + [mk(5.5, M)] * 13
        + [mk(2.5, L)] * 4
    )
    score, band = agg(vulns)
    assert band == "Critical"
    assert 94.0 <= score <= 97.0


def test_unverified_findings_weigh_less() -> None:
    s_verified, _ = agg([mk(9.1, C, verified=True)])
    s_unverified, b_unverified = agg([mk(9.1, C, verified=False)])

    assert s_unverified < s_verified
    # A lone unverified Critical must not read as a maxed-out Critical.
    assert b_unverified != "Critical"


def test_breadth_is_severity_weighted_at_a_fixed_anchor() -> None:
    """Holding the anchor constant, medium-severity breadth outweighs low-severity
    breadth of the same count (Critical > High > Medium > Low breadth weights)."""
    anchor = mk(8.0, H)
    s_mediums, _ = agg([anchor] + [mk(5.5, M)] * 10)
    s_lows, _ = agg([anchor] + [mk(2.5, L)] * 10)

    assert s_mediums > s_lows


def test_score_is_bounded_to_100() -> None:
    score, band = agg([mk(10.0, C)] * 50)
    assert score <= 100.0
    assert band == "Critical"
