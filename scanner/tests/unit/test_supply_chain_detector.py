"""Supply-chain findings must reflect what was actually assessed.

Two defects are pinned here. The detector used to fire on any component carrying a
CVE list regardless of whether that list came from a real assessment, and it
defaulted a missing CVSS score to 7.5 - inventing a "high" severity for a CVE
whose score it did not have.
"""

import pytest

from app.core.detectors.supply_chain import SupplyChainDetector
from shared.models.vulnerability import SeverityLevel, TechnologyComponent


async def _detect(*components: TechnologyComponent):
    return await SupplyChainDetector().detect(
        ["https://target.test"], [], technologies=list(components), root_url="https://target.test"
    )


def _assessed(**kwargs) -> TechnologyComponent:
    kwargs.setdefault("cve_assessment", "assessed")
    kwargs.setdefault("cve_source", "nvd-cpe")
    return TechnologyComponent(**kwargs)


# --------------------------------------------------------------------------- #
# Only assessed components produce findings
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_assessed_component_with_cves_produces_a_finding() -> None:
    findings = await _detect(_assessed(
        name="Nginx", version="1.24.0", category="server",
        cves=["CVE-2023-44487"], cve_scores={"CVE-2023-44487": 7.5},
    ))

    assert len(findings) == 1
    assert findings[0].severity == SeverityLevel.high
    assert "CVE-2023-44487" in findings[0].evidence


@pytest.mark.asyncio
async def test_unassessed_component_produces_no_finding_even_with_stale_cves() -> None:
    """A CVE list that no source stands behind must not be reported."""
    findings = await _detect(TechnologyComponent(
        name="PHP", version="8.1", category="language",
        cves=["CVE-2021-41113"], cve_assessment="not_assessed",
        cve_assessment_reason="no CPE mapping for PHP",
    ))

    assert findings == []


@pytest.mark.asyncio
async def test_failed_assessment_produces_no_finding() -> None:
    findings = await _detect(TechnologyComponent(
        name="Nginx", version="1.24.0", category="server",
        cves=["CVE-2023-44487"], cve_assessment="failed",
        cve_assessment_reason="NVD returned HTTP 429",
    ))

    assert findings == []


@pytest.mark.asyncio
async def test_version_less_component_produces_no_finding() -> None:
    findings = await _detect(_assessed(
        name="PHP", version=None, category="language", cves=["CVE-2024-0001"]
    ))

    assert findings == []


@pytest.mark.asyncio
async def test_clean_assessed_component_produces_no_finding() -> None:
    findings = await _detect(_assessed(name="WordPress", version="7.1", category="cms", cves=[]))

    assert findings == []


# --------------------------------------------------------------------------- #
# Severity comes from the real score, never a default
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "score,expected",
    [
        (9.8, SeverityLevel.critical),
        (7.5, SeverityLevel.high),
        (5.0, SeverityLevel.medium),
        (3.1, SeverityLevel.low),
    ],
)
@pytest.mark.asyncio
async def test_severity_is_graded_from_the_cvss_score(score, expected) -> None:
    findings = await _detect(_assessed(
        name="Nginx", version="1.24.0", category="server",
        cves=["CVE-2024-0001"], cve_scores={"CVE-2024-0001": score},
    ))

    assert findings[0].severity == expected


@pytest.mark.asyncio
async def test_missing_score_is_not_invented_as_high() -> None:
    """The old detector defaulted to 7.5, manufacturing a high-severity finding."""
    findings = await _detect(_assessed(
        name="Nginx", version="1.24.0", category="server",
        cves=["CVE-2024-0001"], cve_scores={},
    ))

    assert len(findings) == 1
    assert findings[0].severity == SeverityLevel.medium
    assert "no cvss" in findings[0].evidence.lower()
    assert "7.5" not in findings[0].evidence


# --------------------------------------------------------------------------- #
# Exploitation signals reach the evidence
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_kev_membership_escalates_to_critical_and_is_stated() -> None:
    """Confirmed in-the-wild exploitation outranks the CVSS band."""
    findings = await _detect(_assessed(
        name="Nginx", version="1.24.0", category="server",
        cves=["CVE-2024-0001"], cve_scores={"CVE-2024-0001": 5.0},
        cve_kev=["CVE-2024-0001"],
    ))

    assert findings[0].severity == SeverityLevel.critical
    assert "known exploited" in findings[0].evidence.lower()


@pytest.mark.asyncio
async def test_epss_probability_appears_in_the_evidence() -> None:
    findings = await _detect(_assessed(
        name="Nginx", version="1.24.0", category="server",
        cves=["CVE-2024-0001"], cve_scores={"CVE-2024-0001": 7.5},
        cve_epss={"CVE-2024-0001": 0.787},
    ))

    assert "78.7%" in findings[0].evidence


@pytest.mark.asyncio
async def test_evidence_names_the_source_that_reported_the_cve() -> None:
    """A reader needs to know whether this came from OSV, NVD or Wordfence."""
    findings = await _detect(_assessed(
        name="Express", version="4.18.2", category="framework", cve_source="osv",
        cves=["CVE-2024-43796"], cve_scores={"CVE-2024-43796": 5.0},
    ))

    assert "osv" in findings[0].evidence.lower()


@pytest.mark.asyncio
async def test_findings_are_ordered_most_urgent_first() -> None:
    findings = await _detect(_assessed(
        name="Nginx", version="1.24.0", category="server",
        cves=["CVE-2024-LOW", "CVE-2024-KEV", "CVE-2024-HIGH"],
        cve_scores={"CVE-2024-LOW": 3.0, "CVE-2024-KEV": 5.0, "CVE-2024-HIGH": 9.1},
        cve_kev=["CVE-2024-KEV"],
    ))

    assert [f.severity for f in findings] == [
        SeverityLevel.critical, SeverityLevel.critical, SeverityLevel.low
    ]
    assert "CVE-2024-KEV" in findings[0].evidence
