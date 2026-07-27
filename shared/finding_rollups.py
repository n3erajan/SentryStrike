"""Shared finding statistics and aggregate-risk calculations.

The scanner and backend both mutate scan rollups. Keeping the formula here
prevents a manual review from producing different report numbers than the
initial deterministic scan.
"""

import math

from shared.models.scan import EvidenceStrengthBreakdown, SeverityBreakdown
from shared.models.vulnerability import EvidenceStrength, SeverityLevel, Vulnerability


def _risk_level(score: float) -> str:
    cvss_equivalent = score / 10.0
    if cvss_equivalent >= 9.0:
        return "Critical"
    if cvss_equivalent >= 7.0:
        return "High"
    if cvss_equivalent >= 4.0:
        return "Medium"
    if cvss_equivalent > 0.0:
        return "Low"
    return "Info"


def calculate_aggregate_risk(
    vulnerabilities: list[Vulnerability],
) -> tuple[float, str]:
    """Return an immutable, evidence-adjusted snapshot of detected scan risk.

    Every finding produced by the scanner participates, including findings that a
    user later marks as false positive. The worst finding anchors the score and
    additional findings move it toward (but never into) the next severity band.
    """
    if not vulnerabilities:
        return 0.0, _risk_level(0.0)

    evidence_weight = {
        EvidenceStrength.confirmed_exploit: 1.0,
        EvidenceStrength.confirmed_observation: 0.9,
        EvidenceStrength.probable: 0.7,
        EvidenceStrength.possible: 0.4,
        EvidenceStrength.informational: 0.0,
    }
    breadth_weight = {
        SeverityLevel.critical: 1.0,
        SeverityLevel.high: 0.6,
        SeverityLevel.medium: 0.3,
        SeverityLevel.low: 0.1,
        SeverityLevel.info: 0.0,
    }

    adjusted_scores = [
        vulnerability.cvss_score
        * 10.0
        * evidence_weight.get(vulnerability.evidence_strength, 0.4)
        for vulnerability in vulnerabilities
    ]
    anchor_index = max(range(len(adjusted_scores)), key=adjusted_scores.__getitem__)
    anchor = adjusted_scores[anchor_index]
    if anchor <= 0.0:
        return 0.0, _risk_level(0.0)

    # Non-critical ceilings are exclusive. Keeping one hundredth of a point of
    # space also prevents two-decimal rounding from changing the severity band.
    if anchor < 40.0:
        band_ceiling = 39.99
    elif anchor < 70.0:
        band_ceiling = 69.99
    elif anchor < 90.0:
        band_ceiling = 89.99
    else:
        band_ceiling = 100.0

    additional_weight = sum(
        breadth_weight.get(vulnerability.severity, 0.3)
        * evidence_weight.get(vulnerability.evidence_strength, 0.4)
        for index, vulnerability in enumerate(vulnerabilities)
        if index != anchor_index
    )
    breadth = (band_ceiling - anchor) * (
        1.0 - math.exp(-0.5 * additional_weight)
    )
    score = round(min(band_ceiling, anchor + breadth), 2)
    return score, _risk_level(score)


def evidence_strength_breakdown(
    vulnerabilities: list[Vulnerability],
) -> EvidenceStrengthBreakdown:
    counts = EvidenceStrengthBreakdown()
    for vulnerability in vulnerabilities:
        if vulnerability.is_false_positive:
            continue
        strength = getattr(
            vulnerability.evidence_strength,
            "value",
            str(vulnerability.evidence_strength),
        )
        if hasattr(counts, strength):
            setattr(counts, strength, getattr(counts, strength) + 1)
    return counts


def severity_breakdown(vulnerabilities: list[Vulnerability]) -> SeverityBreakdown:
    counts = SeverityBreakdown()
    field_by_severity = {
        SeverityLevel.critical: "critical",
        SeverityLevel.high: "high",
        SeverityLevel.medium: "medium",
        SeverityLevel.low: "low",
        SeverityLevel.info: "info",
    }
    for vulnerability in vulnerabilities:
        if vulnerability.is_false_positive:
            continue
        field = field_by_severity[vulnerability.severity]
        setattr(counts, field, getattr(counts, field) + 1)
    return counts


def apply_finding_statistics(scan) -> None:
    """Update mutable finding-review statistics without changing scan risk."""
    vulnerabilities = list(scan.vulnerabilities)
    active_count = sum(not vulnerability.is_false_positive for vulnerability in vulnerabilities)

    scan.statistics.total_vulnerabilities = len(vulnerabilities)
    scan.statistics.active_vulnerabilities = active_count
    scan.statistics.suppressed_vulnerabilities = len(vulnerabilities) - active_count
    scan.statistics.severity_breakdown = severity_breakdown(vulnerabilities)
    if getattr(scan, "report_metadata", None) is not None:
        scan.report_metadata.evidence_strength_breakdown = evidence_strength_breakdown(
            vulnerabilities
        )


def apply_finding_rollups(scan) -> None:
    """Finalize finding statistics and the immutable scan-completion risk snapshot."""
    vulnerabilities = list(scan.vulnerabilities)
    apply_finding_statistics(scan)
    scan.overall_risk_score, scan.overall_risk_level = calculate_aggregate_risk(
        vulnerabilities
    )
