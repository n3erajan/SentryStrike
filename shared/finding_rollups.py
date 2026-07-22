"""Shared finding statistics and aggregate-risk calculations.

The scanner and backend both mutate scan rollups. Keeping the formula here
prevents a manual review from producing different report numbers than the
initial deterministic scan.
"""

import math

from shared.models.scan import EvidenceStrengthBreakdown, SeverityBreakdown
from shared.models.vulnerability import SeverityLevel, Vulnerability


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
    """Return the existing worst-case-anchored 0-100 risk score and band."""
    active = [vulnerability for vulnerability in vulnerabilities if not vulnerability.is_false_positive]
    if not active:
        return 0.0, _risk_level(0.0)

    tier_weight = {
        SeverityLevel.critical: 1.0,
        SeverityLevel.high: 0.6,
        SeverityLevel.medium: 0.3,
        SeverityLevel.low: 0.1,
        SeverityLevel.info: 0.0,
    }
    breadth_cap = 0.5
    breadth_k = 0.35

    weighted_cvss: list[float] = []
    severity_weight_sum = 0.0
    for vulnerability in active:
        evidence_weight = 1.0 if vulnerability.evidence.verified else 0.7
        weighted_cvss.append(vulnerability.cvss_score * evidence_weight)
        severity_weight_sum += tier_weight.get(vulnerability.severity, 0.3) * evidence_weight

    anchor = max(weighted_cvss) * 10.0
    headroom = 100.0 - anchor
    breadth = headroom * breadth_cap * (
        1.0 - math.exp(-breadth_k * severity_weight_sum)
    )
    score = round(min(100.0, anchor + breadth), 2)
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


def apply_finding_rollups(scan) -> None:
    """Update all finding-derived scan totals in place."""
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
    scan.overall_risk_score, scan.overall_risk_level = calculate_aggregate_risk(
        vulnerabilities
    )
