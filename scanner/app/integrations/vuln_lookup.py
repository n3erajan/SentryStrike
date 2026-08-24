"""The shared result type for every vulnerability-intelligence source.

An empty CVE list is ambiguous: it can mean "this version has no known
vulnerabilities", "we had no way to look it up", or "the lookup failed". The
original code collapsed all three into ``[]``, so a rate-limited NVD request and
a genuinely clean component were indistinguishable in the report. Every source
returns a :class:`VulnLookup` instead, which keeps them apart.
"""

from dataclasses import dataclass, field

# Assessment outcomes, mirrored onto ``TechnologyComponent.cve_assessment``.
ASSESSED = "assessed"
NOT_ASSESSED = "not_assessed"
FAILED = "failed"


@dataclass
class VulnLookup:
    """The outcome of one component's vulnerability lookup.

    ``status`` is one of :data:`ASSESSED` (we queried a source that covers this
    component and this is the answer), :data:`NOT_ASSESSED` (no source could
    identify it - typically a missing version or no CPE/package mapping) or
    :data:`FAILED` (a source was queried and errored).
    """

    status: str
    reason: str | None = None
    source: str | None = None
    cves: list[dict] = field(default_factory=list)

    @classmethod
    def assessed(cls, source: str, cves: list[dict]) -> "VulnLookup":
        return cls(status=ASSESSED, source=source, cves=cves)

    @classmethod
    def not_assessed(cls, reason: str) -> "VulnLookup":
        return cls(status=NOT_ASSESSED, reason=reason)

    @classmethod
    def failed(cls, source: str, reason: str) -> "VulnLookup":
        return cls(status=FAILED, source=source, reason=reason)

    @property
    def cve_ids(self) -> list[str]:
        return [c["cve_id"] for c in self.cves if c.get("cve_id")]

    @property
    def scores(self) -> dict[str, float]:
        return {
            c["cve_id"]: c["severity_score"]
            for c in self.cves
            if c.get("cve_id") and c.get("severity_score") is not None
        }
