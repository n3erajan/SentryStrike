from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone

from shared.models.vulnerability import OwaspCategory, SeverityLevel

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone

from shared.models.vulnerability import OwaspCategory, SeverityLevel
from shared.utils.evidence import server_response_bytes


def observed_response_body(finding: "Finding") -> str:
    """Return only the bytes the TARGET sent, never the scanner's own narrative.

    Harvester detectors (exception handling, credential disclosure) mine other
    findings' responses for secondary disclosures. That is only sound while the
    text is server-origin: a scanner-authored line naming an internal IP,
    hostname, or error string would otherwise be reported as the application
    disclosing it.

    This happened in production. The SSRF detector wrote its OAST narrative into
    `verification_response_snippet`, including the collaborator's record of the
    callback source IP (the Docker bridge gateway, 172.20.0.1). The exception
    handler matched its private-IP pattern against that line and raised a
    "Verbose Error Handling" finding for a response that contained no error --
    then inherited SSRF's url, method, payload and request snippet, so no field
    on the finding agreed with any other.

    Writers now keep narrative in `evidence`, which the report layer already
    renders. This stays as a backstop: when a composite is detected, the text
    after the server-response marker is returned, and a composite with no marker
    yields "" rather than prose a harvester would mistake for target output. The
    preamble/marker lists and the extraction itself live in
    ``shared.utils.evidence`` so the analyzer service reuses the exact same rule.
    """
    return server_response_bytes(finding.verification_response_snippet)


@dataclass
class Finding:
    category: OwaspCategory
    vuln_type: str
    severity: SeverityLevel
    url: str
    parameter: str | None = None
    # All vulnerable parameters on this (route, vuln-type) after deduplication grouping.
    # Populated by FindingDeduplicator; the single `parameter` above stays as the primary
    # (highest-confidence) one for backward compatibility.
    affected_parameters: list[str] = field(default_factory=list)
    method: str = "GET"
    payload: str | None = None
    evidence: str | None = None
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Active verification fields
    confidence_score: float = field(default=0.0)  # 0-100, where 100 is confirmed exploitation
    detection_method: str = field(default="heuristic")  # heuristic/boolean/error/time/union/reflection/command_output
    response_diff: str | None = field(default=None)  # Summary of response differences
    reproducible: bool = field(default=False)  # Whether finding can be reliably reproduced
    response_time_ms: float = field(default=0.0)  # For timing-based detection
    detection_evidence: dict = field(default_factory=dict)  # Detailed metadata: baseline_resp, injected_resp, timing_data, error_patterns, etc.
    verified: bool = field(default=False)  # Distinguish confirmed vs suspected
    verification_request_snippet: str | None = field(default=None)  # The actual HTTP request sent
    # SERVER BYTES ONLY. Narrative belongs in `evidence`; the report layer
    # composes the two. See `observed_response_body` for why this matters.
    verification_response_snippet: str | None = field(default=None)


class BaseDetector(ABC):
    name: str = "base"

    @abstractmethod
    async def detect(self, urls: list[str], forms: list[object], **kwargs: object) -> list[Finding]:
        raise NotImplementedError
