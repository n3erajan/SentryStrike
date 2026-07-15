from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone

from shared.models.vulnerability import OwaspCategory, SeverityLevel


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
    verification_response_snippet: str | None = field(default=None)  # The relevant response excerpt


class BaseDetector(ABC):
    name: str = "base"

    @abstractmethod
    async def detect(self, urls: list[str], forms: list[object], **kwargs: object) -> list[Finding]:
        raise NotImplementedError
