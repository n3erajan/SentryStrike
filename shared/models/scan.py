from datetime import datetime, timezone
from enum import Enum

from beanie import Document, Indexed
from pydantic import BaseModel, Field

from shared.models.vulnerability import TechnologyComponent, Vulnerability


class ScanStatus(str, Enum):
    """Lifecycle state of a scan from submission to a terminal state."""

    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class ScanPhase(str, Enum):
    """Fine-grained pipeline stage reported to the user while a scan runs."""

    queued = "queued"
    initializing = "initializing"
    crawling = "crawling"
    technology_detection = "technology_detection"
    tls_analysis = "tls_analysis"
    vulnerability_detection = "vulnerability_detection"
    deduplication = "deduplication"
    ai_analysis = "ai_analysis"
    risk_scoring = "risk_scoring"
    report_generation = "report_generation"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class CrawlMode(str, Enum):
    """Determines how deeply the crawler traverses the target."""

    full = "full"
    single = "single"


class ScanAuthRole(str, Enum):
    """Semantic label for a test-account slot within a scan."""

    main = "main"
    second = "second"
    admin = "admin"


class ScanAuthAccount(BaseModel):
    """A test account supplied at scan submission for authenticated / IDOR testing.

    The backend places this DTO in the Redis job payload as plaintext. ``BLPOP``
    removes that payload when a worker claims it, after which the credentials
    remain only in worker memory. The Scan document persists only the non-secret
    ``auth_roles_provided`` marker.
    """

    role: ScanAuthRole
    username: str | None = None
    password: str | None = None
    cookie: str | None = None
    header: str | None = None


class SeverityBreakdown(BaseModel):
    """Count of findings per severity level for a scan."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ScanStatistics(BaseModel):
    """Aggregate counts and summary metrics for a completed scan."""

    total_urls_crawled: int = 0
    total_vulnerabilities: int = 0
    severity_breakdown: SeverityBreakdown = Field(default_factory=SeverityBreakdown)


class SpaApiCoverage(BaseModel):
    """Metrics collected during SPA crawling and API extraction."""

    spa_detected: bool = False
    js_assets_inspected: int = 0
    routes_extracted: int = 0
    api_endpoints_extracted: int = 0
    parameters_extracted: int = 0
    browser_requests_observed: int = 0
    dead_spa_fallback_routes_suppressed: int = 0
    static_spa_only: bool = False
    browser_available: bool | None = None
    browser_error: str | None = None
    replayable_json_bodies: int = 0
    observed_json_body_targets: int = 0
    observed_form_body_targets: int = 0
    static_synth_body_targets: int = 0
    # Replayable PUT/PATCH targets derived from an observed create (POST) via REST
    # convention (create → update) using the real server-assigned id.
    derived_update_body_targets: int = 0
    skipped_unresolved_body_targets: int = 0
    post_bodies: int = 0
    workflow_states_visited: int = 0
    browser_forms_discovered: int = 0
    browser_forms_submitted: int = 0
    file_inputs_discovered: int = 0
    # Overall dynamic-discovery health for honest reporting:
    # dynamic_ok | dynamic_partial | dynamic_failed.
    dynamic_status: str = "dynamic_ok"


class AuthCoverage(BaseModel):
    """Describes what the scanner achieved with the supplied credentials."""

    state: str = "unauthenticated"
    authenticated_url_count: int = 0
    unauthenticated_url_count: int = 0
    protected_targets_verified: int = 0
    auth_headers_present: bool = False
    session_cookies_present: bool = False


class EvidenceStrengthBreakdown(BaseModel):
    """Count of findings grouped by evidence strength."""

    confirmed_exploit: int = 0
    confirmed_observation: int = 0
    probable: int = 0
    possible: int = 0
    informational: int = 0


class DetectorCoverageMetric(BaseModel):
    """Per-detector statistics recorded during the scan for the report."""

    detector: str
    candidates_built: int = 0
    candidates_filtered: int = 0
    requests_sent: int = 0
    targets_attempted: int = 0
    requests_denied_by_governor: int = 0
    verified_findings: int = 0
    unverified_findings: int = 0
    dropped_findings_verified_mode: int = 0
    replayable_targets_seen: int = 0
    replayable_targets_tested: int = 0
    validated_synth_targets_tested: int = 0
    body_targets_skipped: int = 0
    body_targets_skipped_by_reason: dict[str, int] = Field(default_factory=dict)
    skip_reason_by_risk: dict[str, int] = Field(default_factory=dict)
    skipped_reasons: dict[str, int] = Field(default_factory=dict)


class AttackChain(BaseModel):
    """A multi-step exploitation path that chains individual findings."""

    id: str
    description: str
    vulnerability_ids: list[str]
    severity: str


class ReportMetadata(BaseModel):
    """Metadata about the generated report and coverage quality."""

    generated_at: datetime | None = None
    generated_by: str = "ai"
    ai_model: str | None = None
    summary: str | None = None
    attack_chains: list[AttackChain] = Field(default_factory=list)
    spa_api_coverage: SpaApiCoverage = Field(default_factory=SpaApiCoverage)
    auth_coverage: AuthCoverage = Field(default_factory=AuthCoverage)
    evidence_strength_breakdown: EvidenceStrengthBreakdown = Field(default_factory=EvidenceStrengthBreakdown)
    coverage_warnings: list[str] = Field(default_factory=list)
    detector_coverage: list[DetectorCoverageMetric] = Field(default_factory=list)


class Scan(Document):
    target_url: Indexed(str)
    org_id: Indexed(str)
    # Who submitted the scan.
    submitted_by_user_id: Indexed(str)
    submitted_by_full_name: str
    submitted_by_email: str
    # Who cancelled it, if anyone (may differ from the submitter — any non-viewer
    # org member can cancel a scan).
    cancelled_by_user_id: str | None = None
    cancelled_by_email: str | None = None
    crawl_mode: CrawlMode = CrawlMode.full
    status: ScanStatus = ScanStatus.queued
    progress: int = Field(default=0, ge=0, le=100)
    current_phase: ScanPhase = ScanPhase.queued
    phase_message: str = "Scan queued"
    authorization_confirmed: bool = False
    authorization_confirmed_at: datetime | None = None
    # Non-secret marker only: which account roles were supplied for this scan
    # (e.g. ["main", "admin"]). The credentials themselves are never persisted.
    auth_roles_provided: list[ScanAuthRole] = Field(default_factory=list)

    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    eta_seconds: int | None = None

    statistics: ScanStatistics = Field(default_factory=ScanStatistics)
    overall_risk_score: float = Field(default=0.0, ge=0, le=100)
    # Qualitative band for the aggregate score (Critical/High/Medium/Low/Info),
    # derived from CVSS severity thresholds. Reported alongside the number.
    overall_risk_level: str = Field(default="Info")
    technology_stack: list[TechnologyComponent] = Field(default_factory=list)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    site_title: str = ""
    report_metadata: ReportMetadata = Field(default_factory=ReportMetadata)
    error_message: str | None = None

    class Settings:
        name = "scans"
        indexes = [
            "target_url",
            "org_id",
            "submitted_by_user_id",
            "status",
            [("org_id", 1), ("created_at", -1)],
            [("submitted_by_user_id", 1), ("created_at", -1)],
            [("created_at", -1)],
        ]

    async def touch(self) -> None:
        self.updated_at = datetime.now(timezone.utc)
        await self.save()
