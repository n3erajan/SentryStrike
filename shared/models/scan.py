from datetime import datetime, timezone
from enum import Enum

from beanie import Document, Indexed
from pydantic import BaseModel, Field

from shared.models.analysis_job import AnalysisStatus
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
    active_vulnerabilities: int = 0
    suppressed_vulnerabilities: int = 0
    raw_findings: int = 0
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


class ProbedParameter(BaseModel):
    """One parameter name actually exercised against a path."""

    name: str
    detectors: list[str] = Field(default_factory=list)
    requests: int = 0


class ProbedPath(BaseModel):
    """One path the scanner actually sent requests to.

    Query strings are stripped from ``path``; the parameters exercised are listed
    by name in ``parameters``. Path segments are never templated, so this records
    the concrete resources probed rather than a pattern they belong to.
    """

    path: str
    methods: list[str] = Field(default_factory=list)
    parameters: list[ProbedParameter] = Field(default_factory=list)
    detectors: list[str] = Field(default_factory=list)
    requests: int = 0
    status_codes: list[int] = Field(default_factory=list)
    # Requests sent to this path that never got a response (timeout/transport
    # error). Probed, but not answered - so absence of a finding here is weaker.
    no_response: int = 0
    parameters_omitted: int = 0


class ScanCoverage(BaseModel):
    """Inventory of what the scan actually tested, measured not estimated.

    Built from the tested-surface ledger, which records one entry per distinct
    ``(detector, method, path, parameter)`` that produced a real HTTP exchange.
    Budget-denied probes are excluded by construction, and paths the target
    answered only with 404/410 are separated out as negative existence probes
    rather than counted as surface that was tested. The counts are the honest
    answer to "what was covered"; ``tested_paths`` is the itemised inventory of
    paths that exist, capped for storage with the omitted totals stated alongside.
    """

    paths_tested: int = 0
    # Of ``paths_tested``, how many were probed by at least one detector rather
    # than merely fetched by the crawler. The gap between the two is the set of
    # paths that were reached but never actively tested.
    paths_probed_by_detector: int = 0
    # Candidate paths the target answered only with 404/410. Path-guessing
    # detectors probe thousands of these; they establish that a resource is
    # absent, so counting them as tested surface would inflate coverage into
    # fiction. Reported here, and deliberately not itemised in ``tested_paths``.
    paths_absent: int = 0
    # Paths every probe of which went unanswered, so existence was never
    # established either way.
    paths_existence_unconfirmed: int = 0
    # Share of ``requests_sent`` spent proving those absent paths absent.
    requests_to_absent_paths: int = 0
    parameters_tested: int = 0
    requests_sent: int = 0
    # Requests dispatched that got no response at all across the whole scan.
    requests_without_response: int = 0
    # Probes the budget governor refused at a ceiling - attempted, never sent,
    # and therefore deliberately absent from the tested inventory.
    requests_denied_by_budget: int = 0
    detectors_exercised: list[str] = Field(default_factory=list)
    tested_paths: list[ProbedPath] = Field(default_factory=list)
    tested_paths_truncated: bool = False
    # Distinct paths present in the ledger but not itemised in ``tested_paths``.
    tested_paths_omitted: int = 0
    # Distinct (detector, method, path, parameter) tuples the ledger could not
    # record because it hit its own entry ceiling.
    ledger_entries_omitted: int = 0
    # Playwright-driven probes (DOM XSS verification, browser crawling) do not
    # pass through the HTTP ledger, so they are not itemised below. False here
    # means this inventory covers the HTTP layer only and browser-only coverage
    # is understated - never that no browser testing happened.
    browser_probes_itemised: bool = False


class AttackChain(BaseModel):
    """A multi-step exploitation path that chains individual findings."""

    id: str
    description: str
    vulnerability_ids: list[str]
    severity: str


class ReportMetadata(BaseModel):
    """Metadata about the generated report and coverage quality."""

    generated_at: datetime | None = None
    generated_by: str | None = None
    ai_model: str | None = None
    prompt_version: str | None = None
    summary: str | None = None
    attack_chains: list[AttackChain] = Field(default_factory=list)
    spa_api_coverage: SpaApiCoverage = Field(default_factory=SpaApiCoverage)
    auth_coverage: AuthCoverage = Field(default_factory=AuthCoverage)
    evidence_strength_breakdown: EvidenceStrengthBreakdown = Field(default_factory=EvidenceStrengthBreakdown)
    coverage_warnings: list[str] = Field(default_factory=list)
    detector_coverage: list[DetectorCoverageMetric] = Field(default_factory=list)
    tested_surface: ScanCoverage = Field(default_factory=ScanCoverage)


class ScanAnalysisState(BaseModel):
    status: AnalysisStatus
    current_job_id: str | None = None
    lease_owner: str | None = Field(default=None, exclude=True)
    revision: int = Field(ge=1)
    progress: int = Field(default=0, ge=0, le=100)
    message: str
    model: str | None = None
    prompt_version: str | None = None
    error_code: str | None = None
    error_message: str | None = None
    queued_at: datetime | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Scan(Document):
    target_url: Indexed(str)
    application_id: Indexed(str) | None = None
    org_id: Indexed(str)
    # Who submitted the scan.
    submitted_by_user_id: Indexed(str)
    submitted_by_full_name: str
    submitted_by_email: str
    # Who cancelled it, if anyone (may differ from the submitter - any non-viewer
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
    analysis: ScanAnalysisState | None = None
    error_message: str | None = None

    class Settings:
        name = "scans"
        indexes = [
            "target_url",
            "application_id",
            "org_id",
            "submitted_by_user_id",
            "status",
            [("org_id", 1), ("created_at", -1)],
            [("submitted_by_user_id", 1), ("created_at", -1)],
            [("created_at", -1)],
            [("org_id", 1), ("target_url", 1), ("status", 1)],
        ]

    async def touch(self) -> None:
        self.updated_at = datetime.now(timezone.utc)
        await self.save()
