from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, HttpUrl, field_validator

from shared.models.scan import CrawlMode, ScanPhase, ScanStatus, ScanStatistics
from shared.models.vulnerability import TechnologyComponent, Vulnerability


class ScanAccountCredential(BaseModel):
    """Optional credentials for a single test account.

    Either supply ``username`` + ``password`` (the scanner logs in against the
    target to obtain a live session, which handles multi-cookie / SPA logins
    automatically) or paste a raw ``cookie`` / ``header`` string. ``username``
    accepts an email too — it is submitted as-is into the login form's
    identifier field (frontend may label it "username / email").
    """

    username: str | None = Field(default=None, max_length=320)
    password: str | None = Field(default=None, max_length=512)
    cookie: str | None = Field(
        default=None,
        max_length=8192,
        description='Raw cookie string fallback, e.g. "session=abc; csrf=def".',
    )
    header: str | None = Field(
        default=None,
        max_length=8192,
        description='Raw header string fallback, e.g. "Authorization: Bearer ...".',
    )

    @property
    def is_populated(self) -> bool:
        return bool(
            (self.username and self.password) or self.cookie or self.header
        )


class ScanCredentials(BaseModel):
    """Up to three optional accounts used for access-control / IDOR testing."""

    main: ScanAccountCredential | None = Field(
        default=None,
        description="Primary user; authenticates the crawl and acts as the authed baseline.",
    )
    second: ScanAccountCredential | None = Field(
        default=None,
        description="A second regular user, used to prove horizontal IDOR.",
    )
    admin: ScanAccountCredential | None = Field(
        default=None,
        description="A privileged/admin user, used to prove vertical privilege escalation.",
    )


class ScanConfig(BaseModel):
    """Per-scan configuration overrides. Every field is optional — when unset
    the global ``.env`` / ``config.py`` default is used."""

    crawl_depth: int | None = Field(
        default=None, ge=1, le=10,
        description="Maximum link-follow depth from the root.",
    )
    crawl_max_urls: int | None = Field(
        default=None, ge=10, le=5000,
        description="Maximum number of URLs to discover.",
    )
    crawl_rate_limit_per_second: float | None = Field(
        default=None, ge=0.5, le=100.0,
        description="HTTP requests per second during crawling.",
    )
    crawl_browser_mode: str | None = Field(
        default=None,
        description='Browser discovery mode: "auto" (SPA-only), "always", "never".',
    )
    crawl_browser_max_interactions: int | None = Field(
        default=None, ge=1, le=200,
        description="Maximum browser interactions (clicks, navigations) per page.",
    )
    crawl_browser_budget_seconds: float | None = Field(
        default=None, ge=10.0, le=3600.0,
        description="Max wall-clock seconds for browser discovery.",
    )
    scan_mode: str | None = Field(
        default=None,
        description='Scan verification mode: "verified", "heuristic", or "aggressive".',
    )
    blind_injection_timing_threshold: float | None = Field(
        default=None, ge=0.1, le=1.0,
        description="Fraction of expected delay used as threshold for blind timing injection (0.1-1.0).",
    )
    ssrf_inband_timing_delta_ms: float | None = Field(
        default=None, ge=100.0, le=30000.0,
        description="Min response-time delta (ms) between internal and external control for in-band SSRF detection.",
    )
    scanner_concurrency: int | None = Field(
        default=None, ge=1, le=50,
        description="Number of concurrent HTTP workers during scanning.",
    )
    sensitive_paths_permutation_cap: int | None = Field(
        default=None, ge=0, le=2000,
        description="Maximum sensitive-path permutations to probe.",
    )
    xss_browser_dom_max_jobs: int | None = Field(
        default=None, ge=0, le=100,
        description="Max route+param probes for browser-driven DOM XSS reflection sweep.",
    )
    xss_browser_dom_budget_seconds: float | None = Field(
        default=None, ge=0.0, le=600.0,
        description="Wall-clock budget (seconds) for the DOM XSS browser sweep.",
    )
    allow_secondary_provisioning: bool | None = Field(
        default=None,
        description="Auto-register a throwaway second identity when no second account is supplied.",
    )
    request_timeout_seconds: float | None = Field(
        default=None, ge=1.0, le=120.0,
        description="HTTP request timeout in seconds.",
    )

    @field_validator("crawl_browser_mode")
    @classmethod
    def _validate_browser_mode(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().lower()
        if normalized not in {"auto", "always", "never"}:
            raise ValueError('crawl_browser_mode must be "auto", "always", or "never"')
        return normalized

    @field_validator("scan_mode")
    @classmethod
    def _validate_scan_mode(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().lower()
        if normalized not in {"verified", "heuristic", "aggressive"}:
            raise ValueError('scan_mode must be "verified", "heuristic", or "aggressive"')
        return normalized

    def get_val(self, field_name: str, fallback: Any) -> Any:
        """Resolve config value, falling back to global default if unset/None."""
        val = getattr(self, field_name, None)
        return val if val is not None else fallback



class CreateScanRequest(BaseModel):
    target_url: HttpUrl
    crawl_mode: CrawlMode = CrawlMode.full
    authorization_confirmed: bool = Field(
        description="User confirms they are authorized to security test this target.",
    )
    credentials: ScanCredentials | None = Field(
        default=None,
        description="Optional test-account credentials for authenticated / IDOR testing.",
    )
    config: ScanConfig | None = Field(
        default=None,
        description="Optional per-scan configuration overrides.",
    )

    @field_validator("authorization_confirmed")
    @classmethod
    def _require_authorization_confirmation(cls, value: bool) -> bool:
        if value is not True:
            raise ValueError("You must confirm you are authorized to test this target.")
        return value


class ScanResponse(BaseModel):
    id: str
    target_url: str
    crawl_mode: CrawlMode = CrawlMode.full
    status: ScanStatus
    progress: int
    current_phase: ScanPhase = ScanPhase.queued
    phase_message: str = "Scan queued"
    created_at: datetime
    updated_at: datetime


class ScanDetailResponse(ScanResponse):
    started_at: datetime | None = None
    completed_at: datetime | None = None
    statistics: ScanStatistics
    overall_risk_score: float
    technology_stack: list[TechnologyComponent]
    vulnerabilities: list[Vulnerability]
    error_message: str | None = None


class PaginatedScansResponse(BaseModel):
    total: int
    items: list[ScanResponse]


class ScanStatusResponse(BaseModel):
    id: str
    status: ScanStatus
    progress: int
    current_phase: ScanPhase = ScanPhase.queued
    phase_message: str = "Scan queued"
    started_at: datetime | None = None
    eta_seconds: int | None = None
    error_message: str | None = None


class ApiResponse(BaseModel):
    success: bool = True
    message: str = "ok"
    data: dict | list | None = None


class ListVulnerabilitiesRequest(BaseModel):
    severity: str | None = None
    owasp_category: str | None = Field(default=None, alias="owaspCategory")
