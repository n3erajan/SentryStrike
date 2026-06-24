from datetime import datetime

from pydantic import BaseModel, Field, HttpUrl, field_validator

from app.models.scan import CrawlMode, ScanPhase, ScanStatus, ScanStatistics
from app.models.vulnerability import TechnologyComponent, Vulnerability


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
    login_url: str | None = Field(
        default=None,
        max_length=2048,
        description="Optional explicit login endpoint if it differs from the target root.",
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


class CreateScanRequest(BaseModel):
    target_url: HttpUrl
    crawl_mode: CrawlMode = CrawlMode.full
    authorization_confirmed: bool = Field(
        description="User confirms they are authorized to security test this target.",
    )
    authorization_text: str | None = Field(
        default=None,
        max_length=1000,
        description="Optional authorization note, ticket, contract, or scope reference.",
    )
    credentials: ScanCredentials | None = Field(
        default=None,
        description="Optional test-account credentials for authenticated / IDOR testing.",
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
    error_message: str | None = None


class ApiResponse(BaseModel):
    success: bool = True
    message: str = "ok"
    data: dict | list | None = None


class ListVulnerabilitiesRequest(BaseModel):
    severity: str | None = None
    owasp_category: str | None = Field(default=None, alias="owaspCategory")
