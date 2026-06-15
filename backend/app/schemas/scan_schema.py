from datetime import datetime

from pydantic import BaseModel, Field, HttpUrl, field_validator

from app.models.scan import CrawlMode, ScanStatus, ScanStatistics
from app.models.vulnerability import TechnologyComponent, Vulnerability


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
    error_message: str | None = None


class ApiResponse(BaseModel):
    success: bool = True
    message: str = "ok"
    data: dict | list | None = None


class ListVulnerabilitiesRequest(BaseModel):
    severity: str | None = None
    owasp_category: str | None = Field(default=None, alias="owaspCategory")
