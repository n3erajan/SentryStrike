from datetime import datetime

from pydantic import BaseModel, Field, HttpUrl

from app.models.scan import ScanStatus, ScanStatistics
from app.models.vulnerability import TechnologyComponent, Vulnerability


class CreateScanRequest(BaseModel):
    target_url: HttpUrl


class ScanResponse(BaseModel):
    id: str
    target_url: str
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
