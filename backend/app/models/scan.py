from datetime import datetime, timezone
from enum import Enum

from beanie import Document, Indexed
from pydantic import BaseModel, Field

from app.models.vulnerability import TechnologyComponent, Vulnerability


class ScanStatus(str, Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class CrawlMode(str, Enum):
    full = "full"
    single = "single"


class SeverityBreakdown(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ScanStatistics(BaseModel):
    total_urls_crawled: int = 0
    total_vulnerabilities: int = 0
    severity_breakdown: SeverityBreakdown = Field(default_factory=SeverityBreakdown)


class AttackChain(BaseModel):
    id: str
    description: str
    vulnerability_ids: list[str]
    severity: str


class ReportMetadata(BaseModel):
    generated_at: datetime | None = None
    generated_by: str = "ai"
    summary: str | None = None
    attack_chains: list[AttackChain] = Field(default_factory=list)


class Scan(Document):
    target_url: Indexed(str)
    crawl_mode: CrawlMode = CrawlMode.full
    status: ScanStatus = ScanStatus.queued
    progress: int = Field(default=0, ge=0, le=100)

    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    statistics: ScanStatistics = Field(default_factory=ScanStatistics)
    overall_risk_score: float = Field(default=0.0, ge=0, le=100)
    technology_stack: list[TechnologyComponent] = Field(default_factory=list)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    report_metadata: ReportMetadata = Field(default_factory=ReportMetadata)
    error_message: str | None = None

    class Settings:
        name = "scans"
        indexes = [
            "target_url",
            "status",
            [("created_at", -1)],
        ]

    async def touch(self) -> None:
        self.updated_at = datetime.now(timezone.utc)
        await self.save()
