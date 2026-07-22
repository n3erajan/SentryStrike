from datetime import datetime, timezone
from enum import Enum

from beanie import Document, Indexed
from pydantic import Field
from pymongo import IndexModel


class AnalysisStatus(str, Enum):
    not_requested = "not_requested"
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class AnalysisTrigger(str, Enum):
    automatic = "automatic"
    manual_retry = "manual_retry"


class AnalysisJob(Document):
    scan_id: Indexed(str)
    org_id: Indexed(str)
    revision: int = Field(ge=1)
    status: AnalysisStatus = AnalysisStatus.queued
    trigger: AnalysisTrigger = AnalysisTrigger.automatic

    requested_by_user_id: str | None = None
    requested_by_email: str | None = None

    model: str | None = None
    prompt_version: str | None = None
    finding_count: int = Field(default=0, ge=0)
    analyzed_finding_count: int = Field(default=0, ge=0)
    failed_finding_count: int = Field(default=0, ge=0)
    progress: int = Field(default=0, ge=0, le=100)
    message: str = "Analysis queued"

    attempt: int = Field(default=0, ge=0)
    max_attempts: int = Field(default=3, ge=1)
    next_attempt_at: datetime | None = None
    lease_owner: str | None = None
    lease_expires_at: datetime | None = None

    error_code: str | None = None
    error_message: str | None = None
    provider_request_ids: list[str] = Field(default_factory=list)
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    queued_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: datetime | None = None
    completed_at: datetime | None = None
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Settings:
        name = "analysis_jobs"
        indexes = [
            IndexModel([("scan_id", 1), ("revision", 1)], unique=True),
            IndexModel(
                [("status", 1), ("next_attempt_at", 1), ("lease_expires_at", 1)]
            ),
            IndexModel([("org_id", 1), ("created_at", -1)]),
        ]

