from datetime import datetime, timezone
from enum import Enum

from beanie import Document, Indexed
from pydantic import BaseModel, Field

from shared.models.scan import ScanAuthRole
from shared.models.vulnerability import VerificationTarget


class ReverificationStatus(str, Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"


class ReverificationOutcome(str, Enum):
    reproduced = "reproduced"
    not_reproduced = "not_reproduced"
    inconclusive = "inconclusive"


class ReverificationEvidence(BaseModel):
    request_url: str
    request_method: str
    status_code: int | None = None
    elapsed_ms: float | None = None
    response_snippet: str | None = None
    proof_matched: bool = False
    reason: str


class ReverificationJob(Document):
    """Focused verification attempt and its immutable result evidence."""

    org_id: Indexed(str)
    scan_id: Indexed(str)
    vulnerability_id: Indexed(str)
    requested_by_user_id: Indexed(str)
    requested_by_email: str
    target: VerificationTarget
    auth_roles_provided: list[ScanAuthRole] = Field(default_factory=list)
    status: ReverificationStatus = ReverificationStatus.queued
    outcome: ReverificationOutcome | None = None
    evidence: list[ReverificationEvidence] = Field(default_factory=list)
    error_message: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: datetime | None = None
    completed_at: datetime | None = None

    class Settings:
        name = "reverification_jobs"
        indexes = [
            "org_id",
            "scan_id",
            "vulnerability_id",
            "requested_by_user_id",
            [("org_id", 1), ("scan_id", 1), ("vulnerability_id", 1), ("created_at", -1)],
        ]
