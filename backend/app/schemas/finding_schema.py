from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from shared.models.vulnerability import RemediationStatus
from shared.schemas.scan_schema import ScanCredentials


class AssignFindingRequest(BaseModel):
    """Payload for assigning (or, with null, unassigning) a finding.

    ``assignee_user_id`` must name a member of the caller's own organization;
    ``None`` clears the assignment.
    """

    assignee_user_id: str | None = None


class CommentRequest(BaseModel):
    """Payload for adding a team comment to a finding."""

    body: str = Field(min_length=1, max_length=5000)


class RemediationRequest(BaseModel):
    """Payload for advancing a finding's remediation workflow state."""

    remediation_status: RemediationStatus


class FindingReviewRequest(BaseModel):
    """Payload for suppressing a false positive or restoring an active finding."""

    disposition: Literal["active", "false_positive"]
    reason: str = Field(min_length=1, max_length=5000)

    @field_validator("reason")
    @classmethod
    def _strip_reason(cls, value: str) -> str:
        reason = value.strip()
        if not reason:
            raise ValueError("reason must not be blank")
        return reason


class ReverificationRequest(BaseModel):
    """Optional target credentials; retained only in the Redis job payload."""

    model_config = ConfigDict(extra="forbid")

    credentials: ScanCredentials | None = None
