from pydantic import BaseModel, Field

from shared.models.vulnerability import RemediationStatus


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
