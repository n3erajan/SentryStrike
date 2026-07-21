from datetime import datetime
import re

from pydantic import BaseModel, Field, field_validator

from shared.models.user import UserRole
from shared.schemas.scan_schema import ScanConfig

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Roles that may be handed out via a member invite. The owner role is created
# only through the vendor CLI onboarding flow, never by an owner/admin invite.
INVITABLE_ROLES = frozenset({UserRole.admin, UserRole.analyst, UserRole.developer, UserRole.viewer})
# Roles a member may be reassigned to. Ownership is fixed at onboarding and is
# never granted (or transferred) through the API.
ASSIGNABLE_ROLES = INVITABLE_ROLES


class InviteMemberRequest(BaseModel):
    """Payload for inviting a new member into the caller's organization."""

    email: str = Field(min_length=3, max_length=254)
    role: UserRole

    @field_validator("email")
    @classmethod
    def _validate_email(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not EMAIL_RE.match(normalized):
            raise ValueError("Enter a valid email address.")
        return normalized

    @field_validator("role")
    @classmethod
    def _validate_role(cls, value: UserRole) -> UserRole:
        if value not in INVITABLE_ROLES:
            raise ValueError("Role cannot be invited. Owners are onboarded by the vendor.")
        return value


class ChangeRoleRequest(BaseModel):
    """Payload for changing an existing member's role."""

    role: UserRole

    @field_validator("role")
    @classmethod
    def _validate_role(cls, value: UserRole) -> UserRole:
        if value not in ASSIGNABLE_ROLES:
            raise ValueError("Role cannot be assigned. Ownership is fixed at onboarding.")
        return value


class DefaultConfigRequest(BaseModel):
    """Payload for replacing the workspace's stored default scan config blob."""

    config: ScanConfig = Field(default_factory=ScanConfig)


class RetentionRequest(BaseModel):
    """Payload for updating the workspace's scan-data retention window."""

    retention_days: int = Field(ge=1)


class MemberResponse(BaseModel):
    """Public-facing member profile within a workspace."""

    id: str
    full_name: str
    email: str
    role: str
    is_active: bool
    created_at: datetime


class InviteResponse(BaseModel):
    """Public-facing pending-invite record within a workspace."""

    id: str
    email: str
    role: str
    state: str
    expires_at: datetime
    created_at: datetime
    invited_by_user_id: str | None = None
    email_delivery_status: str
    email_delivery_backend: str | None = None
    email_delivery_attempted_at: datetime | None = None
    email_delivery_error: str | None = None
