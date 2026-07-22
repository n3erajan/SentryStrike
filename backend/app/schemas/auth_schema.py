from datetime import datetime
import re

from pydantic import BaseModel, Field, field_validator

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class RegisterRequest(BaseModel):
    """Payload for accepting an invite and creating an account.

    Registration is invite-only: ``invite_token`` is required and pins the email
    and role. The submitted email must match the invited address.
    """

    invite_token: str = Field(min_length=1, max_length=512)
    full_name: str = Field(min_length=2, max_length=120)
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=8, max_length=256)

    @field_validator("full_name")
    @classmethod
    def _validate_full_name(cls, value: str) -> str:
        normalized = " ".join(value.split())
        if len(normalized) < 2:
            raise ValueError("Enter your full name.")
        return normalized

    @field_validator("email")
    @classmethod
    def _validate_email(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not EMAIL_RE.match(normalized):
            raise ValueError("Enter a valid email address.")
        return normalized


class LoginRequest(BaseModel):
    """Payload for authenticating against an existing account."""

    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=256)

    @field_validator("email")
    @classmethod
    def _validate_email(cls, value: str) -> str:
        return RegisterRequest._validate_email(value)


class UserResponse(BaseModel):
    """Public-facing user profile returned by API endpoints."""

    id: str
    full_name: str
    email: str
    org_id: str
    role: str
    created_at: datetime


class AuthResponse(BaseModel):
    """Envelope wrapping an authentication result with token metadata."""

    user: UserResponse
    access_token: str
    token_type: str = "bearer"
    expires_at: datetime
