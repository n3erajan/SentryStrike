import re
import unicodedata

from pydantic import BaseModel, Field, field_validator


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _normalize_public_text(value: str) -> str:
    normalized = " ".join(value.split())
    if any(unicodedata.category(char).startswith("C") for char in normalized):
        raise ValueError("Control characters are not allowed.")
    return normalized


class AccessRequestCreate(BaseModel):
    full_name: str = Field(min_length=2, max_length=120)
    email: str = Field(min_length=3, max_length=254)
    organization_name: str = Field(min_length=2, max_length=160)
    turnstile_token: str = Field(default="", max_length=2048)
    website: str = Field(default="", max_length=200)

    @field_validator("full_name", "organization_name")
    @classmethod
    def _validate_public_text(cls, value: str) -> str:
        normalized = _normalize_public_text(value)
        if len(normalized) < 2:
            raise ValueError("Enter at least 2 characters.")
        return normalized

    @field_validator("email")
    @classmethod
    def _validate_email(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not EMAIL_RE.match(normalized):
            raise ValueError("Enter a valid email address.")
        return normalized
