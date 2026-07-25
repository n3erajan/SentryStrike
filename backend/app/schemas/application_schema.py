from datetime import datetime

from pydantic import BaseModel, Field, HttpUrl

from shared.schemas.scan_schema import ScanConfig


class CreateApplicationRequest(BaseModel):
    """Payload for creating a new application within an organization."""

    name: str = Field(min_length=1, max_length=200)
    target_url: HttpUrl
    default_scan_config: ScanConfig = Field(default_factory=ScanConfig)


class UpdateApplicationRequest(BaseModel):
    """Payload for updating an existing application."""

    name: str | None = Field(default=None, min_length=1, max_length=200)
    target_url: HttpUrl | None = None
    default_scan_config: ScanConfig | None = None


class ApplicationResponse(BaseModel):
    """Public representation of an application."""

    id: str
    name: str
    target_url: str
    org_id: str
    default_scan_config: dict
    created_at: datetime
    updated_at: datetime
