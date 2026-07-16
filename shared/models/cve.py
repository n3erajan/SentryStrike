from datetime import datetime, timezone

from beanie import Document, Indexed
from pydantic import Field


class CveRecord(Document):
    cve_id: Indexed(str, unique=True)
    component_name: Indexed(str)
    component_version: str | None = None
    severity_score: float | None = None
    summary: str | None = None
    references: list[str] = Field(default_factory=list)
    fetched_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Settings:
        name = "cves"
        indexes = ["component_name", "cve_id", [("fetched_at", -1)]]
