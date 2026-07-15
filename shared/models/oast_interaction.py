from datetime import datetime, timezone

import pymongo
from beanie import Document, Indexed
from pydantic import Field

from shared.config import get_infrastructure_settings


class OastInteractionRecord(Document):
    interaction_id: Indexed(str)
    source_ip: str | None = None
    path: str = ""
    method: str = "GET"
    received_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Settings:
        name = "oast_interactions"
        indexes = [
            "interaction_id",
            pymongo.IndexModel(
                [("received_at", pymongo.ASCENDING)],
                expireAfterSeconds=get_infrastructure_settings().oast_interaction_ttl_seconds,
                name="oast_ttl",
            ),
        ]
