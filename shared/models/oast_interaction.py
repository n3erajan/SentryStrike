from datetime import datetime, timezone

import pymongo
from beanie import Document, Indexed
from pydantic import Field

from shared.config import get_infrastructure_settings


class OastInteractionRecord(Document):
    """A single out-of-band callback received from a scanned target.

    Written by the OAST callback endpoint when a target server makes a
    request to a scanner-minted callback URL — the definitive confirmation
    for blind vulnerabilities such as SSRF. Records expire automatically via
    a MongoDB TTL index so stale interactions do not accumulate.
    """

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
