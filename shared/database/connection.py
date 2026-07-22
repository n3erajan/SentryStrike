from beanie import init_beanie
from motor.motor_asyncio import AsyncIOMotorClient

from shared.config import InfrastructureSettings
from shared.models.audit import AuditLogEntry
from shared.models.analysis_job import AnalysisJob
from shared.models.cve import CveRecord
from shared.models.invite import Invite
from shared.models.notification import Notification
from shared.models.oast_interaction import OastInteractionRecord
from shared.models.organization import Organization
from shared.models.reverification import ReverificationJob
from shared.models.scan import Scan
from shared.models.user import User, UserSession


# Module-level client singleton. Both the API and the worker call init_db()
# once at startup and close_db() on shutdown; the ODM resolves the active
# connection internally after initialization.
_client: AsyncIOMotorClient | None = None


async def init_db(settings: InfrastructureSettings) -> None:
    """Open the MongoDB connection and register all Beanie document models."""
    global _client
    _client = AsyncIOMotorClient(settings.mongodb_uri)
    await init_beanie(
        database=_client[settings.mongodb_db_name],
        document_models=[Scan, AnalysisJob, CveRecord, User, UserSession, OastInteractionRecord, Organization, Invite, AuditLogEntry, Notification, ReverificationJob],
    )


async def close_db() -> None:
    """Close the MongoDB connection if one is open."""
    global _client
    if _client is not None:
        _client.close()
        _client = None
