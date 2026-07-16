from beanie import init_beanie
from motor.motor_asyncio import AsyncIOMotorClient

from shared.config import get_infrastructure_settings
from shared.models.cve import CveRecord
from shared.models.oast_interaction import OastInteractionRecord
from shared.models.scan import Scan
from shared.models.user import User, UserSession


_client: AsyncIOMotorClient | None = None


async def init_db() -> None:
    global _client
    settings = get_infrastructure_settings()
    _client = AsyncIOMotorClient(settings.mongodb_uri)
    await init_beanie(
        database=_client[settings.mongodb_db_name],
        document_models=[Scan, CveRecord, User, UserSession, OastInteractionRecord],
    )


async def close_db() -> None:
    global _client
    if _client is not None:
        _client.close()
        _client = None
