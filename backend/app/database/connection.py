from beanie import init_beanie
from motor.motor_asyncio import AsyncIOMotorClient

from app.config import get_settings
from app.models.cve import CveRecord
from app.models.oast_interaction import OastInteractionRecord
from app.models.scan import Scan
from app.models.user import User, UserSession


_client: AsyncIOMotorClient | None = None


async def init_db() -> None:
    global _client
    settings = get_settings()
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
