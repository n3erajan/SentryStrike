import logging

from fastapi import APIRouter, Request

from app.api.dependencies import json_response
from shared.scan_queue import RedisScanQueue, ScanQueueError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/health", tags=["health"])


@router.get("")
async def health_check(request: Request) -> dict:
    queue: RedisScanQueue | None = getattr(request.app.state, "scan_queue", None)
    active_scanners = 0
    if queue is not None:
        try:
            active_scanners = await queue.count_active_scanners()
        except ScanQueueError:
            logger.exception("failed to count active scanners")

    return json_response({
        "status": "healthy",
        "active_scanners": active_scanners,
    })



