from fastapi import APIRouter

from app.api.dependencies import json_response

router = APIRouter(prefix="/health", tags=["health"])


@router.get("")
async def health_check() -> dict:
    return json_response({"status": "healthy"})



