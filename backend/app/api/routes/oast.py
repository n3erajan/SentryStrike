from fastapi import APIRouter, Request, Response

from app.core.verification.oast import OastClient
from app.models.oast_interaction import OastInteractionRecord

router = APIRouter(prefix="/oast", tags=["oast"])

# Bound the poll query so a hot id cannot return an unbounded document set.
_POLL_LIMIT = 50


@router.get("/poll")
async def poll(id: str = "") -> list[dict]:
    if not OastClient.is_valid_interaction_id(id):
        return []
    docs = (
        await OastInteractionRecord.find({"interaction_id": id})
        .limit(_POLL_LIMIT)
        .to_list()
    )
    return [
        {
            "interaction_id": d.interaction_id,
            "source_ip": d.source_ip,
            "path": d.path,
            "method": d.method,
            "received_at": d.received_at.isoformat() if d.received_at else None,
        }
        for d in docs
    ]


@router.get("/{interaction_id}")
async def catch(interaction_id: str, request: Request) -> Response:
    # Genuine scanner-minted ids only; anything else is noise/abuse -> 404, no write.
    if not OastClient.is_valid_interaction_id(interaction_id):
        return Response(status_code=404)
    await OastInteractionRecord(
        interaction_id=interaction_id,
        source_ip=request.client.host if request.client else None,
        path=request.url.path,
        method=request.method,
    ).insert()
    # Static body — never reflect the id or any input.
    return Response(content="ok", media_type="text/plain")
