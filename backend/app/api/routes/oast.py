from fastapi import APIRouter, Request, Response

from shared.verification.oast import OAST_CALLBACK_BODY, OastClient
from shared.models.oast_interaction import OastInteractionRecord

router = APIRouter(prefix="/oast", tags=["oast"])

# Bound the poll query so a hot id cannot return an unbounded document set.
_POLL_LIMIT = 50


@router.get("/poll")
async def poll(id: str = "") -> list[dict]:
    """Return stored OAST callbacks for a given interaction id.

    Used by scanner workers to poll for out-of-band callbacks that confirm
    blind vulnerabilities like SSRF and blind SQLi.
    """
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
    # Static body - never reflect the id or any input. The body is the shared
    # OAST_CALLBACK_BODY marker: when a scanned application's response to a
    # URL-injection contains it, the server-side fetch's response body was
    # rendered back to the caller, which is how the scanner distinguishes a
    # full-response SSRF from a blind one.
    return Response(content=OAST_CALLBACK_BODY, media_type="text/plain")
