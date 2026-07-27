from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.api.dependencies import get_access_request_service, json_response
from app.config import get_settings
from app.core.access_request_rate_limit import (
    AccessRequestRateLimiterUnavailable,
    AccessRequestRateLimitExceeded,
)
from app.core.access_requests import (
    AccessRequestService,
)
from app.core.turnstile import CaptchaInvalidError, CaptchaUnavailableError
from app.schemas.access_request_schema import AccessRequestCreate


router = APIRouter(prefix="/access-requests", tags=["access requests"])


@router.get("/config")
async def access_request_config() -> dict:
    """Expose the public Turnstile site key needed to render the form."""
    return json_response(
        {"turnstile_site_key": get_settings().turnstile_site_key},
        "access-request configuration",
    )


@router.post("", status_code=status.HTTP_202_ACCEPTED)
async def request_access(
    payload: AccessRequestCreate,
    request: Request,
    service: AccessRequestService = Depends(get_access_request_service),
) -> dict:
    client_ip = request.client.host if request.client else "unknown"
    try:
        await service.submit(
            full_name=payload.full_name,
            email=payload.email,
            organization_name=payload.organization_name,
            turnstile_token=payload.turnstile_token,
            client_ip=client_ip,
            website=payload.website,
        )
    except AccessRequestRateLimitExceeded as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many access requests. Please try again later.",
            headers={"Retry-After": str(exc.retry_after)},
        ) from exc
    except AccessRequestRateLimiterUnavailable as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Access requests are temporarily unavailable. Please try again later.",
        ) from exc
    except CaptchaInvalidError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except CaptchaUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc

    # Deliberately identical for new, duplicate, and honeypot submissions so the
    # public endpoint cannot be used to enumerate pending requests.
    return json_response(
        {"submitted": True},
        "If the request is eligible, we will contact you at the submitted email address.",
    )
