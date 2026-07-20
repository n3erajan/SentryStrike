from http.cookies import SimpleCookie

from fastapi import Depends, Header, HTTPException, Request, status

from app.config import get_settings
from app.core.auth import AuthService, InvalidSessionError
from shared.database.repositories.scan_repository import ScanRepository
from shared.models.user import User

# Module-level singletons wired once. FastAPI's Depends resolver calls the
# factory functions below, which return these shared instances.
scan_repository = ScanRepository()
auth_service = AuthService()


def get_scan_repository() -> ScanRepository:
    """FastAPI dependency: provide the shared ScanRepository singleton."""
    return scan_repository


def get_auth_service() -> AuthService:
    """FastAPI dependency: provide the shared AuthService singleton."""
    return auth_service


def _bearer_token(authorization: str | None) -> str | None:
    """Extract a bearer token from the Authorization header, or None."""
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    return token.strip()


def get_session_token(
    request: Request,
    authorization: str | None = Header(default=None),
) -> str | None:
    """Extract the session token from either the Authorization header or the session cookie."""
    settings = get_settings()
    cookie = SimpleCookie()
    try:
        cookie.load(request.headers.get("cookie", ""))
    except Exception:
        cookie = SimpleCookie()
    cookie_token = cookie[settings.auth_cookie_name].value if settings.auth_cookie_name in cookie else None
    return _bearer_token(authorization) or cookie_token


async def get_current_user(
    token: str | None = Depends(get_session_token),
    service: AuthService = Depends(get_auth_service),
) -> User:
    """Authenticate the request and return the User document.

    Raises HTTPException 401 if the session token is missing, expired, or
    revoked. Protected routes include this dependency in their router.
    """
    try:
        return (await service.authenticate_session(token))[0]
    except InvalidSessionError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=exc.message,
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def ensure_scan_exists(scan_id: str, repo: ScanRepository = Depends(get_scan_repository)):
    """Return a dependency that verifies a scan exists by id.

    Usage: ``Depends(ensure_scan_exists("some-id"))``. Raises 404 when
    the scan is not found.
    """

    async def _inner() -> object:
        scan = await repo.get_by_id(scan_id)
        if not scan:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
        return scan

    return _inner


def json_response(data: object = None, message: str = "ok", success: bool = True) -> dict:
    """Build a standardised API envelope: ``{success, message, data}``."""
    return {"success": success, "message": message, "data": data}
