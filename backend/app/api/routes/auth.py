from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from app.api.dependencies import (
    get_auth_service,
    get_current_user,
    get_invite_service,
    get_session_token,
    json_response,
)
from app.config import get_settings
from app.core.auth import AuthError, AuthService
from app.core.invites import InviteError, InviteService
from shared.models.user import User
from app.schemas.auth_schema import AuthResponse, LoginRequest, RegisterRequest, UserResponse

router = APIRouter(prefix="/auth", tags=["auth"])


def _user_response(user: User) -> UserResponse:
    """Project a User document to its API response shape."""
    return UserResponse(
        id=str(user.id),
        full_name=user.full_name,
        email=user.email,
        org_id=user.org_id,
        role=user.role.value,
        created_at=user.created_at,
    )


def _set_session_cookie(response: Response, token: str, max_age_seconds: int) -> None:
    """Set an HttpOnly session cookie on the response."""
    settings = get_settings()
    response.set_cookie(
        key=settings.auth_cookie_name,
        value=token,
        max_age=max_age_seconds,
        httponly=True,
        secure=settings.auth_cookie_secure,
        samesite=settings.auth_cookie_samesite,
    )


def _clear_session_cookie(response: Response) -> None:
    """Remove the session cookie from the response, effectively logging the user out."""
    settings = get_settings()
    response.delete_cookie(
        key=settings.auth_cookie_name,
        httponly=True,
        secure=settings.auth_cookie_secure,
        samesite=settings.auth_cookie_samesite,
    )


def _session_max_age_seconds(session) -> int:
    """Calculate the remaining lifetime of a session token in seconds."""
    return max(0, int((session.expires_at - session.created_at).total_seconds()))


def _auth_response(user: User, token: str, expires_at) -> dict:
    """Assemble the standard authentication response envelope."""
    return AuthResponse(user=_user_response(user), access_token=token, expires_at=expires_at).model_dump(mode="json")


@router.get("/invite")
async def preview_invite(
    token: str = Query(min_length=1, max_length=512),
    invites: InviteService = Depends(get_invite_service),
) -> dict:
    """Validate an invite token and return its pinned email and role.

    Lets the signup form prefill the (read-only) email and show the role before
    the invitee sets a password. Does not consume the invite.
    """
    try:
        invite = await invites.preview(token)
    except InviteError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc
    return json_response(
        {"email": invite.email, "role": invite.role.value, "org_name": invite.org_name},
        "invite valid",
    )


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(
    payload: RegisterRequest,
    response: Response,
    invites: InviteService = Depends(get_invite_service),
    service: AuthService = Depends(get_auth_service),
) -> dict:
    """Accept an invite and issue an initial session token.

    Registration is invite-only: the token pins the email and role, and (for an
    owner invite) creates the workspace. The submitted email must match.
    """
    try:
        user = await invites.accept(
            token=payload.invite_token,
            full_name=payload.full_name,
            email=payload.email,
            password=payload.password,
        )
        token, session = await service.create_session(user)
    except (AuthError, InviteError) as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc

    _set_session_cookie(response, token, _session_max_age_seconds(session))
    return json_response(_auth_response(user, token, session.expires_at), "account registered")


@router.post("/login")
async def login(
    payload: LoginRequest,
    response: Response,
    service: AuthService = Depends(get_auth_service),
) -> dict:
    """Authenticate with email and password, returning a session token."""
    try:
        user = await service.authenticate(payload.email, payload.password)
        token, session = await service.create_session(user)
    except AuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc

    _set_session_cookie(response, token, _session_max_age_seconds(session))
    return json_response(_auth_response(user, token, session.expires_at), "logged in")


@router.post("/logout")
async def logout(
    response: Response,
    token: str | None = Depends(get_session_token),
    current_user: User = Depends(get_current_user),
    service: AuthService = Depends(get_auth_service),
) -> dict:
    """Revoke the current session and clear the session cookie."""
    _ = current_user
    await service.revoke_session(token)
    _clear_session_cookie(response)
    return json_response({"logged_out": True}, "logged out")


@router.get("/me")
async def me(current_user: User = Depends(get_current_user)) -> dict:
    """Return the currently authenticated user's profile."""
    return json_response(_user_response(current_user).model_dump(mode="json"))
