from fastapi import APIRouter, Depends, HTTPException, Response, status

from app.api.dependencies import get_auth_service, get_current_user, get_session_token, json_response
from app.config import get_settings
from app.core.auth import AuthError, AuthService
from shared.models.user import User
from app.schemas.auth_schema import AuthResponse, LoginRequest, RegisterRequest, UserResponse

router = APIRouter(prefix="/auth", tags=["auth"])


def _user_response(user: User) -> UserResponse:
    return UserResponse(id=str(user.id), email=user.email, created_at=user.created_at)


def _set_session_cookie(response: Response, token: str, max_age_seconds: int) -> None:
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
    settings = get_settings()
    response.delete_cookie(
        key=settings.auth_cookie_name,
        httponly=True,
        secure=settings.auth_cookie_secure,
        samesite=settings.auth_cookie_samesite,
    )


def _session_max_age_seconds(session) -> int:
    return max(0, int((session.expires_at - session.created_at).total_seconds()))


def _auth_response(user: User, token: str, expires_at) -> dict:
    return AuthResponse(user=_user_response(user), access_token=token, expires_at=expires_at).model_dump(mode="json")


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(
    payload: RegisterRequest,
    response: Response,
    service: AuthService = Depends(get_auth_service),
) -> dict:
    try:
        user = await service.register(payload.email, payload.password)
        token, session = await service.create_session(user)
    except AuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc

    _set_session_cookie(response, token, _session_max_age_seconds(session))
    return json_response(_auth_response(user, token, session.expires_at), "account registered")


@router.post("/login")
async def login(
    payload: LoginRequest,
    response: Response,
    service: AuthService = Depends(get_auth_service),
) -> dict:
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
    _ = current_user
    await service.revoke_session(token)
    _clear_session_cookie(response)
    return json_response({"logged_out": True}, "logged out")


@router.get("/me")
async def me(current_user: User = Depends(get_current_user)) -> dict:
    return json_response(_user_response(current_user).model_dump(mode="json"))
