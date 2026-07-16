from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from beanie import PydanticObjectId

from app.config import get_settings
from shared.models.user import User, UserSession

PASSWORD_ALGORITHM = "pbkdf2_sha256"
PASSWORD_ITERATIONS = 260_000


class AuthError(Exception):
    status_code = 400
    message = "Authentication error"


class RegistrationClosedError(AuthError):
    status_code = 403
    message = "Sorry, we currently don't take new users registration."


class DuplicateUserError(AuthError):
    status_code = 409
    message = "An account with this email already exists."


class InvalidCredentialsError(AuthError):
    status_code = 401
    message = "Invalid email or password."


class InvalidSessionError(AuthError):
    status_code = 401
    message = "Authentication required."


def normalize_email(email: str) -> str:
    return email.strip().lower()


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PASSWORD_ITERATIONS,
    ).hex()
    return f"{PASSWORD_ALGORITHM}${PASSWORD_ITERATIONS}${salt}${digest}"


def verify_password(password: str, encoded_hash: str) -> bool:
    try:
        algorithm, iterations_text, salt, stored_digest = encoded_hash.split("$", 3)
        iterations = int(iterations_text)
    except ValueError:
        return False

    if algorithm != PASSWORD_ALGORITHM:
        return False

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations,
    ).hex()
    return hmac.compare_digest(digest, stored_digest)


def new_session_token() -> str:
    return secrets.token_urlsafe(48)


def hash_session_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def as_utc_naive(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


class AuthService:
    async def register(self, email: str, password: str) -> User:
        settings = get_settings()
        if not settings.allow_registration:
            raise RegistrationClosedError()

        normalized_email = normalize_email(email)
        existing = await User.find_one(User.email == normalized_email)
        if existing is not None:
            raise DuplicateUserError()

        user = User(email=normalized_email, password_hash=hash_password(password))
        await user.insert()
        return user

    async def authenticate(self, email: str, password: str) -> User:
        normalized_email = normalize_email(email)
        user = await User.find_one(User.email == normalized_email)
        if user is None or not user.is_active or not verify_password(password, user.password_hash):
            raise InvalidCredentialsError()
        return user

    async def create_session(self, user: User) -> tuple[str, UserSession]:
        settings = get_settings()
        token = new_session_token()
        now = utc_now()
        session = UserSession(
            user_id=str(user.id),
            token_hash=hash_session_token(token),
            created_at=now,
            expires_at=now + timedelta(hours=settings.auth_session_ttl_hours),
        )
        await session.insert()
        return token, session

    async def authenticate_session(self, token: str | None) -> tuple[User, UserSession]:
        if not token:
            raise InvalidSessionError()

        session = await UserSession.find_one(UserSession.token_hash == hash_session_token(token))
        now = utc_now()
        expires_at = as_utc_naive(session.expires_at) if session else None
        revoked_at = as_utc_naive(session.revoked_at) if session else None
        if session is None or revoked_at is not None or expires_at is None or expires_at <= now:
            raise InvalidSessionError()

        try:
            user_id = PydanticObjectId(session.user_id)
        except Exception as exc:
            raise InvalidSessionError() from exc

        user = await User.get(user_id)
        if user is None or not user.is_active:
            raise InvalidSessionError()

        session.last_used_at = now
        await session.save()
        return user, session

    async def revoke_session(self, token: str | None) -> bool:
        if not token:
            return False

        session = await UserSession.find_one(UserSession.token_hash == hash_session_token(token))
        if session is None or session.revoked_at is not None:
            return False

        session.revoked_at = utc_now()
        await session.save()
        return True
