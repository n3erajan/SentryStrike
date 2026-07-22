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
    """Base exception for all authentication failures."""

    status_code = 400
    message = "Authentication error"


class InvalidCredentialsError(AuthError):
    """Email/password combination did not match a known account."""

    status_code = 401
    message = "Invalid email or password."


class InvalidSessionError(AuthError):
    """The session token is missing, expired, or revoked."""

    status_code = 401
    message = "Authentication required."


def normalize_email(email: str) -> str:
    """Canonicalize an email to lowercase with stripped whitespace."""
    return email.strip().lower()


def hash_password(password: str) -> str:
    """Hash a plaintext password with PBKDF2-SHA256 and a random salt.

    Returns a string in the format ``algorithm$iterations$salt$digest`` so
    that the hash is self-describing and the iteration count can be increased
    transparently in the future.
    """
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PASSWORD_ITERATIONS,
    ).hex()
    return f"{PASSWORD_ALGORITHM}${PASSWORD_ITERATIONS}${salt}${digest}"


def verify_password(password: str, encoded_hash: str) -> bool:
    """Compare a plaintext password against a PBKDF2 hash.

    Uses HMAC-comparison to defend against timing side-channels.
    """
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
    """Generate a cryptographically random bearer token."""
    return secrets.token_urlsafe(48)


def hash_session_token(token: str) -> str:
    """Return the SHA-256 hash of a bearer token for server-side storage."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def utc_now() -> datetime:
    """Return the current UTC time as a naive datetime (no tzinfo)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def as_utc_naive(value: datetime | None) -> datetime | None:
    """Normalise a timezone-aware datetime to a naive UTC datetime, or return None."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


class AuthService:
    """Application logic for user login, session management, and logout.

    Account creation lives in ``app.core.invites`` — registration is invite-only,
    so there is no open ``register`` here.
    """

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
