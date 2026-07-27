"""Public access-request verification and persistence."""

from __future__ import annotations

from datetime import timedelta

from pymongo.errors import DuplicateKeyError

from app.config import get_settings
from app.core.access_request_rate_limit import RedisAccessRequestRateLimiter
from app.core.auth import normalize_email, utc_now
from app.core.turnstile import TurnstileVerifier
from shared.models.access_request import AccessRequest


class AccessRequestService:
    def __init__(
        self,
        limiter: RedisAccessRequestRateLimiter,
        turnstile: TurnstileVerifier,
    ) -> None:
        self.limiter = limiter
        self.turnstile = turnstile

    async def submit(
        self,
        *,
        full_name: str,
        email: str,
        organization_name: str,
        turnstile_token: str,
        client_ip: str,
        website: str = "",
    ) -> bool:
        """Verify and persist one pending request, returning whether it was new."""
        await self.limiter.check(client_ip=client_ip)

        # Bots commonly fill hidden fields. Return the normal success shape without
        # spending a Turnstile request or writing anything to MongoDB.
        if website.strip():
            return False

        await self.turnstile.verify(
            token=turnstile_token,
            client_ip=client_ip,
            expected_action="request_access",
        )

        normalized_email = normalize_email(email)
        existing = await AccessRequest.find_one(AccessRequest.email == normalized_email)
        if existing is not None:
            return False

        settings = get_settings()
        request = AccessRequest(
            full_name=full_name,
            email=normalized_email,
            organization_name=organization_name,
            expires_at=utc_now() + timedelta(days=settings.access_request_ttl_days),
        )
        try:
            await request.insert()
        except DuplicateKeyError:
            return False
        return True

    async def close(self) -> None:
        await self.limiter.close()
