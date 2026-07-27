"""Shared Cloudflare Turnstile token verification."""

from __future__ import annotations

import httpx

from app.config import get_settings

TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"


class CaptchaInvalidError(RuntimeError):
    pass


class CaptchaUnavailableError(RuntimeError):
    pass


class TurnstileVerifier:
    def __init__(self, http_client: httpx.AsyncClient | None = None) -> None:
        self.http_client = http_client or httpx.AsyncClient(timeout=10.0)
        self._owns_http_client = http_client is None

    async def verify(
        self,
        *,
        token: str,
        client_ip: str,
        expected_action: str,
    ) -> None:
        if not token.strip():
            raise CaptchaInvalidError("Complete the security check and try again.")

        settings = get_settings()
        try:
            response = await self.http_client.post(
                TURNSTILE_VERIFY_URL,
                data={
                    "secret": settings.turnstile_secret_key.get_secret_value(),
                    "response": token,
                    "remoteip": client_ip,
                },
            )
            response.raise_for_status()
            result = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise CaptchaUnavailableError(
                "The security check is temporarily unavailable. Please try again later."
            ) from exc

        if not isinstance(result, dict):
            raise CaptchaUnavailableError(
                "The security check is temporarily unavailable. Please try again later."
            )
        if not result.get("success"):
            raise CaptchaInvalidError("Complete the security check and try again.")
        action = str(result.get("action") or "")
        if action != expected_action:
            raise CaptchaInvalidError("Complete the security check and try again.")

    async def close(self) -> None:
        if self._owns_http_client:
            await self.http_client.aclose()
