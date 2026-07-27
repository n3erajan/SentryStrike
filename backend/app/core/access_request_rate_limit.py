"""Redis-backed throttling for the public access-request endpoint."""

from __future__ import annotations

import hashlib

from redis.asyncio import Redis
from redis.exceptions import RedisError

from app.config import get_settings


class AccessRequestRateLimitExceeded(RuntimeError):
    def __init__(self, retry_after: int) -> None:
        self.retry_after = max(1, retry_after)
        super().__init__("Access-request rate limit exceeded")


class AccessRequestRateLimiterUnavailable(RuntimeError):
    pass


class RedisAccessRequestRateLimiter:
    """Enforce short and daily limits without retaining raw IP addresses."""

    _INCREMENT_SCRIPT = """
local count = redis.call('INCR', KEYS[1])
if count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
return {count, redis.call('TTL', KEYS[1])}
"""

    def __init__(self, client: Redis) -> None:
        self.client = client

    @classmethod
    def from_settings(cls) -> "RedisAccessRequestRateLimiter":
        settings = get_settings()
        return cls(Redis.from_url(settings.redis_url, decode_responses=True))

    async def check(self, *, client_ip: str) -> None:
        settings = get_settings()
        prefix = settings.access_request_rate_limit_key_prefix.rstrip(":")
        ip_key = hashlib.sha256(client_ip.strip().encode("utf-8")).hexdigest()
        limits = (
            (
                f"{prefix}:ip:{ip_key}:15m",
                15 * 60,
                settings.access_request_ip_limit_per_fifteen_minutes,
            ),
            (
                f"{prefix}:ip:{ip_key}:day",
                24 * 60 * 60,
                settings.access_request_ip_limit_per_day,
            ),
        )
        try:
            for key, window, limit in limits:
                count, ttl = await self.client.eval(
                    self._INCREMENT_SCRIPT, 1, key, window
                )
                if int(count) > limit:
                    raise AccessRequestRateLimitExceeded(
                        int(ttl) if int(ttl) > 0 else window
                    )
        except AccessRequestRateLimitExceeded:
            raise
        except RedisError as exc:
            raise AccessRequestRateLimiterUnavailable(
                "Access-request limiter is unavailable"
            ) from exc

    async def close(self) -> None:
        await self.client.aclose()
