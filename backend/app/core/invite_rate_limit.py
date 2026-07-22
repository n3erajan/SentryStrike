"""Application-level invitation throttling backed by Redis."""

from __future__ import annotations

from redis.asyncio import Redis
from redis.exceptions import RedisError

from app.config import get_settings


class InviteRateLimitExceeded(RuntimeError):
    def __init__(self, retry_after: int) -> None:
        self.retry_after = max(1, retry_after)
        super().__init__("Invitation rate limit exceeded")


class InviteRateLimiterUnavailable(RuntimeError):
    pass


class RedisInviteRateLimiter:
    """Count invite attempts by workspace and actor with bounded Redis keys."""

    _INCREMENT_SCRIPT = """
local count = redis.call('INCR', KEYS[1])
if count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
return {count, redis.call('TTL', KEYS[1])}
"""

    def __init__(self, client: Redis) -> None:
        self.client = client

    @classmethod
    def from_settings(cls) -> "RedisInviteRateLimiter":
        settings = get_settings()
        return cls(Redis.from_url(settings.redis_url, decode_responses=True))

    async def check(self, *, org_id: str, actor_user_id: str) -> None:
        settings = get_settings()
        prefix = settings.invite_rate_limit_key_prefix.rstrip(":")
        limits = (
            (f"{prefix}:workspace:{org_id}", 3600, settings.invite_workspace_limit_per_hour),
            (
                f"{prefix}:actor:{actor_user_id}",
                600,
                settings.invite_actor_limit_per_ten_minutes,
            ),
        )
        try:
            for key, window, limit in limits:
                count, ttl = await self.client.eval(
                    self._INCREMENT_SCRIPT, 1, key, window
                )
                if int(count) > limit:
                    raise InviteRateLimitExceeded(int(ttl) if int(ttl) > 0 else window)
        except InviteRateLimitExceeded:
            raise
        except RedisError as exc:
            raise InviteRateLimiterUnavailable("Invitation limiter is unavailable") from exc

    async def close(self) -> None:
        await self.client.aclose()
