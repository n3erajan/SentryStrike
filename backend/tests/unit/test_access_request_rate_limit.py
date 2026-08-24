import pytest
from redis.exceptions import RedisError

from app.config import get_settings
from app.core.access_request_rate_limit import (
    AccessRequestRateLimiterUnavailable,
    AccessRequestRateLimitExceeded,
    RedisAccessRequestRateLimiter,
)


@pytest.fixture
def fifteen_minute_limit(monkeypatch) -> int:
    """Pin the 15m limit so the test does not depend on the ambient .env.

    ``get_settings`` reads ``backend/.env``, where a deployment may raise
    ACCESS_REQUEST_IP_LIMIT_PER_FIFTEEN_MINUTES above the count these tests
    use - the limiter would then fall through to the daily window and the
    fake's scripted results would run out.
    """
    limit = 3
    settings = get_settings()
    monkeypatch.setattr(
        settings, "access_request_ip_limit_per_fifteen_minutes", limit, raising=False
    )
    return limit


class FakeRedis:
    def __init__(self, results: list[tuple[int, int]]) -> None:
        self.results = list(results)
        self.calls: list[tuple] = []

    async def eval(self, script, key_count, key, window):
        self.calls.append((script, key_count, key, window))
        return self.results.pop(0)

    async def aclose(self) -> None:
        return None


@pytest.mark.asyncio
async def test_access_request_limiter_counts_fifteen_minute_and_daily_windows() -> None:
    redis = FakeRedis([(1, 899), (1, 86399)])
    limiter = RedisAccessRequestRateLimiter(redis)

    await limiter.check(client_ip="203.0.113.8")

    assert redis.calls[0][2].endswith(":15m")
    assert "203.0.113.8" not in redis.calls[0][2]
    assert redis.calls[0][3] == 900
    assert redis.calls[1][2].endswith(":day")
    assert redis.calls[1][3] == 86400


@pytest.mark.asyncio
async def test_access_request_limiter_surfaces_short_window_retry_after(
    fifteen_minute_limit: int,
) -> None:
    over_limit = fifteen_minute_limit + 1
    limiter = RedisAccessRequestRateLimiter(FakeRedis([(over_limit, 417)]))

    with pytest.raises(AccessRequestRateLimitExceeded) as exc_info:
        await limiter.check(client_ip="203.0.113.8")

    assert exc_info.value.retry_after == 417


@pytest.mark.asyncio
async def test_access_request_limiter_fails_closed_when_redis_is_unavailable() -> None:
    class OfflineRedis:
        async def eval(self, *_args):
            raise RedisError("offline")

    limiter = RedisAccessRequestRateLimiter(OfflineRedis())

    with pytest.raises(AccessRequestRateLimiterUnavailable):
        await limiter.check(client_ip="203.0.113.8")
