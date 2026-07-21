import pytest

from app.core.invite_rate_limit import InviteRateLimitExceeded, RedisInviteRateLimiter


class FakeRedis:
    def __init__(self, results: list[tuple[int, int]]) -> None:
        self.results = list(results)
        self.calls: list[tuple] = []
        self.closed = False

    async def eval(self, script, key_count, key, window):
        self.calls.append((script, key_count, key, window))
        return self.results.pop(0)

    async def aclose(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_invite_limiter_counts_workspace_and_actor_windows() -> None:
    redis = FakeRedis([(1, 3599), (1, 599)])
    limiter = RedisInviteRateLimiter(redis)

    await limiter.check(org_id="org-1", actor_user_id="user-1")

    assert redis.calls[0][2].endswith(":workspace:org-1")
    assert redis.calls[0][3] == 3600
    assert redis.calls[1][2].endswith(":actor:user-1")
    assert redis.calls[1][3] == 600


@pytest.mark.asyncio
async def test_invite_limiter_surfaces_retry_after() -> None:
    redis = FakeRedis([(21, 127)])
    limiter = RedisInviteRateLimiter(redis)

    with pytest.raises(InviteRateLimitExceeded) as exc_info:
        await limiter.check(org_id="org-1", actor_user_id="user-1")

    assert exc_info.value.retry_after == 127
