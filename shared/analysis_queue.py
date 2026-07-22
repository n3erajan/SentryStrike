from __future__ import annotations

from typing import Protocol

from pydantic import BaseModel, Field, ValidationError
from redis.asyncio import Redis
from redis.exceptions import RedisError


class AnalysisSignal(BaseModel):
    analysis_job_id: str = Field(min_length=1)


class AnalysisQueueError(RuntimeError):
    """Raised when Redis cannot send or receive an analysis wake-up signal."""


class AnalysisQueue(Protocol):
    async def enqueue(self, signal: AnalysisSignal) -> None: ...

    async def dequeue(self, timeout_seconds: int = 5) -> AnalysisSignal | None: ...

    async def close(self) -> None: ...


class AnalysisQueueConfig(Protocol):
    redis_url: str
    analysis_queue_name: str


class RedisAnalysisQueue:
    """Redis wake-up signals for durable analysis jobs stored in MongoDB."""

    def __init__(self, client: Redis, *, queue_name: str) -> None:
        self.client = client
        self.queue_name = queue_name

    @classmethod
    def from_settings(
        cls,
        settings: AnalysisQueueConfig,
    ) -> "RedisAnalysisQueue":
        client = Redis.from_url(settings.redis_url, decode_responses=True)
        return cls(client, queue_name=settings.analysis_queue_name)

    async def enqueue(self, signal: AnalysisSignal) -> None:
        try:
            await self.client.rpush(
                self.queue_name,
                signal.model_dump_json(),
            )
        except RedisError as exc:
            raise AnalysisQueueError("Unable to signal analysis job") from exc

    async def dequeue(self, timeout_seconds: int = 5) -> AnalysisSignal | None:
        try:
            item = await self.client.blpop(
                self.queue_name,
                timeout=max(1, timeout_seconds),
            )
        except RedisError as exc:
            raise AnalysisQueueError("Unable to read analysis queue") from exc

        if item is None:
            return None

        _, payload = item
        try:
            return AnalysisSignal.model_validate_json(payload)
        except ValidationError as exc:
            raise AnalysisQueueError("Discarded invalid analysis signal") from exc

    async def close(self) -> None:
        await self.client.aclose()
