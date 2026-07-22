from __future__ import annotations

import logging
from enum import Enum
from typing import AsyncIterator, Protocol

from pydantic import BaseModel, Field, ValidationError, model_validator
from redis.asyncio import Redis
from redis.exceptions import RedisError

from shared.models.scan import ScanAuthAccount
from shared.schemas.scan_schema import ScanConfig

logger = logging.getLogger(__name__)


class ScanJobKind(str, Enum):
    full_scan = "full_scan"
    finding_reverification = "finding_reverification"


class ScanJob(BaseModel):
    """A single unit of scan work placed on the shared queue.

    The payload travels between the backend API (producer) and scanner
    workers (consumers) via Redis. Credentials ride along as plaintext in the
    job payload only; they are removed from the queue once a worker claims the
    job and are never persisted to the database.
    """

    scan_id: str = Field(min_length=1)
    kind: ScanJobKind = ScanJobKind.full_scan
    reverification_job_id: str | None = None
    auth_accounts: list[ScanAuthAccount] = Field(default_factory=list)
    scan_config: ScanConfig | None = None

    @model_validator(mode="after")
    def _require_reverification_id(self) -> "ScanJob":
        if (
            self.kind == ScanJobKind.finding_reverification
            and not self.reverification_job_id
        ):
            raise ValueError("reverification_job_id is required for re-verification jobs")
        if self.kind == ScanJobKind.full_scan and self.reverification_job_id is not None:
            raise ValueError("full scan jobs cannot reference a re-verification job")
        return self


class ScanQueueError(RuntimeError):
    """Raised when the shared scan queue cannot complete an operation."""


class ScanQueue(Protocol):
    """Abstract contract for the scan job queue.

    Both the backend API and scanner workers depend on this interface, which
    keeps the concrete transport (Redis) swappable without touching either
    service's business logic.
    """

    async def enqueue(self, job: ScanJob) -> None: ...

    async def dequeue(self) -> ScanJob: ...

    async def request_cancel(self, scan_id: str) -> None: ...

    async def is_cancelled(self, scan_id: str) -> bool: ...

    async def clear_cancel(self, scan_id: str) -> None: ...

    def watch_cancellations(self) -> AsyncIterator[str]: ...

    async def renew_lease(self, scan_id: str) -> None: ...

    async def is_lease_alive(self, scan_id: str) -> bool: ...

    async def clear_lease(self, scan_id: str) -> None: ...

    async def close(self) -> None: ...


class ScanQueueConfig(Protocol):
    redis_url: str
    scan_queue_name: str
    scan_cancel_key_prefix: str
    scan_cancel_ttl_seconds: int
    worker_heartbeat_prefix: str
    worker_heartbeat_ttl_seconds: int
    scan_lease_key_prefix: str
    scan_lease_ttl_seconds: int


class RedisScanQueue:
    """Redis-backed implementation of the scan job queue.

    Jobs are pushed onto a Redis list (``RPUSH``) and claimed with a blocking
    pop (``BLPOP``) so workers idle efficiently instead of polling. Cancellation
    and worker liveness are tracked with short-lived keys rather than queue
    messages, because they are signals — not work items.
    """
    def __init__(
        self,
        client: Redis,
        *,
        queue_name: str,
        cancel_key_prefix: str,
        cancel_ttl_seconds: int,
        heartbeat_key_prefix: str = "sentrystrike:worker:heartbeat",
        heartbeat_ttl_seconds: int = 20,
        lease_key_prefix: str = "sentrystrike:scan:lease",
        lease_ttl_seconds: int = 30,
    ) -> None:
        self.client = client
        self.queue_name = queue_name
        self.cancel_key_prefix = cancel_key_prefix.rstrip(":")
        self.cancel_ttl_seconds = cancel_ttl_seconds
        self.heartbeat_key_prefix = heartbeat_key_prefix.rstrip(":")
        self.heartbeat_ttl_seconds = heartbeat_ttl_seconds
        self.lease_key_prefix = lease_key_prefix.rstrip(":")
        self.lease_ttl_seconds = lease_ttl_seconds
        # Pub/Sub channel carrying cancellation signals for immediate delivery.
        # The cancel key (below) remains the durable backstop; this channel is
        # the low-latency fast path a running worker subscribes to.
        self.cancel_channel = f"{self.cancel_key_prefix}:channel"

    @classmethod
    def from_settings(
        cls,
        settings: ScanQueueConfig,
    ) -> RedisScanQueue:
        """Build a queue client from the calling service's settings."""
        client = Redis.from_url(settings.redis_url, decode_responses=True)
        return cls(
            client,
            queue_name=settings.scan_queue_name,
            cancel_key_prefix=settings.scan_cancel_key_prefix,
            cancel_ttl_seconds=settings.scan_cancel_ttl_seconds,
            heartbeat_key_prefix=settings.worker_heartbeat_prefix,
            heartbeat_ttl_seconds=settings.worker_heartbeat_ttl_seconds,
            lease_key_prefix=settings.scan_lease_key_prefix,
            lease_ttl_seconds=settings.scan_lease_ttl_seconds,
        )

    def _cancel_key(self, scan_id: str) -> str:
        """Return the Redis key that flags a scan for cancellation."""
        return f"{self.cancel_key_prefix}:{scan_id}"

    def _lease_key(self, scan_id: str) -> str:
        """Return the Redis key that proves a worker is actively running a scan."""
        return f"{self.lease_key_prefix}:{scan_id}"

    async def enqueue(self, job: ScanJob) -> None:
        try:
            await self.client.rpush(
                self.queue_name,
                job.model_dump_json(exclude_none=True),
            )
        except RedisError as exc:
            raise ScanQueueError("Unable to enqueue scan") from exc

    async def dequeue(self) -> ScanJob:
        try:
            item = await self.client.blpop(self.queue_name, timeout=0)
        except RedisError as exc:
            raise ScanQueueError("Unable to read from scan queue") from exc

        if item is None:
            raise ScanQueueError("Redis returned no scan job")

        _, payload = item
        try:
            return ScanJob.model_validate_json(payload)
        except ValidationError as exc:
            raise ScanQueueError("Discarded invalid scan job payload") from exc

    async def request_cancel(self, scan_id: str) -> None:
        # Two signals, deliberately: the key is the durable backstop (survives a
        # worker that is between subscribing, restarting, or not yet running the
        # scan) and the publish is the low-latency fast path a running worker's
        # watcher reacts to within milliseconds.
        try:
            await self.client.set(
                self._cancel_key(scan_id),
                "1",
                ex=self.cancel_ttl_seconds,
            )
            await self.client.publish(self.cancel_channel, scan_id)
        except RedisError as exc:
            raise ScanQueueError("Unable to request scan cancellation") from exc

    async def is_cancelled(self, scan_id: str) -> bool:
        try:
            return bool(await self.client.exists(self._cancel_key(scan_id)))
        except RedisError as exc:
            raise ScanQueueError("Unable to check scan cancellation") from exc

    async def clear_cancel(self, scan_id: str) -> None:
        try:
            await self.client.delete(self._cancel_key(scan_id))
        except RedisError as exc:
            raise ScanQueueError("Unable to clear scan cancellation") from exc

    async def watch_cancellations(self) -> AsyncIterator[str]:
        """Yield scan ids as cancellation requests are published.

        Subscribes to the cancel channel and yields each published ``scan_id``.
        A running worker consumes this to cancel the in-flight scan task the
        moment a request arrives, instead of waiting for the next phase-boundary
        poll of the cancel key. The subscribe/publish race (a publish that lands
        between a worker starting and this subscription being live) is closed by
        the caller doing an initial ``is_cancelled`` key read after subscribing.
        """
        pubsub = self.client.pubsub()
        try:
            await pubsub.subscribe(self.cancel_channel)
            async for message in pubsub.listen():
                if message.get("type") != "message":
                    continue
                data = message.get("data")
                if data is None:
                    continue
                yield data if isinstance(data, str) else data.decode()
        except RedisError as exc:
            raise ScanQueueError("Unable to watch scan cancellations") from exc
        finally:
            try:
                await pubsub.unsubscribe(self.cancel_channel)
                await pubsub.aclose()
            except RedisError:
                logger.debug("failed to close cancel-channel pubsub cleanly")

    async def renew_lease(self, scan_id: str) -> None:
        """Refresh the per-scan lease, proving a worker is actively running it.

        The lease is a short-TTL key a running worker renews on a timer. If the
        worker dies, the key expires and the scan becomes detectable as orphaned.
        """
        try:
            await self.client.set(
                self._lease_key(scan_id),
                "1",
                ex=self.lease_ttl_seconds,
            )
        except RedisError as exc:
            raise ScanQueueError("Unable to renew scan lease") from exc

    async def is_lease_alive(self, scan_id: str) -> bool:
        """Return True while a worker holds a live lease on this scan."""
        try:
            return bool(await self.client.exists(self._lease_key(scan_id)))
        except RedisError as exc:
            raise ScanQueueError("Unable to check scan lease") from exc

    async def clear_lease(self, scan_id: str) -> None:
        try:
            await self.client.delete(self._lease_key(scan_id))
        except RedisError as exc:
            raise ScanQueueError("Unable to clear scan lease") from exc

    async def close(self) -> None:
        await self.client.aclose()

    def _heartbeat_key(self, worker_id: str) -> str:
        return f"{self.heartbeat_key_prefix}:{worker_id}"

    async def set_heartbeat(self, worker_id: str) -> None:
        try:
            await self.client.set(
                self._heartbeat_key(worker_id),
                "1",
                ex=self.heartbeat_ttl_seconds,
            )
        except RedisError as exc:
            raise ScanQueueError("Unable to set worker heartbeat") from exc

    async def clear_heartbeat(self, worker_id: str) -> None:
        try:
            await self.client.delete(self._heartbeat_key(worker_id))
        except RedisError as exc:
            raise ScanQueueError("Unable to clear worker heartbeat") from exc

    async def count_active_scanners(self) -> int:
        """Return the number of workers with a live heartbeat key."""
        try:
            keys = await self.client.keys(f"{self.heartbeat_key_prefix}:*")
            return len(keys)
        except RedisError as exc:
            raise ScanQueueError("Unable to count active workers") from exc
