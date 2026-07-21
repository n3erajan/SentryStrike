from unittest.mock import AsyncMock

import pytest

from shared.models.scan import ScanAuthAccount, ScanAuthRole
from shared.scan_queue import RedisScanQueue, ScanJob
from shared.schemas.scan_schema import ScanConfig


def _queue(client: AsyncMock) -> RedisScanQueue:
    return RedisScanQueue(
        client,
        queue_name="test:scans",
        cancel_key_prefix="test:cancel",
        cancel_ttl_seconds=120,
        lease_key_prefix="test:lease",
        lease_ttl_seconds=30,
    )


@pytest.mark.asyncio
async def test_enqueue_serializes_credentials_and_config() -> None:
    client = AsyncMock()
    queue = _queue(client)
    job = ScanJob(
        scan_id="scan-1",
        auth_accounts=[
            ScanAuthAccount(
                role=ScanAuthRole.main,
                username="user@example.test",
                password="secret",
            )
        ],
        scan_config=ScanConfig(crawl_depth=2),
    )

    await queue.enqueue(job)

    queue_name, payload = client.rpush.await_args.args
    assert queue_name == "test:scans"
    restored = ScanJob.model_validate_json(payload)
    assert restored.auth_accounts[0].password == "secret"
    assert restored.scan_config.crawl_depth == 2


@pytest.mark.asyncio
async def test_dequeue_parses_and_removes_claimed_job() -> None:
    job = ScanJob(scan_id="scan-2")
    client = AsyncMock()
    client.blpop.return_value = ("test:scans", job.model_dump_json())
    queue = _queue(client)

    restored = await queue.dequeue()

    client.blpop.assert_awaited_once_with("test:scans", timeout=0)
    assert restored.scan_id == "scan-2"


@pytest.mark.asyncio
async def test_cancellation_key_uses_bounded_ttl() -> None:
    client = AsyncMock()
    queue = _queue(client)

    await queue.request_cancel("scan-3")

    client.set.assert_awaited_once_with("test:cancel:scan-3", "1", ex=120)


@pytest.mark.asyncio
async def test_request_cancel_also_publishes_for_immediate_delivery() -> None:
    client = AsyncMock()
    queue = _queue(client)

    await queue.request_cancel("scan-3")

    # Durable key (backstop) plus a publish on the cancel channel so a running
    # worker's watcher can cancel the scan task immediately.
    client.publish.assert_awaited_once_with("test:cancel:channel", "scan-3")


@pytest.mark.asyncio
async def test_lease_renew_sets_key_with_ttl() -> None:
    client = AsyncMock()
    queue = _queue(client)

    await queue.renew_lease("scan-5")

    client.set.assert_awaited_once_with("test:lease:scan-5", "1", ex=30)


@pytest.mark.asyncio
async def test_is_lease_alive_checks_key_existence() -> None:
    client = AsyncMock()
    client.exists.return_value = 1
    queue = _queue(client)

    assert await queue.is_lease_alive("scan-5") is True
    client.exists.assert_awaited_once_with("test:lease:scan-5")


@pytest.mark.asyncio
async def test_clear_lease_deletes_key() -> None:
    client = AsyncMock()
    queue = _queue(client)

    await queue.clear_lease("scan-5")

    client.delete.assert_awaited_once_with("test:lease:scan-5")
