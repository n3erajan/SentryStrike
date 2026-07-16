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
