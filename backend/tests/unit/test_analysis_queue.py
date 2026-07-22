from unittest.mock import AsyncMock

import pytest

from shared.analysis_queue import AnalysisSignal, RedisAnalysisQueue


def _queue(client: AsyncMock) -> RedisAnalysisQueue:
    return RedisAnalysisQueue(client, queue_name="test:analysis")


@pytest.mark.asyncio
async def test_enqueue_contains_only_opaque_analysis_job_id() -> None:
    client = AsyncMock()
    queue = _queue(client)

    await queue.enqueue(AnalysisSignal(analysis_job_id="job-1"))

    queue_name, payload = client.rpush.await_args.args
    assert queue_name == "test:analysis"
    assert AnalysisSignal.model_validate_json(payload).model_dump() == {
        "analysis_job_id": "job-1"
    }


@pytest.mark.asyncio
async def test_dequeue_uses_bounded_wait_so_mongo_polling_can_run() -> None:
    client = AsyncMock()
    client.blpop.return_value = None
    queue = _queue(client)

    signal = await queue.dequeue(timeout_seconds=7)

    assert signal is None
    client.blpop.assert_awaited_once_with("test:analysis", timeout=7)


@pytest.mark.asyncio
async def test_dequeue_parses_analysis_signal() -> None:
    client = AsyncMock()
    client.blpop.return_value = (
        "test:analysis",
        AnalysisSignal(analysis_job_id="job-2").model_dump_json(),
    )
    queue = _queue(client)

    signal = await queue.dequeue()

    assert signal is not None
    assert signal.analysis_job_id == "job-2"

