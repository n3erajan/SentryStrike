"""Background retention-purge worker.

Runs alongside the API and scan worker as a separate process. On the configured
interval it deletes each org's scans past their retention window (see
``RetentionService``). It mirrors the scan worker's shape: initialise the DB,
loop forever, and treat any single pass's failure as non-fatal so the schedule
survives a transient database or purge error.

Run once (e.g. for a manual sweep) with ``python -m app.cli purge-retention``.
"""

from __future__ import annotations

import asyncio
import logging

from app.config import get_settings
from app.core.retention import RetentionService
from shared.database.connection import close_db, init_db
from shared.utils.logger import configure_logging

logger = logging.getLogger(__name__)


async def run_retention_worker() -> None:
    """Initialise services, then run a purge pass on the configured interval forever."""
    settings = get_settings()
    configure_logging(log_level=settings.log_level)
    await init_db(settings)

    interval = settings.retention_purge_interval_seconds
    service = RetentionService()
    logger.info("retention worker started; purge interval=%ds", interval)
    try:
        while True:
            try:
                await service.purge_once()
            except Exception:  # noqa: BLE001 — a failed pass must not kill the schedule
                logger.exception("retention purge pass failed; will retry next interval")
            await asyncio.sleep(interval)
    finally:
        await close_db()


def main() -> None:
    try:
        asyncio.run(run_retention_worker())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
