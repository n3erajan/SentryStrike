"""Unit-test defaults.

The browser crawl (``BrowserDiscoveryEngine.crawl_into``) parallelizes over N
worker coroutines. The pre-existing browser tests were written against the
serial crawl and drive a single shared fake page, so they assume one worker.
Pin the default worker count to 1 for the unit suite so those tests keep their
deterministic serial semantics; the dedicated parallel-crawl tests opt into
``workers>1`` explicitly (via the ``BrowserDiscoveryEngine(workers=...)``
constructor arg), which overrides this default.
"""

import pytest

from app.config import get_settings


@pytest.fixture(autouse=True)
def _serial_browser_crawl_by_default(monkeypatch):
    monkeypatch.setenv("CRAWL_BROWSER_WORKERS", "1")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()
