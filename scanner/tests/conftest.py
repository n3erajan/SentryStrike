"""Scanner test defaults independent of local worker configuration.

Browser tests were written against serial crawl semantics unless they opt into
parallel workers explicitly. Tests also exercise scanner defaults rather than
values from a developer's local ``scanner/.env`` file.
"""

import pytest

from app.config import get_settings


@pytest.fixture(autouse=True)
def _isolated_scanner_settings(monkeypatch):
    monkeypatch.setenv("AI_ANALYSIS_ENABLED", "true")
    monkeypatch.setenv("CRAWL_BROWSER_ENABLED", "false")
    monkeypatch.setenv("CRAWL_BROWSER_WORKERS", "1")
    monkeypatch.setenv("SCAN_AUTH_USERNAME", "")
    monkeypatch.setenv("SCAN_AUTH_PASSWORD", "")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()
