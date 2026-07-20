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
    monkeypatch.setenv("CRAWL_BROWSER_WORKERS", "1")
    # A developer's local scanner/.env may point OAST at a live collaborator.
    # Left set, detectors that build an OAST client from settings (e.g. SSRF)
    # would attempt real callback/poll network requests during unit tests.
    # Neutralize them so tests exercise the OAST-unconfigured default path.
    monkeypatch.setenv("OAST_CALLBACK_BASE_URL", "")
    monkeypatch.setenv("OAST_POLL_URL", "")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()
