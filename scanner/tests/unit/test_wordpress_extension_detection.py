"""Detected WordPress extensions must carry the slug the Wordfence feed needs."""

import pytest

from app.integrations import wappalyzer
from app.integrations.wappalyzer import TechnologyDetector


class FakeCrawl:
    browser_available = False

    def __init__(self, html: str) -> None:
        self.spa_root_html = html
        self.requests = []


WP_HTML = """
<html><head>
<meta name="generator" content="WordPress 7.1" />
<link rel='stylesheet' href='/wp-includes/css/dist/block-library/style.min.css?ver=7.1'>
<link rel='stylesheet' href='/wp-content/plugins/smart-slider-3/admin/a.css?ver=3.5.1'>
<link rel='stylesheet' href='/wp-content/plugins/akismet/a.css?ver=7.1'>
<link rel='stylesheet' href='/wp-content/themes/astra/style.css?ver=4.6.2'>
</head><body></body></html>
"""


@pytest.mark.asyncio
async def test_detected_plugins_and_themes_carry_slug_and_version() -> None:
    components = await TechnologyDetector().detect(
        "https://t.test", crawl_result=FakeCrawl(WP_HTML)
    )
    by_slug = {c.slug: c for c in components if c.slug}

    assert by_slug["smart-slider-3"].version == "3.5.1"
    assert by_slug["smart-slider-3"].category == "wordpress plugins"
    assert by_slug["astra"].version == "4.6.2"
    assert by_slug["astra"].category == "wordpress themes"


@pytest.mark.asyncio
async def test_plugin_version_matching_core_is_left_unresolved() -> None:
    """Akismet's ?ver=7.1 is WordPress's core version, not Akismet's."""
    components = await TechnologyDetector().detect(
        "https://t.test", crawl_result=FakeCrawl(WP_HTML)
    )
    akismet = next(c for c in components if c.slug == "akismet")

    assert akismet.version is None


@pytest.mark.asyncio
async def test_a_fingerprinted_extension_gets_its_slug_backfilled_not_duplicated() -> None:
    """The engine names "Smart Slider 3"; the asset path gives its slug."""
    components = await TechnologyDetector().detect(
        "https://t.test", crawl_result=FakeCrawl(WP_HTML)
    )
    sliders = [c for c in components if "slider" in c.name.lower()]

    assert len(sliders) == 1
    assert sliders[0].slug == "smart-slider-3"


@pytest.mark.asyncio
async def test_wordpress_core_itself_gets_no_slug() -> None:
    components = await TechnologyDetector().detect(
        "https://t.test", crawl_result=FakeCrawl(WP_HTML)
    )
    core = next(c for c in components if c.name == "WordPress")

    assert core.version == "7.1"
    assert core.slug is None
