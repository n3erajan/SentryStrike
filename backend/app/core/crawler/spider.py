import asyncio
import logging
import re
from dataclasses import dataclass, field
from urllib import robotparser

import httpx
from bs4 import BeautifulSoup

from app.config import get_settings
from app.core.crawler.url_parser import normalize_url, same_domain

logger = logging.getLogger(__name__)


@dataclass
class FormInput:
    name: str
    input_type: str = "text"


@dataclass
class HtmlForm:
    page_url: str
    action: str
    method: str
    inputs: list[FormInput] = field(default_factory=list)


@dataclass
class CrawlResult:
    urls: list[str] = field(default_factory=list)
    forms: list[HtmlForm] = field(default_factory=list)


class WebSpider:
    def __init__(self) -> None:
        self.settings = get_settings()

    async def crawl(self, root_url: str, max_depth: int | None = None) -> CrawlResult:
        max_depth = max_depth if max_depth is not None else self.settings.crawl_depth
        visited: set[str] = set()
        queue: list[tuple[str, int]] = [(root_url, 0)]
        forms: list[HtmlForm] = []
        discovered_urls: list[str] = []

        robots = await self._load_robots(root_url)

        async with httpx.AsyncClient(
            timeout=self.settings.request_timeout_seconds,
            follow_redirects=True,
            headers={"User-Agent": "SentryStrikeScanner/1.0"},
        ) as client:
            while queue and len(discovered_urls) < self.settings.crawl_max_urls:
                url, depth = queue.pop(0)
                if url in visited or depth > max_depth:
                    continue
                if robots is not None and not robots.can_fetch("*", url):
                    continue

                visited.add(url)
                try:
                    response = await client.get(url)
                except Exception as exc:
                    logger.warning("crawl failed for %s: %s", url, exc)
                    continue

                if "text/html" not in response.headers.get("content-type", ""):
                    continue

                discovered_urls.append(url)
                page_forms, links = self._parse_html(url, response.text)
                forms.extend(page_forms)

                for link in links:
                    normalized = normalize_url(url, link)
                    if same_domain(root_url, normalized) and normalized not in visited:
                        queue.append((normalized, depth + 1))

                await asyncio.sleep(max(0.01, 1.0 / self.settings.crawl_rate_limit_per_second))

        return CrawlResult(urls=discovered_urls, forms=forms)

    async def _load_robots(self, root_url: str) -> robotparser.RobotFileParser | None:
        robots_url = normalize_url(root_url, "/robots.txt")
        parser = robotparser.RobotFileParser()
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(robots_url)
            if response.status_code >= 400:
                return None
            parser.parse(response.text.splitlines())
            return parser
        except Exception:
            return None

    def _parse_html(self, page_url: str, html: str) -> tuple[list[HtmlForm], list[str]]:
        soup = BeautifulSoup(html, "html.parser")

        links = [a.get("href", "") for a in soup.find_all("a") if a.get("href")]
        links = [link for link in links if not link.startswith("javascript:")]

        forms: list[HtmlForm] = []
        for form in soup.find_all("form"):
            action = form.get("action", page_url)
            method = form.get("method", "GET").upper()
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                inputs.append(FormInput(name=name, input_type=inp.get("type", "text")))
            forms.append(HtmlForm(page_url=page_url, action=normalize_url(page_url, action), method=method, inputs=inputs))

        if re.search(r"\.php\?|\.aspx\?", page_url, flags=re.I):
            links.append(page_url)

        return forms, links
