import asyncio
import logging
import pathlib
import re
from dataclasses import dataclass, field
from urllib import robotparser
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup

from app.config import get_settings
from app.core.crawler.url_parser import normalize_url, same_domain, normalize_for_dedupe

logger = logging.getLogger(__name__)

STATIC_EXTENSIONS = {
    # Stylesheets & scripts
    ".css", ".js", ".map",
    # Images
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".webp", ".bmp", ".tiff",
    # Fonts
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    # Media
    ".mp4", ".mp3", ".ogg", ".webm", ".avi",
    # Documents & data (not web endpoints)
    ".pdf", ".xml", ".json", ".csv", ".xls", ".xlsx",
    # Archives
    ".zip", ".tar", ".gz",
}


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
    session_cookies: dict[str, str] = field(default_factory=dict)


class WebSpider:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.session_cookies = {}

    async def crawl(self, root_url: str, max_depth: int | None = None) -> CrawlResult:
        max_depth = max_depth if max_depth is not None else self.settings.crawl_depth
        visited: set[str] = set()
        queue: list[tuple[str, int]] = []
        forms: list[HtmlForm] = []
        discovered_urls: list[str] = []

        def enqueue(url_candidate: str, depth: int):
            if max_depth is not None and depth > max_depth:
                return
            
            p = urlparse(url_candidate)
            ext = pathlib.PurePosixPath(p.path).suffix.lower()
            if ext in STATIC_EXTENSIONS:
                logger.debug("skipping static asset: %s", url_candidate)
                return

            norm = normalize_for_dedupe(url_candidate)
            if norm not in visited:
                visited.add(norm)
                queue.append((url_candidate, depth))

        enqueue(root_url, 0)


        robots = await self._load_robots(root_url)

        async with httpx.AsyncClient(
            timeout=self.settings.request_timeout_seconds,
            follow_redirects=True,
            headers={"User-Agent": "SentryStrikeScanner/1.0"},
        ) as client:
            # Perform authentication if configured
            await self._authenticate_session(client, root_url)

            # 1. Parse Sitemap directives from robots.txt if possible
            sitemap_urls = []
            try:
                robots_url = normalize_url(root_url, "/robots.txt")
                robots_response = await client.get(robots_url)
                if robots_response.status_code == 200:
                    for line in robots_response.text.splitlines():
                        if line.lower().startswith("sitemap:"):
                            parts = line.split(":", 1)
                            if len(parts) > 1:
                                sitemap_urls.append(parts[1].strip())
            except Exception as e:
                logger.warning("Failed to check sitemaps from robots.txt: %s", e)

            for sitemap_url in sitemap_urls:
                try:
                    resp = await client.get(sitemap_url)
                    if resp.status_code == 200:
                        locs = re.findall(r"<loc>(.*?)</loc>", resp.text, re.I)
                        for loc in locs:
                            loc_clean = loc.strip()
                            if loc_clean and same_domain(root_url, loc_clean):
                                enqueue(loc_clean, 0)
                except Exception as e:
                    logger.warning("Failed to fetch sitemap %s: %s", sitemap_url, e)

            # 2. Add common directory brute force paths
            common_paths = [
                "/admin", "/api", "/backup", "/db", "/config", "/settings", 
                "/setup", "/install", "/administrator", "/console", "/panel",
                "/private", "/db_backup", "/wp-admin", "/robots.txt", "/sitemap.xml",
                "/api/v1", "/phpmyadmin", "/.env", "/.git", "/backup.sql"
            ]
            for path in common_paths:
                brute_url = normalize_url(root_url, path)
                enqueue(brute_url, 0)

            # 3. Main crawling loop
            while queue and len(discovered_urls) < self.settings.crawl_max_urls:
                url, depth = queue.pop(0)
                if robots is not None and not robots.can_fetch("*", url):
                    continue

                try:
                    response = await client.get(url)
                except Exception as exc:
                    logger.warning("crawl failed for %s: %s", url, exc)
                    continue

                # Add to discovered_urls if request was successful/interesting
                if response.status_code in [200, 301, 302, 403]:
                    if url not in discovered_urls:
                        discovered_urls.append(url)

                if "text/html" not in response.headers.get("content-type", ""):
                    continue
                
                # Update cookies in case session updated
                self.session_cookies.update(dict(client.cookies))

                page_forms, links = self._parse_html(url, response.text)
                forms.extend(page_forms)

                # Add form actions as links so we can scan the endpoints
                for form in page_forms:
                    links.append(form.action)

                for link in links:
                    normalized = normalize_url(url, link)
                    if same_domain(root_url, normalized):
                        enqueue(normalized, depth + 1)

                await asyncio.sleep(max(0.01, 1.0 / self.settings.crawl_rate_limit_per_second))

        return CrawlResult(urls=discovered_urls, forms=forms, session_cookies=self.session_cookies)

    async def _authenticate_session(self, client: httpx.AsyncClient, root_url: str):
        """Authenticate session using cookies or credentials."""
        # 1. Parse cookie string if provided
        if self.settings.authentication_cookie:
            cookies = {}
            for cookie in self.settings.authentication_cookie.split(";"):
                cookie = cookie.strip()
                if "=" in cookie:
                    k, v = cookie.split("=", 1)
                    cookies[k] = v
            client.cookies.update(cookies)
            self.session_cookies.update(cookies)
            logger.info("Session authenticated via provided cookie string")
            return

        # 2. Check if username and password are provided
        username = self.settings.authentication_username
        password = self.settings.authentication_password
        if username and password:
            try:
                # First, request login page to extract CSRF tokens and baseline cookies
                login_urls = [
                    normalize_url(root_url, "/login.php"),
                    normalize_url(root_url, "/login"),
                    root_url
                ]
                
                login_response = None
                login_url = root_url
                for l_url in login_urls:
                    try:
                        resp = await client.get(l_url)
                        if resp.status_code == 200 and ("login" in resp.text.lower() or "username" in resp.text.lower()):
                            login_response = resp
                            login_url = l_url
                            break
                    except Exception:
                        continue
                
                if not login_response:
                    # Fallback to root url
                    login_url = root_url
                    login_response = await client.get(login_url)

                # Parse HTML for login form and input fields
                soup = BeautifulSoup(login_response.text, "html.parser")
                form = soup.find("form")
                
                # Build payload
                payload = {}
                action = login_url
                method = "POST"
                
                if form:
                    action = normalize_url(login_url, form.get("action", ""))
                    method = form.get("method", "POST").upper()
                    
                    # Fill inputs
                    for inp in form.find_all(["input", "select", "textarea"]):
                        name = inp.get("name")
                        if not name:
                            continue
                        val = inp.get("value", "")
                        inp_type = inp.get("type", "text").lower()
                        autocomplete = inp.get("autocomplete", "").lower()
                        
                        # Identify fields
                        name_lower = name.lower()
                        if inp_type == "email" or autocomplete in ("username", "email"):
                            payload[name] = username
                        elif inp_type == "password" or autocomplete in ("current-password", "password"):
                            payload[name] = password
                        elif "user" in name_lower or "email" in name_lower or "login" in name_lower:
                            payload[name] = username
                        elif "pass" in name_lower:
                            payload[name] = password
                        elif inp_type == "hidden":
                            payload[name] = val
                        elif inp_type in ["submit", "button"] and "submit" in name_lower:
                            payload[name] = val or "Submit"

                    submit_btn = form.find("input", attrs={"type": "submit"})
                    if submit_btn and submit_btn.get("name"):
                        payload[submit_btn["name"]] = submit_btn.get("value", "Submit")

                # Send POST request
                if method == "POST":
                    resp = await client.post(action, data=payload)
                else:
                    resp = await client.get(action, params=payload)
                
                # Check for successful authentication
                if resp.status_code in [200, 302]:
                    logger.info("Authentication request sent. Session cookies: %s", dict(client.cookies))
                
            except Exception as e:
                logger.error("Authentication failed: %s", e)

        self.session_cookies.update(dict(client.cookies))

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

        # Extract links from multiple tags: a, iframe, script, link, img
        links = []
        for tag, attr in [("a", "href"), ("iframe", "src"), ("script", "src"), ("link", "href"), ("img", "src")]:
            for element in soup.find_all(tag):
                val = element.get(attr, "")
                if val and not val.startswith("javascript:"):
                    links.append(val)

        # Follow meta refresh redirects
        meta_refresh = soup.find("meta", attrs={"http-equiv": re.compile("^refresh$", re.I)})
        if meta_refresh:
            content = meta_refresh.get("content", "")
            match = re.search(r"url=['\"]?([^'\";]+)", content, re.I)
            if match:
                links.append(match.group(1))

        # Follow JS redirects
        for script in soup.find_all("script"):
            if script.string:
                for match in re.finditer(r"(?:window|document)\.location(?:\.href)?\s*=\s*['\"]([^'\"]+)['\"]", script.string, re.I):
                    links.append(match.group(1))
                for match in re.finditer(r"location\.replace\(['\"]([^'\"]+)['\"]\)", script.string, re.I):
                    links.append(match.group(1))

        forms: list[HtmlForm] = []
        for form in soup.find_all("form"):
            action = form.get("action", page_url)
            method = form.get("method", "GET").upper()
            inputs = []
            for inp in form.find_all(["input", "textarea", "select", "button"]):
                name = inp.get("name")
                if not name:
                    continue
                if inp.name == "textarea":
                    inp_type = "textarea"
                elif inp.name == "select":
                    inp_type = "select"
                elif inp.name == "button":
                    inp_type = getattr(inp, "type", "button") if hasattr(inp, "type") else "button"
                else:
                    inp_type = inp.get("type", "text")
                inputs.append(FormInput(name=name, input_type=inp_type))
            forms.append(HtmlForm(page_url=page_url, action=normalize_url(page_url, action), method=method, inputs=inputs))

        return forms, links
