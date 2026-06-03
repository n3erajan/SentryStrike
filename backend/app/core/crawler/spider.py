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
from app.utils.http_logging import make_httpx_response_logger
from app.utils.scan_http import create_scan_client

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
    value: str = ""


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


@dataclass
class AuthReplayState:
    login_url: str
    action: str
    method: str
    payload: dict[str, str]


class WebSpider:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.session_cookies = {}
        self._auth_replay_state: AuthReplayState | None = None
        self._configured_auth_cookies: dict[str, str] = {}

    def _snapshot_cookies(self, cookies: httpx.Cookies) -> dict[str, str]:
        snapshot: dict[str, str] = {}
        for cookie in cookies.jar:
            snapshot[cookie.name] = cookie.value
        return snapshot

    async def crawl(self, root_url: str, max_depth: int | None = None) -> CrawlResult:
        max_depth = max_depth if max_depth is not None else self.settings.crawl_depth
        visited: set[str] = set()
        queue = asyncio.Queue()
        forms: list[HtmlForm] = []
        discovered_urls: list[str] = []
        discovered_set: set[str] = set()
        lock = asyncio.Lock()

        def should_enqueue(url_candidate: str, depth: int) -> bool:
            if max_depth is not None and depth > max_depth:
                return False
            
            p = urlparse(url_candidate)
            ext = pathlib.PurePosixPath(p.path).suffix.lower()
            if ext in STATIC_EXTENSIONS:
                logger.debug("skipping static asset: %s", url_candidate)
                return False

            norm = normalize_for_dedupe(url_candidate)
            if norm not in visited:
                visited.add(norm)
                return True
            return False

        # Helper to safely call should_enqueue and put to queue
        async def safe_enqueue(url_candidate: str, depth: int):
            async with lock:
                if should_enqueue(url_candidate, depth):
                    await queue.put((url_candidate, depth))

        await safe_enqueue(root_url, 0)

        robots = await self._load_robots(root_url)

        async with create_scan_client(
            timeout=self.settings.request_timeout_seconds,
            follow_redirects=True,
            headers={"User-Agent": "SentryStrikeScanner/1.0"},
            event_hooks={"response": [make_httpx_response_logger("crawler", "crawl")]},
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
                                await safe_enqueue(loc_clean, 0)
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
                await safe_enqueue(brute_url, 0)

            # 3. Main crawling loop with concurrency
            import time
            rate_limit = self.settings.crawl_rate_limit_per_second
            request_interval = 1.0 / rate_limit if rate_limit > 0 else 0
            last_request_time = time.time()

            async def rate_limit_sleep():
                if request_interval <= 0:
                    return
                nonlocal last_request_time
                delay = 0
                async with lock:
                    now = time.time()
                    if last_request_time < now:
                        last_request_time = now
                    next_allowed = last_request_time + request_interval
                    delay = next_allowed - now
                    if delay > 0:
                        last_request_time = next_allowed
                    else:
                        last_request_time = now
                        delay = 0

                if delay > 0:
                    await asyncio.sleep(delay)

            async def worker():
                while True:
                    try:
                        async with lock:
                            if len(discovered_urls) >= self.settings.crawl_max_urls:
                                break
                        
                        item = await queue.get()
                        if item is None:
                            queue.task_done()
                            break
                        url, depth = item
                    except asyncio.CancelledError:
                        break

                    if robots is not None and not robots.can_fetch("*", url):
                        queue.task_done()
                        continue

                    # Respect rate limit
                    await rate_limit_sleep()

                    try:
                        response = await self._request_with_session_keeper(client, "GET", url)
                    except Exception as exc:
                        logger.warning("crawl failed for %s: %s", url, exc)
                        queue.task_done()
                        continue

                    async with lock:
                        if len(discovered_urls) >= self.settings.crawl_max_urls:
                            queue.task_done()
                            break

                        # Add to discovered_urls if request was successful/interesting
                        if response.status_code in [200, 301, 302, 403]:
                            if url not in discovered_set:
                                discovered_set.add(url)
                                discovered_urls.append(url)

                    if "text/html" not in response.headers.get("content-type", ""):
                        queue.task_done()
                        continue
                    
                    async with lock:
                        # Update cookies in case session updated
                        self.session_cookies.update(self._snapshot_cookies(client.cookies))

                    page_forms, links = self._parse_html(url, response.text)
                    
                    async with lock:
                        forms.extend(page_forms)

                    # Add form actions as links so we can scan the endpoints
                    for form in page_forms:
                        links.append(form.action)

                    for link in links:
                        normalized = normalize_url(url, link)
                        if same_domain(root_url, normalized):
                            await safe_enqueue(normalized, depth + 1)

                    queue.task_done()

            # Spawn concurrent workers
            concurrency = self.settings.scanner_concurrency
            workers = [asyncio.create_task(worker()) for _ in range(concurrency)]

            try:
                # Wait until queue is empty and all tasks are done, OR we reached max URLs
                join_task = asyncio.create_task(queue.join())
                while not join_task.done():
                    async with lock:
                        if len(discovered_urls) >= self.settings.crawl_max_urls:
                            break
                    await asyncio.sleep(0.1)
                
                if not join_task.done():
                    join_task.cancel()
            except Exception as e:
                logger.error("Error in crawl wait: %s", e)
            finally:
                # Cancel workers
                for w in workers:
                    w.cancel()
                await asyncio.gather(*workers, return_exceptions=True)

        return CrawlResult(urls=discovered_urls, forms=forms, session_cookies=self.session_cookies)

    async def fetch_single(self, target_url: str) -> CrawlResult:
        """Fetch one URL only — no link discovery, sitemaps, or path brute-force."""
        forms: list[HtmlForm] = []
        discovered_urls: list[str] = []

        async with create_scan_client(
            timeout=self.settings.request_timeout_seconds,
            follow_redirects=True,
            headers={"User-Agent": "SentryStrikeScanner/1.0"},
            event_hooks={"response": [make_httpx_response_logger("crawler", "fetch_single")]},
        ) as client:
            await self._authenticate_session(client, target_url)

            try:
                response = await self._request_with_session_keeper(client, "GET", target_url)
            except Exception as exc:
                logger.warning("fetch_single failed for %s: %s", target_url, exc)
                return CrawlResult(urls=[], forms=[], session_cookies=self.session_cookies)

            if response.status_code in {200, 301, 302, 403}:
                discovered_urls.append(target_url)

            if "text/html" in response.headers.get("content-type", ""):
                self.session_cookies.update(self._snapshot_cookies(client.cookies))
                page_forms, _ = self._parse_html(target_url, response.text)
                forms.extend(page_forms)

        return CrawlResult(urls=discovered_urls, forms=forms, session_cookies=self.session_cookies)

    async def _request_with_session_keeper(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        *,
        retry_on_login: bool = True,
        **kwargs,
    ) -> httpx.Response:
        response = await client.request(method, url, **kwargs)
        if not retry_on_login:
            return response

        if not self._session_keeper_enabled():
            return response

        if not self._looks_like_session_loss(response, url):
            return response

        logger.info("crawler session appears expired at %s; refreshing auth state and retrying once", url)
        await self._authenticate_session(client, url, force=True)
        return await client.request(method, url, **kwargs)

    def _session_keeper_enabled(self) -> bool:
        return bool(
            self.settings.authentication_cookie
            or (self.settings.authentication_username and self.settings.authentication_password)
            or self._auth_replay_state
        )

    def _looks_like_session_loss(self, response: httpx.Response, requested_url: str = "") -> bool:
        final_path = response.url.path.lower()
        requested_path = urlparse(requested_url).path.lower()
        if response.status_code in {401, 403, 419, 440}:
            return True
        if final_path != requested_path and any(token in final_path for token in ("/login", "/signin", "/auth", "/session")):
            return True
        content_type = response.headers.get("content-type", "").lower()
        if "text/html" not in content_type:
            return False
        body = response.text.lower()
        has_login_form = "<form" in body and any(token in body for token in ("password", "username", "login", "signin"))
        has_session_message = any(
            token in body
            for token in (
                "session expired",
                "please log in",
                "please login",
                "you must log in",
                "authentication required",
            )
        )
        return has_login_form and has_session_message

    async def _authenticate_session(self, client: httpx.AsyncClient, root_url: str, force: bool = False):
        """Authenticate session using cookies or credentials."""
        # 1. Parse cookie string if provided
        if self.settings.authentication_cookie:
            if not self._configured_auth_cookies or force:
                cookies = {}
                for cookie in self.settings.authentication_cookie.split(";"):
                    cookie = cookie.strip()
                    if "=" in cookie:
                        k, v = cookie.split("=", 1)
                        cookies[k] = v
                self._configured_auth_cookies = cookies
            cookies = self._configured_auth_cookies
            client.cookies.update(cookies)
            self.session_cookies.update(cookies)
            logger.info("Session authenticated via provided cookie string")
            return

        if force and self._auth_replay_state is not None:
            try:
                state = self._auth_replay_state
                await client.get(state.login_url)
                if state.method == "POST":
                    await client.post(state.action, data=state.payload)
                else:
                    await client.get(state.action, params=state.payload)
                self.session_cookies.update(self._snapshot_cookies(client.cookies))
                logger.info("Session refreshed via stored login replay state")
                return
            except Exception as e:
                logger.warning("Stored login replay failed, attempting fresh authentication: %s", e)

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
                    self._auth_replay_state = AuthReplayState(
                        login_url=login_url,
                        action=action,
                        method=method,
                        payload=dict(payload),
                    )
                    logger.info("Authentication request sent. Session cookies: %s", self._snapshot_cookies(client.cookies))
                
            except Exception as e:
                logger.error("Authentication failed: %s", e)

        self.session_cookies.update(self._snapshot_cookies(client.cookies))

    async def _load_robots(self, root_url: str) -> robotparser.RobotFileParser | None:
        robots_url = normalize_url(root_url, "/robots.txt")
        parser = robotparser.RobotFileParser()
        try:
            async with create_scan_client(timeout=5.0) as client:
                response = await client.get(robots_url)
            if response.status_code >= 400:
                return None
            parser.parse(response.text.splitlines())
            return parser
        except Exception:
            return None

    @staticmethod
    def _normalize_malformed_forms(html: str) -> str:
        """Convert self-closing <form ... /> tags into proper open tags.

        DVWA and other legacy PHP apps sometimes emit XML-style self-closing
        form tags. HTML parsers treat those as empty elements, so every input
        that follows becomes a sibling instead of a child of the form.
        """
        return re.sub(r"<form\b([^>]*?)/>", r"<form\1>", html, flags=re.I)

    def _parse_html(self, page_url: str, html: str) -> tuple[list[HtmlForm], list[str]]:
        soup = BeautifulSoup(self._normalize_malformed_forms(html), "html.parser")

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
                value = inp.get("value", "")
                if inp.name == "textarea":
                    value = inp.get_text("", strip=False)
                inputs.append(FormInput(name=name, input_type=inp_type, value=value))
            forms.append(HtmlForm(page_url=page_url, action=normalize_url(page_url, action), method=method, inputs=inputs))

        return forms, links
