import threading
import time
import logging
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
import httpx

from app.core.crawler import spider as spider_module
from app.core.crawler.models import CrawlState, RequestObservation
from app.core.crawler.spider import AuthReplayState, WebSpider
from app.core.detectors.sensitive_paths import SensitivePathsDetector


@pytest.fixture(autouse=True)
def _disable_real_browser(monkeypatch):
    """Unit tests must never launch a real browser (CI has no Chromium
    guarantee). Dynamic-discovery behaviour is covered via mocks. Tests can
    still opt in by overriding these env vars and clearing the settings cache."""
    monkeypatch.setenv("CRAWL_BROWSER_ENABLED", "false")
    monkeypatch.setenv("CRAWL_BROWSER_MODE", "never")


@pytest.mark.asyncio
async def test_run_browser_discovery_merges_partial_results_on_error(monkeypatch):
    """RC-1 regression: a truncated/erroring browser run still merges its partial
    observations into the crawl state (the merge runs in ``finally``)."""

    class _StubEngine:
        def __init__(self, max_interactions=25):
            self.max_interactions = max_interactions

        @staticmethod
        async def check_readiness():
            return True, None

        async def crawl_into(
            self,
            state,
            root_url,
            auth_cookies=None,
            auth_headers=None,
            routes=None,
            deadline=None,
        ):
            # Stream a partial observation, mark availability, then blow up —
            # simulating a timeout/exception mid-run.
            state.browser_available = True
            state.requests.append(
                RequestObservation(url="http://spa.test/api/x", method="POST")
            )
            state.browser_forms_discovered += 1
            state.browser_error = "truncated mid-run"
            raise RuntimeError("simulated browser crash")

    monkeypatch.setattr(spider_module, "BrowserDiscoveryEngine", _StubEngine)

    spider = WebSpider()
    crawl_state = CrawlState()
    await spider._run_browser_discovery(crawl_state, "http://spa.test/", ["/a", "/b"])

    # Partial observation survived the crash and was merged.
    assert len(crawl_state.requests) == 1
    assert crawl_state.requests[0].url == "http://spa.test/api/x"
    assert crawl_state.browser_available is True
    assert crawl_state.browser_forms_discovered == 1
    assert crawl_state.browser_error == "truncated mid-run"


@pytest.mark.parametrize(
    "enabled,mode,is_spa,expected",
    [
        (False, "auto", True, True),      # SPA in auto -> run
        (False, "auto", False, False),    # non-SPA in auto -> skip
        (False, "always", False, True),   # always -> run regardless
        (False, "never", True, False),    # never -> skip even for SPA
        (True, "never", False, True),     # legacy enabled overrides mode
    ],
)
def test_should_run_browser_decision_matrix(monkeypatch, enabled, mode, is_spa, expected):
    monkeypatch.setenv("CRAWL_BROWSER_ENABLED", "true" if enabled else "false")
    monkeypatch.setenv("CRAWL_BROWSER_MODE", mode)
    get_settings = __import__("app.config", fromlist=["get_settings"]).get_settings
    get_settings.cache_clear()
    try:
        spider = WebSpider()
        assert spider._should_run_browser(is_spa) is expected
    finally:
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_run_browser_discovery_degrades_when_playwright_unavailable(monkeypatch):
    class _UnreadyEngine:
        def __init__(self, max_interactions=25):
            raise AssertionError("engine must not be constructed when unavailable")

        @staticmethod
        async def check_readiness():
            return False, "Playwright import failed: boom"

    monkeypatch.setattr(spider_module, "BrowserDiscoveryEngine", _UnreadyEngine)

    spider = WebSpider()
    crawl_state = CrawlState()
    await spider._run_browser_discovery(crawl_state, "http://spa.test/", ["/a"])

    assert crawl_state.browser_available is False
    assert "Playwright import failed" in crawl_state.browser_error


class MultiPageHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/", "/index"):
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b'<html><body><a href="/xss/">xss</a></body></html>')
        elif self.path.startswith("/xss"):
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(
                b'<html><body><form action="/xss/submit" method="GET">'
                b'<input type="text" name="name" value=""/></form></body></html>'
            )
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


class SpaHandler(BaseHTTPRequestHandler):
    shell = b"""<html><head><title>SPA</title><script src="/assets/app.js"></script></head><body><div id="root"></div></body></html>"""

    def do_GET(self):
        if self.path == "/assets/app.js":
            self.send_response(200)
            self.send_header("Content-type", "application/javascript")
            self.end_headers()
            self.wfile.write(
                b"const routes=[{path:'/dashboard'},{path:'/users/:id'}];"
                b"fetch('/api/users', {method:'POST', body: JSON.stringify({name:'a'})});"
                b"const gql='/graphql'; query CurrentUser($id: ID!) { user(id:$id){name} }"
            )
        elif self.path.startswith("/assets/"):
            self.send_response(404)
            self.end_headers()
        else:
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(self.shell)

    def log_message(self, format, *args):
        pass


class SpaSensitivePathsHandler(BaseHTTPRequestHandler):
    shell = (
        b"""<html><head><title>SPA</title><script src="/assets/app.js"></script></head>"""
        b"""<body><div id="root"></div><script>window.debug=true</script></body></html>"""
    )

    def do_GET(self):
        if self.path == "/.env":
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"DB_PASSWORD=secret\nAPP_KEY=base64:test")
        else:
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(self.shell)

    def log_message(self, format, *args):
        pass


def _start_server(port: int) -> tuple[HTTPServer, threading.Thread]:
    httpd = HTTPServer(("127.0.0.1", port), MultiPageHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.3)
    return httpd, thread


def _start_spa_server(port: int) -> tuple[HTTPServer, threading.Thread]:
    httpd = HTTPServer(("127.0.0.1", port), SpaHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.3)
    return httpd, thread


def _start_spa_sensitive_paths_server(port: int) -> tuple[HTTPServer, threading.Thread]:
    httpd = HTTPServer(("127.0.0.1", port), SpaSensitivePathsHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.3)
    return httpd, thread


@pytest.mark.asyncio
async def test_fetch_single_does_not_follow_links(monkeypatch):
    monkeypatch.setenv("CRAWL_DEPTH", "3")
    monkeypatch.setenv("CRAWL_MAX_URLS", "50")
    get_settings = __import__("app.config", fromlist=["get_settings"]).get_settings
    get_settings.cache_clear()

    httpd, thread = _start_server(8091)
    try:
        spider = WebSpider()
        result = await spider.fetch_single("http://127.0.0.1:8091/xss/")

        assert result.urls == ["http://127.0.0.1:8091/xss/"]
        assert len(result.forms) == 1
        assert result.forms[0].action.endswith("/xss/submit")
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=1)
        get_settings.cache_clear()


def test_parse_html_self_closing_form_includes_file_input():
    """DVWA-style <form ... /> must not orphan following inputs."""
    spider = WebSpider()
    html = (
        '<form enctype="multipart/form-data" action="#" method="POST" />\n'
        '<input type="hidden" name="MAX_FILE_SIZE" value="100000" />\n'
        '<input name="uploaded" type="file" />\n'
        '<input type="submit" name="Upload" value="Upload" />\n'
        "</form>\n"
    )

    forms, _ = spider._parse_html("http://example.com/dvwa/vulnerabilities/upload/", html)

    assert len(forms) == 1
    input_types = {inp.name: inp.input_type for inp in forms[0].inputs}
    assert input_types["uploaded"] == "file"
    assert input_types["MAX_FILE_SIZE"] == "hidden"
    assert input_types["Upload"] == "submit"


class FakeSessionClient:
    def __init__(self) -> None:
        self.request_count = 0
        self.replayed = False
        self.cookies = httpx.Cookies()

    async def request(self, method: str, url: str, **kwargs):
        self.request_count += 1
        if self.request_count == 1:
            return httpx.Response(
                200,
                headers={"content-type": "text/html"},
                text="<html><form><input name='username'><input type='password' name='password'>Session expired</form></html>",
                request=httpx.Request(method, "http://example.test/login"),
            )
        return httpx.Response(
            200,
            headers={"content-type": "text/html"},
            text="<html>private area</html>",
            request=httpx.Request(method, url),
        )

    async def get(self, url: str, **kwargs):
        return httpx.Response(200, text="<html>login</html>", request=httpx.Request("GET", url))

    async def post(self, url: str, data=None, **kwargs):
        self.replayed = True
        self.cookies.set("sessionid", "fresh")
        return httpx.Response(200, text="<html>ok</html>", request=httpx.Request("POST", url))


@pytest.mark.asyncio
async def test_session_keeper_reauthenticates_and_retries_login_bounce():
    spider = WebSpider()
    spider._auth_replay_state = AuthReplayState(
        login_url="http://example.test/login",
        action="http://example.test/login",
        method="POST",
        payload={"username": "user", "password": "pass"},
    )
    client = FakeSessionClient()

    response = await spider._request_with_session_keeper(client, "GET", "http://example.test/private")

    assert response.text == "<html>private area</html>"
    assert client.replayed is True
    assert client.request_count == 2


@pytest.mark.asyncio
async def test_crawl_discovers_linked_paths(monkeypatch):
    monkeypatch.setenv("CRAWL_DEPTH", "2")
    monkeypatch.setenv("CRAWL_MAX_URLS", "50")
    get_settings = __import__("app.config", fromlist=["get_settings"]).get_settings
    get_settings.cache_clear()

    httpd, thread = _start_server(8092)
    try:
        spider = WebSpider()
        result = await spider.crawl("http://127.0.0.1:8092/")

        discovered_paths = {url.split("8092", 1)[-1] for url in result.urls}
        assert "/xss/" in discovered_paths or "/xss" in discovered_paths
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=1)
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_crawl_logs_finished_inventory(monkeypatch, caplog):
    monkeypatch.setenv("CRAWL_DEPTH", "2")
    monkeypatch.setenv("CRAWL_MAX_URLS", "50")
    get_settings = __import__("app.config", fromlist=["get_settings"]).get_settings
    get_settings.cache_clear()

    httpd, thread = _start_server(8095)
    try:
        spider = WebSpider()
        with caplog.at_level(logging.INFO, logger="app.core.crawler.spider"):
            await spider.crawl("http://127.0.0.1:8095/")

        messages = [record.getMessage() for record in caplog.records]
        assert any("crawler finished for http://127.0.0.1:8095/" in message for message in messages)
        assert any("crawler route: url=http://127.0.0.1:8095/xss/submit" in message and "GET:form:name" in message for message in messages)
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=1)
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_crawl_extracts_spa_js_routes_and_api_inventory(monkeypatch):
    monkeypatch.setenv("CRAWL_DEPTH", "2")
    monkeypatch.setenv("CRAWL_MAX_URLS", "50")
    get_settings = __import__("app.config", fromlist=["get_settings"]).get_settings
    get_settings.cache_clear()

    httpd, thread = _start_spa_server(8093)
    try:
        spider = WebSpider()
        result = await spider.crawl("http://127.0.0.1:8093/")

        route_urls = {route.url for route in result.routes}
        api_urls = {endpoint.url for endpoint in result.api_endpoints}
        assert "http://127.0.0.1:8093/dashboard" in route_urls
        assert "http://127.0.0.1:8093/api/users" in api_urls
        assert "http://127.0.0.1:8093/graphql" in api_urls
        assert any(asset.endswith("/assets/app.js") for asset in result.assets)
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=1)
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_crawl_marks_spa_fallback_common_paths_dead(monkeypatch):
    monkeypatch.setenv("CRAWL_DEPTH", "1")
    monkeypatch.setenv("CRAWL_MAX_URLS", "50")
    get_settings = __import__("app.config", fromlist=["get_settings"]).get_settings
    get_settings.cache_clear()

    httpd, thread = _start_spa_server(8094)
    try:
        spider = WebSpider()
        result = await spider.crawl("http://127.0.0.1:8094/")

        dead_urls = {route.url for route in result.dead_routes}
        discovered_paths = {url.split("8094", 1)[-1] for url in result.urls}
        assert "http://127.0.0.1:8094/admin" in dead_urls
        assert "/admin" not in discovered_paths
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=1)
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_sensitive_paths_ignores_spa_shell_fallbacks_but_keeps_real_files(monkeypatch):
    monkeypatch.setenv("REQUEST_TIMEOUT_SECONDS", "5")
    get_settings = __import__("app.config", fromlist=["get_settings"]).get_settings
    get_settings.cache_clear()

    httpd, thread = _start_spa_sensitive_paths_server(8096)
    root_url = "http://127.0.0.1:8096/"
    try:
        detector = SensitivePathsDetector()
        findings = await detector.detect(
            [root_url],
            [],
            root_url=root_url,
            is_spa=True,
            spa_root_html=SpaSensitivePathsHandler.shell.decode(),
        )

        finding_urls = {finding.url for finding in findings}
        assert f"{root_url}.env" in finding_urls
        assert f"{root_url}debug" not in finding_urls
        assert all("window.debug=true" not in (finding.evidence or "") for finding in findings)
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=1)
        get_settings.cache_clear()
