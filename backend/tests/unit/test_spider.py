import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
import httpx

from app.core.crawler.spider import AuthReplayState, WebSpider


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


def _start_server(port: int) -> tuple[HTTPServer, threading.Thread]:
    httpd = HTTPServer(("127.0.0.1", port), MultiPageHandler)
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
