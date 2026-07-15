"""Issue 4 — a target-controlled robots.txt must not turn into SSRF.

robots.txt can declare ``Sitemap:`` directives, and those URLs are fully
attacker-controlled. The crawler used to fetch every declared sitemap URL before
checking its origin, so ``Sitemap: http://victim/internal`` made SentryStrike
issue a request to an arbitrary host. The fix resolves and origin-checks the
sitemap URL BEFORE fetching, and fetches with redirects disabled so a
same-origin sitemap cannot bounce off-origin either.
"""
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from app.core.crawler.spider import WebSpider


# Records every path the "victim" (off-origin) server is asked for, so the test
# can assert the scanner never reached it.
_VICTIM_HITS: list[str] = []


class VictimHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        _VICTIM_HITS.append(self.path)
        self.send_response(200)
        self.send_header("Content-type", "application/xml")
        self.end_headers()
        self.wfile.write(b"<urlset><url><loc>http://victim/secret</loc></url></urlset>")

    def log_message(self, format, *args):
        pass


class RobotsSsrfHandler(BaseHTTPRequestHandler):
    """Target server whose robots.txt declares an OFF-origin sitemap."""

    victim_port = 0

    def do_GET(self):
        if self.path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            body = f"User-agent: *\nSitemap: http://127.0.0.1:{self.victim_port}/sitemap.xml\n"
            self.wfile.write(body.encode())
        elif self.path in ("/", "/index"):
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>home</body></html>")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


@pytest.mark.asyncio
async def test_off_origin_sitemap_declared_by_robots_is_not_fetched(monkeypatch):
    monkeypatch.setenv("CRAWL_DEPTH", "1")
    monkeypatch.setenv("CRAWL_MAX_URLS", "20")
    get_settings = __import__("app.config", fromlist=["get_settings"]).get_settings
    get_settings.cache_clear()

    _VICTIM_HITS.clear()
    victim = HTTPServer(("127.0.0.1", 8188), VictimHandler)
    victim_thread = threading.Thread(target=victim.serve_forever, daemon=True)
    victim_thread.start()

    RobotsSsrfHandler.victim_port = 8188
    target = HTTPServer(("127.0.0.1", 8187), RobotsSsrfHandler)
    target_thread = threading.Thread(target=target.serve_forever, daemon=True)
    target_thread.start()
    time.sleep(0.3)

    try:
        spider = WebSpider()
        result = await spider.crawl("http://127.0.0.1:8187/")

        # The off-origin sitemap host must never have been contacted (no SSRF)...
        assert _VICTIM_HITS == [], f"scanner fetched off-origin sitemap: {_VICTIM_HITS}"
        # ...and the <loc> it would have yielded must not be in scope.
        assert not any("victim" in url or ":8188" in url for url in result.urls)
    finally:
        target.shutdown()
        target.server_close()
        target_thread.join(timeout=1)
        victim.shutdown()
        victim.server_close()
        victim_thread.join(timeout=1)
        get_settings.cache_clear()
