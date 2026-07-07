import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace

import pytest

from app.core.scanner import ScanOrchestrator
from app.core.detectors.base_detector import Finding
from app.models.scan import CrawlMode, ScanPhase, ScanStatus
from app.models.vulnerability import OwaspCategory, SeverityLevel, TechnologyComponent


class FakeRepo:
    def __init__(self, scan: object):
        self.scan = scan

    async def get_by_id(self, _: str):
        return self.scan

    async def update_status(self, scan: object, status: ScanStatus, progress: int | None = None, error_message: str | None = None):
        scan.status = status
        if progress is not None:
            scan.progress = progress
        if error_message:
            scan.error_message = error_message
        return scan


class FakeSpider:
    async def crawl(self, _: str, **kwargs):
        class Result:
            urls = ["https://example.com/search?q=1"]
            forms = []
            routes = []
            api_endpoints = []
            requests = []
            request_audit = []
            parameters = []

        return Result()

    async def fetch_single(self, _: str):
        class Result:
            urls = ["https://example.com/search?q=1"]
            forms = []
            routes = []
            api_endpoints = []
            requests = []
            request_audit = []
            parameters = []

        return Result()


class FakeTechDetector:
    async def detect(self, _: str):
        return [TechnologyComponent(name="nginx", version="1.18", category="server")]


class FakeCveService:
    async def enrich_components(self, components):
        for component in components:
            component.cves = ["CVE-2024-0001"]
        return components


class FakeSsl:
    async def analyze(self, _: str):
        return {"valid": True, "issues": []}


class FakeDetector:
    async def detect(self, urls, forms, **kwargs):
        return [
            Finding(
                category=OwaspCategory.a05,
                vuln_type="Potential SQL Injection",
                severity=SeverityLevel.high,
                url=urls[0],
                evidence="test evidence",
                verified=True,
            )
        ]


class FakePrioritizer:
    async def prioritize(self, vulnerabilities):
        for v in vulnerabilities:
            v.cvss_score = 8.0
        return vulnerabilities


class FakeFP:
    async def filter(self, vulnerabilities):
        return vulnerabilities


class FakeRemediation:
    async def enrich_many(self, vulnerabilities):
        for v in vulnerabilities:
            v.ai_analysis.remediation = "sanitize inputs"
        return vulnerabilities


class FakeReport:
    async def generate(self, scan: object):
        return {"executive_summary": "Summary"}


class FakeScan:
    def __init__(self) -> None:
        self.id = "mock-id"
        self.target_url = "https://example.com"
        self.owner_user_id = "user-1"
        self.owner_email = "user@example.test"
        self.crawl_mode = CrawlMode.full
        self.status = ScanStatus.queued
        self.progress = 0
        self.current_phase = ScanPhase.queued
        self.phase_message = "Scan queued"
        self.authorization_confirmed = True
        self.authorization_text = "Test authorization"
        self.authorization_confirmed_at = datetime.now(timezone.utc)
        self.created_at = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)
        self.started_at = None
        self.completed_at = None
        self.statistics = SimpleNamespace(
            total_urls_crawled=0,
            total_vulnerabilities=0,
            severity_breakdown=SimpleNamespace(critical=0, high=0, medium=0, low=0, info=0),
        )
        self.overall_risk_score = 0.0
        self.technology_stack = []
        self.vulnerabilities = []
        self.report_metadata = SimpleNamespace(
            generated_at=None,
            generated_by="ai",
            summary=None,
            detector_coverage=[],
            attack_chains=[],
            evidence_strength_breakdown=None,
            spa_api_coverage=None,
            auth_coverage=None,
            coverage_warnings=[]
        )
        self.error_message = None

    async def save(self) -> None:
        self.updated_at = datetime.now(timezone.utc)


@pytest.mark.asyncio
async def test_scanner_workflow_completes() -> None:
    scan = FakeScan()

    orchestrator = ScanOrchestrator(FakeRepo(scan))
    orchestrator.spider = FakeSpider()
    orchestrator.technology_detector = FakeTechDetector()
    orchestrator.cve_service = FakeCveService()
    orchestrator.ssl_analyzer = FakeSsl()
    orchestrator.detectors = [FakeDetector()]
    orchestrator.supply_chain_detector = FakeDetector()
    orchestrator.prioritizer = FakePrioritizer()
    orchestrator.false_positive = FakeFP()
    orchestrator.remediation_gen = FakeRemediation()
    orchestrator.ai_report = FakeReport()

    await orchestrator.run_scan("mock-id")

    assert scan.status == ScanStatus.completed
    assert scan.progress == 100
    assert scan.current_phase == ScanPhase.completed
    assert scan.phase_message == "Scan completed"
    assert scan.statistics.total_vulnerabilities >= 1
    assert scan.overall_risk_score > 0


@pytest.mark.asyncio
async def test_single_path_scan_uses_fetch_single(monkeypatch):
    scan = FakeScan()
    scan.crawl_mode = CrawlMode.single
    scan.target_url = "https://example.com/xss/"

    used_fetch_single = False

    class TrackingSpider(FakeSpider):
        async def fetch_single(self, url: str):
            nonlocal used_fetch_single
            used_fetch_single = True
            return await super().fetch_single(url)

        async def crawl(self, url: str, **kwargs):
            raise AssertionError("crawl() should not be called in single-path mode")

    orchestrator = ScanOrchestrator(FakeRepo(scan))
    orchestrator.spider = TrackingSpider()
    orchestrator.technology_detector = FakeTechDetector()
    orchestrator.cve_service = FakeCveService()
    orchestrator.ssl_analyzer = FakeSsl()
    orchestrator.detectors = [FakeDetector()]
    orchestrator.supply_chain_detector = FakeDetector()
    orchestrator.ai_report = FakeReport()

    await orchestrator.run_scan("mock-id")

    assert used_fetch_single
    assert scan.status == ScanStatus.completed


class MockServerRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<html><body><a href="/sqli?id=1">sqli</a><form action="/login" method="POST"><input type="text" name="username"/><input type="submit" name="submit"/></form><form action="/update" method="POST"><input type="text" name="data"/></form></body></html>')
        elif self.path.startswith('/sqli'):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            import urllib.parse
            if "'" in urllib.parse.unquote(self.path):
                self.wfile.write(b"you have an error in your sql syntax")
            else:
                self.wfile.write(b"User details")
        else:
            self.send_response(404)
            self.end_headers()
            
    def do_POST(self):
        if self.path == '/login':
            self.send_response(200)
            self.send_header('Set-Cookie', 'session=123; SameSite=Strict')
            self.end_headers()
            self.wfile.write(b"Logged in")
        elif self.path == '/update':
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Updated")
            
    def log_message(self, format, *args):
        pass # Suppress logging

def run_mock_server(httpd):
    httpd.serve_forever()

@pytest.mark.asyncio
async def test_full_scan_against_mock_server(monkeypatch):
    # Start mock server
    server_address = ('127.0.0.1', 8089)
    httpd = HTTPServer(server_address, MockServerRequestHandler)
    server_thread = threading.Thread(target=run_mock_server, args=(httpd,))
    server_thread.daemon = True
    server_thread.start()
    
    # Wait for server to start
    time.sleep(0.5)
    
    try:
        # Mock AI Client to avoid actual LLM calls
        from app.analyzers.ai_client import OllamaClient
        
        async def mock_generate_json_list(*args, **kwargs):
            # Return empty list or fallbacks
            expected_count = kwargs.get('expected_count', 1)
            fallback = kwargs.get('fallback', {})
            return [fallback for _ in range(expected_count)]
            
        async def mock_generate_json(*args, **kwargs):
            return kwargs.get('fallback', {})
            
        monkeypatch.setattr(OllamaClient, "generate_json_list", mock_generate_json_list)
        monkeypatch.setattr(OllamaClient, "generate_json", mock_generate_json)
        
        scan = FakeScan()
        scan.target_url = "http://127.0.0.1:8089"
        orchestrator = ScanOrchestrator(FakeRepo(scan))
        
        # Disable SSL check which may fail for localhost
        orchestrator.ssl_analyzer = FakeSsl()
        
        # Avoid tech detector slowing things down or making external calls
        orchestrator.technology_detector = FakeTechDetector()
        orchestrator.cve_service = FakeCveService()

        await orchestrator.run_scan("mock-id")
        
        assert scan.status == ScanStatus.completed
        # Check that SQLi or CSRF vulnerabilities were found
        vuln_types = [v.vuln_type.lower() for v in scan.vulnerabilities]
        assert any("sql injection" in v for v in vuln_types)
    finally:
        httpd.shutdown()
        httpd.server_close()
        server_thread.join()
