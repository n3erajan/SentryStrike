from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app.core.scanner import ScanOrchestrator
from app.core.detectors.base_detector import Finding
from app.models.scan import ScanStatus
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
    async def crawl(self, _: str):
        class Result:
            urls = ["https://example.com/search?q=1"]
            forms = []

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
                category=OwaspCategory.a03,
                vuln_type="Potential SQL Injection",
                severity=SeverityLevel.high,
                url=urls[0],
                evidence="test evidence",
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
        self.status = ScanStatus.queued
        self.progress = 0
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
        self.report_metadata = SimpleNamespace(generated_at=None, generated_by="ai", summary=None)
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
    assert scan.statistics.total_vulnerabilities >= 1
    assert scan.overall_risk_score > 0
