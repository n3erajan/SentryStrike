from types import SimpleNamespace

import pytest

from app.analyzers.report_generator import AiReportGenerator
from app.config import get_settings
from shared.models.vulnerability import TechnologyComponent


class CapturingClient:
    def __init__(self):
        self.prompt = ""

    async def generate_json(self, prompt: str):
        self.prompt = prompt
        return {
            "executive_summary": "summary",
            "technical_analysis": "analysis",
            "recommendations": "recommendations",
            "overall_risk_assessment": "risk",
        }


@pytest.mark.asyncio
async def test_report_generator_includes_detected_technologies(monkeypatch) -> None:
    monkeypatch.setenv("AI_ANALYSIS_ENABLED", "true")
    get_settings.cache_clear()
    client = CapturingClient()
    generator = AiReportGenerator()
    generator.client = client
    scan = SimpleNamespace(
        target_url="https://example.test",
        statistics=SimpleNamespace(
            total_vulnerabilities=1,
            severity_breakdown=SimpleNamespace(critical=0, high=1, medium=0),
        ),
        overall_risk_score=75.0,
        report_metadata=SimpleNamespace(attack_chains=[]),
        technology_stack=[
            TechnologyComponent(name="nginx", version="1.18", category="server", cves=["CVE-2021-0001"]),
            TechnologyComponent(name="jQuery", version="3.6.0", category="library", cves=[]),
        ],
    )

    report = await generator.generate(scan)

    assert "Technologies detected: nginx 1.18" in client.prompt
    assert "CVE-2021-0001" in client.prompt
    assert report["technologies_detected"] == (
        "nginx 1.18 (server; CVE-2021-0001); "
        "jQuery 3.6.0 (library; no known CVEs found)"
    )
