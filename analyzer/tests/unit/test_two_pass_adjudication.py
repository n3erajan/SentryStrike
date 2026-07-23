from types import SimpleNamespace
import pytest

from app.clients.ai_client import ProviderResult
from app.services.finding_analysis import (
    FindingAnalysisService,
    compute_fp_probability,
    extract_page_title,
    has_code_blocks,
)
from shared.models.vulnerability import (
    Evidence,
    EvidenceStrength,
    LocationInfo,
    OwaspCategory,
    SeverityLevel,
    Vulnerability,
)


class MockTwoPassClient:
    def __init__(self, axes: dict[str, str], verdict: str, reasoning: str) -> None:
        self.axes = axes
        self.verdict = verdict
        self.reasoning = reasoning
        self.calls = []

    async def generate_json(self, prompt: str) -> ProviderResult:
        self.calls.append(prompt)
        if "Evaluate these categorical axes" in prompt or "fp_axes" in prompt or "Adjudication" in prompt:
            data = {
                "verdict": self.verdict,
                "fp_axes": self.axes,
                "decisive_axis": list(self.axes.keys())[0] if self.axes else "",
                "false_positive_reasoning": self.reasoning,
            }
        else:
            data = {
                "description": "Verbose error page exposing server details.",
                "exploitability": "Medium",
                "exploitability_reasoning": "Stack trace visible in HTTP 200 response.",
                "business_impact": "Discloses internal frame details.",
                "remediation": "Disable debug mode.",
                "references": ["https://owasp.org"],
            }
        return ProviderResult(data=data, request_id=f"req-{len(self.calls)}")


def test_extract_page_title_and_code_blocks():
    html = "<html><head><title>SQL Injection Tutorial for Developers</title></head><body><code>' OR 1=1--</code></body></html>"
    assert extract_page_title(html) == "SQL Injection Tutorial for Developers"
    assert has_code_blocks(html) is True

    plain = "HTTP/1.1 500 Internal Server Error"
    assert extract_page_title(plain) is None
    assert has_code_blocks(plain) is False


def test_compute_fp_probability():
    # SQLi on tutorial page case (proof does not support claim, explainable by normal educational content)
    axes_sqli_doc = {"EVIDENTIAL_ALIGNMENT": "no", "EXPLAINABLE_BY_NORMAL_BEHAVIOR": "yes"}
    assert compute_fp_probability(axes_sqli_doc) == 0.85

    # Exposed API Documentation case (proof directly supports claim, not normal intended app behavior)
    axes_api_docs = {"EVIDENTIAL_ALIGNMENT": "yes", "EXPLAINABLE_BY_NORMAL_BEHAVIOR": "no"}
    assert compute_fp_probability(axes_api_docs) == 0.05

    # Public API IDOR case (public product catalog, explainable as normal behavior)
    axes_public_api = {"EVIDENTIAL_ALIGNMENT": "no", "EXPLAINABLE_BY_NORMAL_BEHAVIOR": "yes"}
    assert compute_fp_probability(axes_public_api) == 0.85

    # Real SQL injection TP case
    axes_tp = {"EVIDENTIAL_ALIGNMENT": "yes", "EXPLAINABLE_BY_NORMAL_BEHAVIOR": "no", "CAUSALLY_CONNECTED": "yes"}
    assert compute_fp_probability(axes_tp) == 0.05


@pytest.mark.asyncio
async def test_two_pass_analysis_documentation_fp():
    axes = {"PROOF_GENUINE": "no", "CONTENT_IS_DOCUMENTATION": "yes"}
    client = MockTwoPassClient(axes, "likely_false_positive", "Matched pattern is on a tutorial page.")
    service = FindingAnalysisService(client)
    service.settings = SimpleNamespace(
        ai_analysis_enabled=True,
        analysis_finding_evidence_max_chars=3000,
        ai_model="gemma4-e4b-8k",
    )

    vuln = Vulnerability(
        id="v-doc-sqli",
        category=OwaspCategory.a05,
        vuln_type="Verbose Error Handling",
        severity=SeverityLevel.medium,
        cvss_score=5.3,
        location=LocationInfo(url="https://target.test/docs/errors"),
        evidence=Evidence(
            response_snippet="<html><head><title>Common HTTP Errors Guide</title></head><body><code>500 Internal Server Error</code></body></html>",
            evidence_strength=EvidenceStrength.possible,
            proof_type="pattern_match",
        ),
    )

    analysis, result = await service.analyze(vuln, revision=1, technology_stack="Python/Flask")

    assert len(client.calls) == 2  # Two-pass execution!
    assert analysis.verdict.value == "likely_false_positive"
    assert analysis.false_positive_probability >= 0.80
    assert analysis.fp_axes == axes
    assert analysis.decisive_axis == "PROOF_GENUINE"


@pytest.mark.asyncio
async def test_active_output_ceiling_clamping():
    # Model mistakenly marks FP on active output, but code ceiling (0.05) clamps it!
    axes = {"CONTENT_PRE_EXISTING": "yes"}
    client = MockTwoPassClient(axes, "likely_false_positive", "Looks like pre-existing text.")
    service = FindingAnalysisService(client)
    service.settings = SimpleNamespace(
        ai_analysis_enabled=True,
        analysis_finding_evidence_max_chars=3000,
        ai_model="gemma4-e4b-8k",
    )

    vuln = Vulnerability(
        id="v-rce",
        category=OwaspCategory.a05,
        vuln_type="Command Injection",
        severity=SeverityLevel.critical,
        cvss_score=9.8,
        location=LocationInfo(url="https://target.test/exec"),
        evidence=Evidence(
            response_snippet="uid=33(www-data) gid=33(www-data)",
            evidence_strength=EvidenceStrength.confirmed_exploit,
            proof_type="active_output",
        ),
    )

    analysis, result = await service.analyze(vuln, revision=1, technology_stack="Linux/Bash")

    # Probability was clamped by active_output ceiling (0.05), so verdict fell back to uncertain
    assert analysis.false_positive_probability <= 0.05
    assert analysis.verdict.value == "uncertain"
