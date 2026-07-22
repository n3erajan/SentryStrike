from datetime import datetime
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.api.routes.reports import (
    SCANNER_LIMITATIONS,
    _build_report_payload,
    generate_pdf_report,
)
from shared.models.analysis_job import AnalysisStatus
from shared.models.scan import (
    AttackChain,
    AuthCoverage,
    EvidenceStrengthBreakdown,
    ReportMetadata,
    ScanAnalysisState,
    ScanStatistics,
    SpaApiCoverage,
)
from shared.models.vulnerability import (
    LocationInfo,
    OwaspCategory,
    SeverityLevel,
    Vulnerability,
)


def test_report_payload_exposes_evidence_and_coverage_metadata() -> None:
    generated_at = datetime(2026, 6, 8, 9, 10, 17)
    scan = SimpleNamespace(
        report_metadata=ReportMetadata(
            generated_at=generated_at,
            summary="Executive summary.",
            evidence_strength_breakdown=EvidenceStrengthBreakdown(
                confirmed_exploit=2,
                confirmed_observation=1,
                probable=3,
                possible=4,
                informational=5,
            ),
            auth_coverage=AuthCoverage(
                state="authenticated_verified",
                authenticated_url_count=7,
                unauthenticated_url_count=2,
                protected_targets_verified=1,
                auth_headers_present=True,
                session_cookies_present=True,
            ),
            spa_api_coverage=SpaApiCoverage(
                spa_detected=True,
                js_assets_inspected=4,
                routes_extracted=6,
                api_endpoints_extracted=8,
                parameters_extracted=10,
                browser_requests_observed=12,
                dead_spa_fallback_routes_suppressed=3,
            ),
        ),
        statistics=ScanStatistics(total_urls_crawled=9, total_vulnerabilities=15),
        overall_risk_score=82.0,
        submitted_by_user_id="user-1",
        submitted_by_full_name="Niuradaj Adhadh",
        submitted_by_email="user@example.test",
        authorization_confirmed=True,
        authorization_confirmed_at=generated_at,
        technology_stack=[],
        vulnerabilities=[],
    )

    payload = _build_report_payload(scan, "scan-1")

    assert payload["generated_at"] == "2026-06-08T09:10:17"
    assert payload["report_metadata"]["generated_at"] == "2026-06-08T09:10:17"
    assert payload["evidence_strength_breakdown"]["confirmed_exploit"] == 2
    assert payload["auth_coverage"]["state"] == "authenticated_verified"
    assert payload["spa_api_coverage"]["api_endpoints_extracted"] == 8
    assert payload["submitted_by_user_id"] == "user-1"
    assert payload["submitted_by_full_name"] == "Niuradaj Adhadh"
    assert payload["submitted_by_email"] == "user@example.test"
    assert payload["authorization"]["confirmed"] is True
    assert payload["scanner_limitations"] == SCANNER_LIMITATIONS


def test_pending_report_payload_does_not_fabricate_ai_metadata() -> None:
    scan = SimpleNamespace(
        report_metadata=ReportMetadata(),
        statistics=ScanStatistics(),
        overall_risk_score=0.0,
        submitted_by_user_id="user-1",
        submitted_by_full_name="Scan Submitter",
        submitted_by_email="user@example.test",
        authorization_confirmed=True,
        authorization_confirmed_at=None,
        technology_stack=[],
        vulnerabilities=[],
        analysis=ScanAnalysisState(
            status=AnalysisStatus.queued,
            current_job_id="job-1",
            revision=1,
            message="Analysis queued",
        ),
    )

    payload = _build_report_payload(scan, "scan-1")

    assert payload["generated_at"] is None
    assert payload["executive_summary"] is None
    assert payload["report_metadata"]["generated_at"] is None
    assert payload["report_metadata"]["summary"] is None
    assert payload["analysis"]["status"] == "queued"
    assert payload["analysis"]["revision"] == 1


def test_report_payload_separates_suppressed_findings_and_filters_attack_chains() -> None:
    active = Vulnerability(
        id="active-1",
        category=OwaspCategory.a05,
        vuln_type="SQL Injection",
        severity=SeverityLevel.critical,
        location=LocationInfo(url="https://target.example/search"),
    )
    suppressed = Vulnerability(
        id="suppressed-1",
        category=OwaspCategory.a05,
        vuln_type="Reflected XSS",
        severity=SeverityLevel.high,
        location=LocationInfo(url="https://target.example/search"),
        is_false_positive=True,
        false_positive_reason="Generic SPA fallback response.",
        false_positive_marked_by_user_id="user-analyst",
        false_positive_marked_by_email="analyst@example.test",
        false_positive_marked_at=datetime(2026, 7, 22, 10, 0),
    )
    scan = SimpleNamespace(
        report_metadata=ReportMetadata(
            attack_chains=[
                AttackChain(
                    id="active-chain",
                    description="Active chain",
                    vulnerability_ids=["active-1"],
                    severity="Critical",
                ),
                AttackChain(
                    id="suppressed-chain",
                    description="Includes a suppressed finding",
                    vulnerability_ids=["active-1", "suppressed-1"],
                    severity="Critical",
                ),
            ]
        ),
        statistics=ScanStatistics(total_vulnerabilities=2),
        overall_risk_score=70.0,
        overall_risk_level="High",
        submitted_by_user_id="user-1",
        submitted_by_full_name="Scan Submitter",
        submitted_by_email="user@example.test",
        authorization_confirmed=True,
        authorization_confirmed_at=None,
        technology_stack=[],
        vulnerabilities=[active, suppressed],
        analysis=None,
    )

    payload = _build_report_payload(scan, "scan-1")

    assert len(payload["vulnerabilities"]) == 2
    assert [item["id"] for item in payload["active_vulnerabilities"]] == ["active-1"]
    assert [item["id"] for item in payload["suppressed_findings"]] == ["suppressed-1"]
    assert payload["suppressed_findings"][0]["false_positive_marked_by_email"] == "analyst@example.test"
    assert payload["statistics"]["active_vulnerabilities"] == 1
    assert payload["statistics"]["suppressed_vulnerabilities"] == 1
    assert [chain["id"] for chain in payload["attack_chains"]] == ["active-chain"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "analysis_status",
    [
        AnalysisStatus.queued,
        AnalysisStatus.running,
        AnalysisStatus.failed,
        AnalysisStatus.cancelled,
        AnalysisStatus.not_requested,
    ],
)
async def test_pdf_is_blocked_until_current_analysis_completes(analysis_status) -> None:
    scan = SimpleNamespace(
        analysis=ScanAnalysisState(
            status=analysis_status,
            current_job_id="job-1",
            revision=1,
            message="Analysis not complete",
        )
    )
    repo = SimpleNamespace(
        get_in_org=lambda scan_id, org_id: None,
    )

    async def get_in_org(scan_id, org_id):
        return scan

    repo.get_in_org = get_in_org

    with pytest.raises(HTTPException) as exc_info:
        await generate_pdf_report(
            "scan-1",
            repo=repo,
            current_user=SimpleNamespace(org_id="org-1"),
        )

    assert exc_info.value.status_code == 409
    assert exc_info.value.detail["code"] == "analysis_not_completed"
    assert exc_info.value.detail["analysis_status"] == analysis_status.value


@pytest.mark.asyncio
async def test_pdf_is_generated_for_completed_current_analysis(monkeypatch) -> None:
    generated_at = datetime(2026, 7, 21)
    scan = SimpleNamespace(
        analysis=ScanAnalysisState(
            status=AnalysisStatus.completed,
            current_job_id="job-2",
            revision=2,
            progress=100,
            message="Analysis completed",
        ),
        report_metadata=ReportMetadata(
            generated_at=generated_at,
            summary="Executive summary.",
        ),
        statistics=ScanStatistics(),
        overall_risk_score=0.0,
        submitted_by_user_id="user-1",
        submitted_by_full_name="Scan Submitter",
        submitted_by_email="user@example.test",
        authorization_confirmed=True,
        authorization_confirmed_at=generated_at,
        technology_stack=[],
        vulnerabilities=[],
    )

    async def get_in_org(scan_id, org_id):
        return scan

    monkeypatch.setattr(
        "app.api.routes.reports.build_scan_pdf",
        lambda *, scan_data: b"pdf-bytes",
    )

    response = await generate_pdf_report(
        "scan-1",
        repo=SimpleNamespace(get_in_org=get_in_org),
        current_user=SimpleNamespace(org_id="org-1"),
    )

    assert response.status_code == 200
    assert response.body == b"pdf-bytes"
    assert response.media_type == "application/pdf"
