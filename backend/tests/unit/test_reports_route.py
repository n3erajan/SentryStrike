from datetime import datetime
from types import SimpleNamespace

from app.api.routes.reports import SCANNER_LIMITATIONS, _build_report_payload
from app.models.scan import (
    AuthCoverage,
    EvidenceStrengthBreakdown,
    ReportMetadata,
    ScanStatistics,
    SpaApiCoverage,
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
        technology_stack=[],
        vulnerabilities=[],
    )

    payload = _build_report_payload(scan, "scan-1")

    assert payload["generated_at"] == "2026-06-08T09:10:17"
    assert payload["report_metadata"]["generated_at"] == "2026-06-08T09:10:17"
    assert payload["evidence_strength_breakdown"]["confirmed_exploit"] == 2
    assert payload["auth_coverage"]["state"] == "authenticated_verified"
    assert payload["spa_api_coverage"]["api_endpoints_extracted"] == 8
    assert payload["scanner_limitations"] == SCANNER_LIMITATIONS
