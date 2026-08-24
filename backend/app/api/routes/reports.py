from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response

from app.api.dependencies import (
    get_application_repository,
    get_current_user,
    get_scan_repository,
    json_response,
)
from shared.database.repositories.application_repository import ApplicationRepository
from shared.database.repositories.scan_repository import ScanRepository
from shared.models.analysis_job import AnalysisStatus
from shared.models.user import User
from app.utils.pdf_generator import build_scan_pdf

router = APIRouter(prefix="/reports", tags=["reports"])

SCANNER_LIMITATIONS = [
    "OWASP A06, A08, and A09 are disclosed as outside active automated detector scope.",
    "SPA/API coverage depends on crawl visibility and whether browser-based discovery was enabled.",
    "Authenticated coverage is verified only when the scanner proves access to a protected target.",
    "Absence of a finding on a tested surface is not proof of absence; surfaces this scan never "
    "reached are listed nowhere and must be assumed untested.",
]


def _model_dump(value: object) -> dict:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    return dict(value or {})


async def _application_name(
    apps: ApplicationRepository,
    scan,
    org_id: str,
) -> str:
    """Resolve the org-scoped application name for a scan, if any."""
    if not getattr(scan, "application_id", None):
        return ""
    application = await apps.get_in_org(str(scan.application_id), org_id)
    return application.name if application is not None else ""


def _build_report_payload(
    scan,
    scan_id: str,
    *,
    application_name: str = "",
) -> dict:
    report_metadata = _model_dump(scan.report_metadata)
    generated_at = report_metadata.get("generated_at")
    vulnerabilities = [v.model_dump(mode="json") for v in scan.vulnerabilities]
    active_vulnerabilities = [
        vulnerability
        for vulnerability in vulnerabilities
        if not vulnerability.get("is_false_positive", False)
    ]
    suppressed_findings = [
        vulnerability
        for vulnerability in vulnerabilities
        if vulnerability.get("is_false_positive", False)
    ]
    statistics = scan.statistics.model_dump(mode="json")
    statistics["active_vulnerabilities"] = len(active_vulnerabilities)
    statistics["suppressed_vulnerabilities"] = len(suppressed_findings)
    active_ids = {vulnerability["id"] for vulnerability in active_vulnerabilities}
    attack_chains = [
        chain
        for chain in report_metadata.get("attack_chains", [])
        if set(chain.get("vulnerability_ids", [])).issubset(active_ids)
    ]
    report_metadata["attack_chains"] = attack_chains

    return {
        "scan_id": scan_id,
        "generated_at": generated_at,
        "executive_summary": scan.report_metadata.summary,
        "analysis": _model_dump(scan.analysis) if getattr(scan, "analysis", None) else None,
        "submitted_by_user_id": scan.submitted_by_user_id,
        "submitted_by_full_name": scan.submitted_by_full_name,
        "submitted_by_email": scan.submitted_by_email,
        "authorization": {
            "confirmed": getattr(scan, "authorization_confirmed", False),
            "confirmed_at": getattr(scan, "authorization_confirmed_at", None),
        },
        "statistics": statistics,
        "risk_score": scan.overall_risk_score,
        "risk_level": getattr(scan, "overall_risk_level", None),
        "technology_stack": [tech.model_dump(mode="json") for tech in scan.technology_stack],
        "vulnerabilities": vulnerabilities,
        "active_vulnerabilities": active_vulnerabilities,
        "suppressed_findings": suppressed_findings,
        "site_title": getattr(scan, "site_title", ""),
        "application_name": application_name or "",
        "report_metadata": report_metadata,
        "evidence_strength_breakdown": report_metadata.get("evidence_strength_breakdown", {}),
        "spa_api_coverage": report_metadata.get("spa_api_coverage", {}),
        "auth_coverage": report_metadata.get("auth_coverage", {}),
        # Promoted from report_metadata so the itemised "what was actually
        # tested" inventory and the scan's own coverage caveats are findable at
        # the top level of the JSON report rather than buried in metadata. The
        # PDF carries only the counts; this is where the full inventory lives.
        "tested_surface": report_metadata.get("tested_surface", {}),
        "coverage_warnings": report_metadata.get("coverage_warnings", []),
        "detector_coverage": report_metadata.get("detector_coverage", []),
        "attack_chains": attack_chains,
        "scanner_limitations": SCANNER_LIMITATIONS,
    }


@router.get("/{scan_id}")
async def get_report_data(
    scan_id: str,
    repo: ScanRepository = Depends(get_scan_repository),
    apps: ApplicationRepository = Depends(get_application_repository),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Return the structured report data for a completed scan."""
    scan = await repo.get_in_org(scan_id, current_user.org_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    application_name = await _application_name(apps, scan, current_user.org_id)
    return json_response(_build_report_payload(scan, scan_id, application_name=application_name))


@router.get("/{scan_id}/pdf")
async def generate_pdf_report(
    scan_id: str,
    repo: ScanRepository = Depends(get_scan_repository),
    apps: ApplicationRepository = Depends(get_application_repository),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Generate and download a client-ready PDF report for a completed scan."""
    scan = await repo.get_in_org(scan_id, current_user.org_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    analysis = getattr(scan, "analysis", None)
    analysis_status = (
        getattr(analysis.status, "value", analysis.status) if analysis else "pending"
    )
    if analysis_status != AnalysisStatus.completed.value:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "analysis_not_completed",
                "message": "The PDF report is available after AI analysis completes.",
                "analysis_status": analysis_status,
                "analysis_revision": getattr(analysis, "revision", None),
            },
        )

    application_name = await _application_name(apps, scan, current_user.org_id)
    scan_data = {
        "success": True,
        "data": _build_report_payload(scan, scan_id, application_name=application_name),
    }
    payload = build_scan_pdf(scan_data=scan_data)
    return Response(
        content=payload,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=scan-{scan_id}.pdf"},
    )
