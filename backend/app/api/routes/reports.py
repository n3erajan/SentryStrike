from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response

from app.api.dependencies import get_current_user, get_scan_repository, json_response
from shared.database.repositories.scan_repository import ScanRepository
from shared.models.analysis_job import AnalysisStatus
from shared.models.user import User
from app.utils.pdf_generator import build_scan_pdf

router = APIRouter(prefix="/reports", tags=["reports"])

SCANNER_LIMITATIONS = [
    "OWASP A06, A08, and A09 are disclosed as outside active automated detector scope.",
    "SPA/API coverage depends on crawl visibility and whether browser-based discovery was enabled.",
    "Authenticated coverage is verified only when the scanner proves access to a protected target.",
]


def _model_dump(value: object) -> dict:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    return dict(value or {})


def _build_report_payload(scan, scan_id: str) -> dict:
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
        "report_metadata": report_metadata,
        "evidence_strength_breakdown": report_metadata.get("evidence_strength_breakdown", {}),
        "spa_api_coverage": report_metadata.get("spa_api_coverage", {}),
        "auth_coverage": report_metadata.get("auth_coverage", {}),
        "attack_chains": attack_chains,
        "scanner_limitations": SCANNER_LIMITATIONS,
    }


@router.get("/{scan_id}")
async def get_report_data(
    scan_id: str,
    repo: ScanRepository = Depends(get_scan_repository),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Return the structured report data for a completed scan."""
    scan = await repo.get_in_org(scan_id, current_user.org_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return json_response(_build_report_payload(scan, scan_id))


@router.get("/{scan_id}/pdf")
async def generate_pdf_report(
    scan_id: str,
    repo: ScanRepository = Depends(get_scan_repository),
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

    scan_data = {
        "success": True,
        "data": _build_report_payload(scan, scan_id),
    }
    payload = build_scan_pdf(scan_data=scan_data)
    return Response(
        content=payload,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=scan-{scan_id}.pdf"},
    )
