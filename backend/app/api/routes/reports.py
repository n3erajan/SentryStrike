from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response

from app.analyzers.report_generator import AiReportGenerator
from app.api.dependencies import get_current_user, get_scan_repository, json_response
from app.database.repositories.scan_repository import ScanRepository
from app.models.user import User
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
    generated_at = report_metadata.get("generated_at") or datetime.now().isoformat()
    report_metadata["generated_at"] = generated_at

    return {
        "scan_id": scan_id,
        "generated_at": generated_at,
        "executive_summary": scan.report_metadata.summary or "No summary available.",
        "owner_user_id": getattr(scan, "owner_user_id", None),
        "owner_email": getattr(scan, "owner_email", None),
        "authorization": {
            "confirmed": getattr(scan, "authorization_confirmed", False),
            "text": getattr(scan, "authorization_text", None),
            "confirmed_at": getattr(scan, "authorization_confirmed_at", None),
        },
        "statistics": scan.statistics.model_dump(mode="json"),
        "risk_score": scan.overall_risk_score,
        "risk_level": getattr(scan, "overall_risk_level", None),
        "technology_stack": [tech.model_dump(mode="json") for tech in scan.technology_stack],
        "vulnerabilities": [v.model_dump(mode="json") for v in scan.vulnerabilities],
        "report_metadata": report_metadata,
        "evidence_strength_breakdown": report_metadata.get("evidence_strength_breakdown", {}),
        "spa_api_coverage": report_metadata.get("spa_api_coverage", {}),
        "auth_coverage": report_metadata.get("auth_coverage", {}),
        "attack_chains": report_metadata.get("attack_chains", []),
        "scanner_limitations": SCANNER_LIMITATIONS,
    }


@router.get("/{scan_id}")
async def get_report_data(
    scan_id: str,
    repo: ScanRepository = Depends(get_scan_repository),
    current_user: User = Depends(get_current_user),
) -> dict:
    scan = await repo.get_owned_by_id(scan_id, str(current_user.id))
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return json_response(_build_report_payload(scan, scan_id))


@router.post("/{scan_id}/generate")
async def generate_ai_report(
    scan_id: str,
    repo: ScanRepository = Depends(get_scan_repository),
    current_user: User = Depends(get_current_user),
) -> dict:
    scan = await repo.get_owned_by_id(scan_id, str(current_user.id))
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    report = await AiReportGenerator().generate(scan)
    scan.report_metadata.generated_at = datetime.now()
    scan.report_metadata.summary = report.get("executive_summary")
    await scan.save()
    return json_response(report, "report generated")


@router.get("/{scan_id}/pdf")
async def generate_pdf_report(
    scan_id: str,
    repo: ScanRepository = Depends(get_scan_repository),
    current_user: User = Depends(get_current_user),
) -> Response:
    scan = await repo.get_owned_by_id(scan_id, str(current_user.id))
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

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
