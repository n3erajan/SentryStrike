from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response

from app.analyzers.report_generator import AiReportGenerator
from app.api.dependencies import get_scan_repository, json_response
from app.database.repositories.scan_repository import ScanRepository
from app.utils.pdf_generator import build_scan_pdf

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/{scan_id}")
async def get_report_data(scan_id: str, repo: ScanRepository = Depends(get_scan_repository)) -> dict:
    scan = await repo.get_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    data = {
        "scan_id": scan_id,
        "generated_at": scan.report_metadata.generated_at,
        "executive_summary": scan.report_metadata.summary,
        "statistics": scan.statistics.model_dump(),
        "risk_score": scan.overall_risk_score,
        "technology_stack": [tech.model_dump() for tech in scan.technology_stack],
        "vulnerabilities": [v.model_dump() for v in scan.vulnerabilities],
    }
    return json_response(data)


@router.post("/{scan_id}/generate")
async def generate_ai_report(scan_id: str, repo: ScanRepository = Depends(get_scan_repository)) -> dict:
    scan = await repo.get_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    report = await AiReportGenerator().generate(scan)
    scan.report_metadata.generated_at = datetime.now()
    scan.report_metadata.summary = report.get("executive_summary")
    await scan.save()
    return json_response(report, "report generated")


@router.get("/{scan_id}/pdf")
async def generate_pdf_report(scan_id: str, repo: ScanRepository = Depends(get_scan_repository)) -> Response:
    scan = await repo.get_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan_data = {
        "success": True,
        "data": {
            "scan_id": scan_id,
            "generated_at": scan.report_metadata.generated_at.isoformat()
                            if scan.report_metadata.generated_at else datetime.now().isoformat(),
            "executive_summary": scan.report_metadata.summary or "No summary available.",
            "statistics": scan.statistics.model_dump(),
            "risk_score": scan.overall_risk_score,
            "technology_stack": [tech.model_dump() for tech in scan.technology_stack],
            "vulnerabilities": [v.model_dump() for v in scan.vulnerabilities],
        },
    }
    payload = build_scan_pdf(scan_data=scan_data)
    return Response(
        content=payload,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=scan-{scan_id}.pdf"},
    )
