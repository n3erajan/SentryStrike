from datetime import datetime

from pydantic import BaseModel, Field


class ReportResponse(BaseModel):
    scan_id: str
    generated_at: datetime | None = None
    executive_summary: str | None = None
    technical_analysis: str | None = None
    recommendations: list[str] = Field(default_factory=list)
    overall_risk_assessment: str | None = None


class GenerateReportResponse(BaseModel):
    message: str
    report: ReportResponse
