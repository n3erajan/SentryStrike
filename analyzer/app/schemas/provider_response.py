from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator

from shared.models.vulnerability import AiVerdict, Exploitability


class FindingEnrichmentResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    description: str = Field(min_length=1, max_length=4000)
    exploitability: Exploitability
    exploitability_reasoning: str = Field(min_length=1, max_length=4000)
    business_impact: str = Field(min_length=1, max_length=4000)
    remediation: str = Field(min_length=1, max_length=6000)
    references: list[str] = Field(default_factory=list, max_length=12)

    @field_validator("references")
    @classmethod
    def _allow_http_references(cls, values: list[str]) -> list[str]:
        return [
            value
            for value in values
            if urlparse(value).scheme.lower() in {"http", "https"}
        ]


class FindingAdjudicationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verdict: AiVerdict
    fp_axes: dict[str, str] = Field(default_factory=dict)
    decisive_axis: str = Field(default="")
    false_positive_reasoning: str = Field(min_length=1, max_length=4000)


class FindingAnalysisResponse(BaseModel):
    """Legacy backward-compatible single response model."""
    model_config = ConfigDict(extra="forbid")

    description: str = Field(min_length=1, max_length=4000)
    exploitability: Exploitability
    exploitability_reasoning: str = Field(min_length=1, max_length=4000)
    business_impact: str = Field(min_length=1, max_length=4000)
    verdict: AiVerdict
    false_positive_probability: float = Field(ge=0.0, le=1.0)
    false_positive_reasoning: str = Field(min_length=1, max_length=4000)
    fp_axes: dict[str, str] | None = None
    decisive_axis: str | None = None
    remediation: str = Field(min_length=1, max_length=6000)
    references: list[str] = Field(default_factory=list, max_length=12)

    @field_validator("references")
    @classmethod
    def _allow_http_references(cls, values: list[str]) -> list[str]:
        return [
            value
            for value in values
            if urlparse(value).scheme.lower() in {"http", "https"}
        ]


class ReportAnalysisResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    executive_summary: str = Field(min_length=1, max_length=8000)

