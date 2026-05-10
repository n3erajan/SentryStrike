from dataclasses import dataclass


@dataclass
class CvssResult:
    score: float
    vector: str
    severity: str


class CvssCalculator:
    """Simple CVSS v3.1 approximation for scanner output normalization."""

    @staticmethod
    def from_confidence_impact(confidence: float, impact: float) -> CvssResult:
        score = max(0.0, min(10.0, round((confidence * 0.45 + impact * 0.55) * 10, 1)))
        if score >= 9.0:
            sev = "Critical"
        elif score >= 7.0:
            sev = "High"
        elif score >= 4.0:
            sev = "Medium"
        elif score > 0:
            sev = "Low"
        else:
            sev = "Info"
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        return CvssResult(score=score, vector=vector, severity=sev)
