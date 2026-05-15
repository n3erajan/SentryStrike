from dataclasses import dataclass


@dataclass
class CvssResult:
    score: float
    vector: str
    severity: str


class CvssCalculator:
    """Simple CVSS v3.1 approximation for scanner output normalization."""

    VULN_CVSS_PROFILES: dict[str, dict[str, str]] = {
        "Command Injection": {"ac": "L", "ui": "N", "s": "U", "c": "H", "i": "H", "a": "H"},
        "SQL Injection": {"ac": "L", "ui": "N", "s": "U", "c": "H", "i": "H", "a": "N"},
        "File Inclusion": {"ac": "L", "ui": "N", "s": "U", "c": "H", "i": "H", "a": "H"},
        "File Upload": {"ac": "L", "ui": "N", "s": "U", "c": "H", "i": "H", "a": "H"},
        "XSS": {"ac": "L", "ui": "R", "s": "C", "c": "L", "i": "L", "a": "N"},
        "CSRF": {"ac": "L", "ui": "R", "s": "U", "c": "N", "i": "L", "a": "N"},
        "SSRF": {"ac": "L", "ui": "N", "s": "C", "c": "H", "i": "N", "a": "N"},
        "IDOR": {"ac": "L", "ui": "N", "s": "U", "c": "H", "i": "N", "a": "N"},
        "Missing Security": {"ac": "H", "ui": "N", "s": "U", "c": "L", "i": "N", "a": "N"},
        "Insecure Transport": {"ac": "H", "ui": "N", "s": "U", "c": "H", "i": "N", "a": "N"},
        "Cookie": {"ac": "L", "ui": "N", "s": "U", "c": "L", "i": "N", "a": "N"},
    }

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

    @staticmethod
    def from_vulnerability_context(
        vuln_type: str,
        requires_auth: bool = False,
        confidence: float = 0.8,
        impact: float = 0.5,
    ) -> CvssResult:
        profile = {"ac": "L", "ui": "N", "s": "U", "c": "L", "i": "L", "a": "N"}
        for key, value in CvssCalculator.VULN_CVSS_PROFILES.items():
            if key.lower() in vuln_type.lower():
                profile = value
                break

        av = "N"
        pr = "L" if requires_auth else "N"
        vector = (
            f"CVSS:3.1/AV:{av}/AC:{profile['ac']}/PR:{pr}/UI:{profile['ui']}"
            f"/S:{profile['s']}/C:{profile['c']}/I:{profile['i']}/A:{profile['a']}"
        )

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

        return CvssResult(score=score, vector=vector, severity=sev)
