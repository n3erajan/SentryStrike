import math
from dataclasses import dataclass


@dataclass
class CvssResult:
    score: float
    vector: str
    severity: str


class CvssCalculator:
    """Standard CVSS v3.1 calculation for scanner output normalization."""

    VULN_CVSS_PROFILES: dict[str, dict[str, str]] = {
        # --- Critical (9.0+) ---
        "Command Injection": {"ac": "L", "ui": "N", "s": "U", "c": "H", "i": "H", "a": "H"},
        "SQL Injection": {"ac": "L", "ui": "N", "s": "U", "c": "H", "i": "H", "a": "N"},
        "File Inclusion": {"ac": "L", "ui": "N", "s": "U", "c": "H", "i": "H", "a": "H"},
        "File Upload": {"ac": "L", "ui": "N", "s": "U", "c": "H", "i": "H", "a": "H"},
        "Default Credentials": {"ac": "L", "ui": "N", "s": "U", "c": "H", "i": "H", "a": "H"},

        # --- High (7.0-8.9) ---
        "Path Traversal": {"ac": "L", "ui": "N", "s": "U", "c": "H", "i": "N", "a": "N"},
        "Arbitrary File Read": {"ac": "L", "ui": "N", "s": "U", "c": "H", "i": "N", "a": "N"},
        "IDOR": {"ac": "L", "ui": "N", "s": "U", "c": "H", "i": "N", "a": "N"},
        "Forced Browsing": {"ac": "L", "ui": "N", "s": "U", "c": "H", "i": "N", "a": "N"},
        "Sensitive File": {"ac": "L", "ui": "N", "s": "U", "c": "H", "i": "N", "a": "N"},
        "Brute-Force": {"ac": "L", "ui": "N", "s": "U", "c": "H", "i": "N", "a": "N"},
        "Credentials": {"ac": "L", "ui": "N", "s": "U", "c": "H", "i": "N", "a": "N"},
        "Token Exposed": {"ac": "L", "ui": "N", "s": "U", "c": "H", "i": "N", "a": "N"},
        "Insecure Transport": {"ac": "L", "ui": "N", "s": "U", "c": "H", "i": "N", "a": "N"},
        "Stored XSS": {"ac": "L", "ui": "R", "s": "C", "c": "L", "i": "H", "a": "N"},
        "SSRF": {"ac": "L", "ui": "N", "s": "C", "c": "H", "i": "N", "a": "N"},

        # --- Medium (4.0-6.9) ---
        "XSS": {"ac": "L", "ui": "R", "s": "C", "c": "L", "i": "L", "a": "N"},
        "CSRF": {"ac": "L", "ui": "R", "s": "U", "c": "N", "i": "L", "a": "N", "pr": "L"},
        "Cookie": {"ac": "L", "ui": "N", "s": "U", "c": "L", "i": "N", "a": "N"},
        "Mixed Content": {"ac": "L", "ui": "R", "s": "U", "c": "L", "i": "N", "a": "N"},
        "Open Redirect": {"ac": "L", "ui": "R", "s": "U", "c": "N", "i": "L", "a": "N"},
        "OAuth": {"ac": "L", "ui": "R", "s": "U", "c": "L", "i": "L", "a": "N"},
        "TLS": {"ac": "H", "ui": "N", "s": "U", "c": "H", "i": "N", "a": "N"},
        "SSL": {"ac": "H", "ui": "N", "s": "U", "c": "H", "i": "N", "a": "N"},
        "Vulnerable Component": {"ac": "L", "ui": "N", "s": "U", "c": "H", "i": "H", "a": "N"},

        # --- Low (0.1-3.9) ---
        "Missing Security": {"ac": "H", "ui": "N", "s": "U", "c": "L", "i": "N", "a": "N"},
        "Information Disclosure": {"ac": "H", "ui": "N", "s": "U", "c": "L", "i": "N", "a": "N"},
        "CSP": {"ac": "H", "ui": "N", "s": "U", "c": "L", "i": "N", "a": "N"},
        "Cache Control": {"ac": "H", "ui": "N", "s": "U", "c": "L", "i": "N", "a": "N"},
        "CAPTCHA": {"ac": "H", "ui": "N", "s": "U", "c": "L", "i": "N", "a": "N"},
        "Captcha": {"ac": "H", "ui": "N", "s": "U", "c": "L", "i": "N", "a": "N"},
        "Debug": {"ac": "H", "ui": "N", "s": "U", "c": "L", "i": "N", "a": "N"},
        "Metrics": {"ac": "H", "ui": "N", "s": "U", "c": "L", "i": "N", "a": "N"},
        "Autocomplete": {"ac": "H", "ui": "R", "s": "U", "c": "L", "i": "N", "a": "N"},
    }

    @staticmethod
    def _round_up(val: float) -> float:
        return math.ceil(val * 10) / 10.0

    @staticmethod
    def calculate_cvss_v31_score(vector: str) -> float:
        try:
            metrics = dict(part.split(":") for part in vector.split("/")[1:])
            
            weight_av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(metrics.get("AV"), 0.85)
            weight_ac = {"L": 0.77, "H": 0.44}.get(metrics.get("AC"), 0.77)
            
            s = metrics.get("S", "U")
            pr = metrics.get("PR", "N")
            if s == "U":
                weight_pr = {"N": 0.85, "L": 0.62, "H": 0.27}.get(pr, 0.85)
            else:
                weight_pr = {"N": 0.85, "L": 0.68, "H": 0.50}.get(pr, 0.85)
                
            weight_ui = {"N": 0.85, "R": 0.62}.get(metrics.get("UI"), 0.85)
            
            weight_c = {"N": 0.0, "L": 0.22, "H": 0.56}.get(metrics.get("C"), 0.0)
            weight_i = {"N": 0.0, "L": 0.22, "H": 0.56}.get(metrics.get("I"), 0.0)
            weight_a = {"N": 0.0, "L": 0.22, "H": 0.56}.get(metrics.get("A"), 0.0)
            
            iss = 1 - (1 - weight_c) * (1 - weight_i) * (1 - weight_a)
            
            if iss <= 0:
                return 0.0
                
            if s == "U":
                impact = 6.42 * iss
            else:
                impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
                
            exploitability = 8.22 * weight_av * weight_ac * weight_pr * weight_ui
            
            if s == "U":
                score = CvssCalculator._round_up(min(impact + exploitability, 10.0))
            else:
                score = CvssCalculator._round_up(min(1.08 * (impact + exploitability), 10.0))
                
            return score
        except Exception:
            return 0.0

    @staticmethod
    def get_severity(score: float) -> str:
        if score >= 9.0:
            return "Critical"
        if score >= 7.0:
            return "High"
        if score >= 4.0:
            return "Medium"
        if score > 0.0:
            return "Low"
        return "Info"

    @staticmethod
    def from_confidence_impact(confidence: float, impact: float) -> CvssResult:
        # Fallback for old callers, still use approximation if vector not built
        score = max(0.0, min(10.0, round((confidence * 0.45 + impact * 0.55) * 10, 1)))
        sev = CvssCalculator.get_severity(score)
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
        # Let the profile dictate PR if it's explicitly set (like CSRF or IDOR)
        default_pr = profile.get("pr", "L" if requires_auth else "N")
        
        vector = (
            f"CVSS:3.1/AV:{av}/AC:{profile['ac']}/PR:{default_pr}/UI:{profile['ui']}"
            f"/S:{profile['s']}/C:{profile['c']}/I:{profile['i']}/A:{profile['a']}"
        )

        score = CvssCalculator.calculate_cvss_v31_score(vector)
        sev = CvssCalculator.get_severity(score)

        return CvssResult(score=score, vector=vector, severity=sev)
