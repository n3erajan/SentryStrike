import httpx
import logging

from app.config import get_settings
from app.core.detectors.base_detector import BaseDetector, Finding
from app.models.vulnerability import OwaspCategory, SeverityLevel
from app.utils.http_logging import make_httpx_response_logger
from app.utils.scan_http import create_scan_client

logger = logging.getLogger(__name__)


class SecurityHeadersDetector(BaseDetector):
    name = "security_headers"

    def __init__(self) -> None:
        self.settings = get_settings()

    def _cache_controls_sensitive(self, cc: str, pragma: str, expires: str) -> bool:
        cc_lower = cc.lower()
        if "no-store" in cc_lower:
            return False
        if "no-cache" in cc_lower and "must-revalidate" in cc_lower:
            return False  # partial protection - skip or Info only
        if "private" in cc_lower:
            return False
        return True  # flag missing cache hardening

    async def detect(self, urls: list[str], forms: list[object], **kwargs: object) -> list[Finding]:
        findings: list[Finding] = []
        checked = set()
        required_headers = {
            "content-security-policy",
            "x-content-type-options",
            "strict-transport-security",
            "x-frame-options",
            "referrer-policy",
            "permissions-policy",
        }
        root_url = str(kwargs.get("root_url") or (urls[0] if urls else ""))

        if not root_url:
            return findings

        async with create_scan_client(
            timeout=self.settings.request_timeout_seconds,
            event_hooks={"response": [make_httpx_response_logger("security_headers", "header_check")]},
        ) as client:
            if root_url in checked:
                return findings
            checked.add(root_url)

            try:
                response = await client.get(root_url)
            except Exception:
                return findings

            headers = {k.lower(): v.lower() for k, v in response.headers.items()}
            
            # Check for missing headers
            for req_header in required_headers:
                if req_header not in headers:
                    findings.append(
                        Finding(
                            category=OwaspCategory.a02,
                            vuln_type="Missing Security Header",
                            severity=SeverityLevel.medium if req_header in ["content-security-policy", "x-frame-options"] else SeverityLevel.low,
                            url=root_url,
                            evidence=f"Header not found: {req_header}",
                            verified=True
                        )
                    )

            # Evaluate CSP policy quality
            csp = headers.get("content-security-policy", "")
            if csp:
                weaknesses = []
                if "unsafe-inline" in csp:
                    weaknesses.append("unsafe-inline is allowed in directives")
                if "unsafe-eval" in csp:
                    weaknesses.append("unsafe-eval is allowed in directives")
                if "*" in csp:
                    weaknesses.append("wildcard '*' source origin is allowed")
                
                if weaknesses:
                    findings.append(
                        Finding(
                            category=OwaspCategory.a02,
                            vuln_type="Weak Content Security Policy (CSP)",
                            severity=SeverityLevel.medium,
                            url=root_url,
                            evidence=f"CSP header policy is weak: {'; '.join(weaknesses)} (CSP: {response.headers.get('content-security-policy')})",
                            verified=True
                        )
                    )

            # Evaluate Cache-Control presence
            cc = headers.get("cache-control", "")
            pragma = headers.get("pragma", "")
            expires = headers.get("expires", "")
            
            # Only report on pages that appear sensitive
            set_cookies = headers.get("set-cookie", "")
            is_sensitive = False
            if set_cookies:
                for cookie in set_cookies.split(","):
                    if any(tok in cookie.lower() for tok in ["session", "token", "auth", "sid", "sessid", "jwt"]):
                        is_sensitive = True
                        break
                        
            # Server header version leak
            server_hdr = response.headers.get("server", "")
            if server_hdr and any(c.isdigit() for c in server_hdr):
                findings.append(
                    Finding(
                        category=OwaspCategory.a02,
                        vuln_type="Information Disclosure in Header",
                        severity=SeverityLevel.low,
                        url=root_url,
                        evidence=f"Server header leaks version: {server_hdr}",
                        verified=True
                    )
                )

        return findings
