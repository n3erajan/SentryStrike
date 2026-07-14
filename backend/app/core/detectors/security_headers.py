import httpx
import logging

from app.config import get_settings
from app.core.detectors.base_detector import BaseDetector, Finding
from app.models.vulnerability import OwaspCategory, SeverityLevel
from app.utils.http_logging import make_httpx_response_logger
from app.utils.scan_http import build_httpx_evidence_snippets, create_scan_client

logger = logging.getLogger(__name__)


class SecurityHeadersDetector(BaseDetector):
    name = "security_headers"

    def __init__(self) -> None:
        self.settings = get_settings()

    # A never-allowlisted attacker origin used to probe the target's CORS policy.
    _CORS_PROBE_ORIGIN = "https://sentrystrike-cors-probe.example"

    def _evaluate_cors(self, headers: dict[str, str], probe_origin: str) -> tuple[str, str] | None:
        """Judge a CORS response elicited by an arbitrary attacker ``Origin``.

        ``headers`` must have lowercased keys AND lowercased values (as produced
        in :meth:`detect`). Returns ``(severity_key, detail)`` when the policy is
        permissive toward the arbitrary origin, else ``None``. Only genuinely
        exploitable/permissive shapes are flagged so this stays low-FP:

        * ACAO reflects the arbitrary origin + credentials -> ``high``
        * ACAO reflects the arbitrary origin (no credentials) -> ``medium``
        * ACAO == ``*`` + credentials -> ``medium`` (non-browser clients honour it)
        * ACAO == ``*`` (no credentials) -> ``low`` (any origin reads responses)
        * ACAO == ``null`` -> ``medium`` (sandboxed/opaque origins granted access)

        A response that echoes back its OWN origin only, or omits ACAO, is a
        correctly-scoped policy and is not flagged.
        """
        acao = headers.get("access-control-allow-origin", "").strip()
        if not acao:
            return None
        credentials = headers.get("access-control-allow-credentials", "").strip() == "true"
        probe = probe_origin.strip().lower()

        if acao == probe:
            if credentials:
                return ("high", f"reflects an arbitrary request Origin ({probe_origin}) together with "
                                "Access-Control-Allow-Credentials: true — any website can read this "
                                "origin's authenticated responses")
            return ("medium", f"reflects an arbitrary request Origin ({probe_origin}) — any website can "
                              "read cross-origin responses from this origin")
        if acao == "*":
            if credentials:
                return ("medium", "wildcard Access-Control-Allow-Origin '*' combined with "
                                  "Access-Control-Allow-Credentials: true (honoured by non-browser clients)")
            return ("low", "wildcard Access-Control-Allow-Origin '*' allows any origin to read responses")
        if acao == "null":
            return ("medium", "Access-Control-Allow-Origin: null grants access to sandboxed/opaque origins")
        return None

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
            root_request_snippet, root_response_snippet = build_httpx_evidence_snippets(response)

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
                            verified=True,
                            verification_request_snippet=root_request_snippet,
                            verification_response_snippet=root_response_snippet,
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
                            verified=True,
                            verification_request_snippet=root_request_snippet,
                            verification_response_snippet=root_response_snippet,
                        )
                    )

            # CORS misconfiguration: send an arbitrary attacker Origin and see
            # whether the server grants it cross-origin read access.
            try:
                cors_response = await client.get(root_url, headers={"Origin": self._CORS_PROBE_ORIGIN})
            except Exception:
                cors_response = None
            if cors_response is not None:
                cors_headers = {k.lower(): v.lower() for k, v in cors_response.headers.items()}
                verdict = self._evaluate_cors(cors_headers, self._CORS_PROBE_ORIGIN)
                if verdict is not None:
                    severity_key, detail = verdict
                    severity_map = {
                        "high": SeverityLevel.high,
                        "medium": SeverityLevel.medium,
                        "low": SeverityLevel.low,
                    }
                    raw_acao = cors_response.headers.get("access-control-allow-origin")
                    raw_acac = cors_response.headers.get("access-control-allow-credentials") or "absent"
                    cors_request_snippet, cors_response_snippet = build_httpx_evidence_snippets(cors_response)
                    findings.append(
                        Finding(
                            category=OwaspCategory.a02,
                            vuln_type="CORS Misconfiguration",
                            severity=severity_map[severity_key],
                            url=root_url,
                            evidence=(
                                f"Cross-Origin Resource Sharing policy is permissive: {detail}. "
                                f"Probe Origin: {self._CORS_PROBE_ORIGIN}; "
                                f"Access-Control-Allow-Origin: {raw_acao}; "
                                f"Access-Control-Allow-Credentials: {raw_acac}."
                            ),
                            verified=True,
                            detection_method="cors_acao_probe",
                            verification_request_snippet=cors_request_snippet,
                            verification_response_snippet=cors_response_snippet,
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
                        verified=True,
                        verification_request_snippet=root_request_snippet,
                        verification_response_snippet=root_response_snippet,
                    )
                )

        return findings
