import logging
from urllib.parse import urlparse
import re

from app.core.detectors.base_detector import BaseDetector, Finding
from app.core.verification.verification_framework import HttpVerifier
from app.models.vulnerability import OwaspCategory, SeverityLevel

logger = logging.getLogger(__name__)


class CryptoFailuresDetector(BaseDetector):
    name = "crypto_failures"

    async def detect(self, urls: list[str], forms: list[object], **kwargs: object) -> list[Finding]:
        findings: list[Finding] = []
        root_url = str(kwargs.get("root_url") or (urls[0] if urls else ""))
        session_cookies = kwargs.get("session_cookies") or {}
        insecure_transport_reported = False

        if root_url:
            parsed_root = urlparse(root_url)
            if parsed_root.scheme != "https":
                findings.append(
                    Finding(
                        category=OwaspCategory.a02,
                        vuln_type="Insecure Transport",
                        severity=SeverityLevel.high,
                        url=root_url,
                        evidence="Target does not enforce HTTPS.",
                        verified=True
                    )
                )
                insecure_transport_reported = True

        # Perform active checking for Secure cookies and mixed content on the pages
        verifier = HttpVerifier(cookies=session_cookies)
        verifier.set_request_context(module="crypto_failures")
        reported_session_cookies: set[str] = set()
        try:
            # Only test up to 5 URLs to keep it fast
            for url in urls[:5]:
                parsed = urlparse(url)
                if parsed.scheme != "https":
                    if not insecure_transport_reported:
                        findings.append(
                            Finding(
                                category=OwaspCategory.a02,
                                vuln_type="Insecure Transport",
                                severity=SeverityLevel.high,
                                url=url,
                                evidence="Endpoint does not enforce HTTPS.",
                                verified=True
                            )
                        )
                        insecure_transport_reported = True
                    continue

                # Fetch page
                response = await verifier.send_request(url, "GET", test_phase="transport_check")
                if response.status_code != 200:
                    continue

                # 1. Check for Mixed Content (HTTPS page referencing HTTP resources)
                mixed_content_resources = re.findall(r'(?:src|href)=["\'](http://[^"\']+)["\']', response.body, re.I)
                if mixed_content_resources:
                    findings.append(
                        Finding(
                            category=OwaspCategory.a02,
                            vuln_type="Mixed Content (HTTP resources loaded over HTTPS)",
                            severity=SeverityLevel.medium,
                            url=url,
                            evidence=f"HTTPS page loads insecure resources: {', '.join(mixed_content_resources[:3])}",
                            verified=True,
                            verification_request_snippet=response.request_snippet,
                            verification_response_snippet=response.response_snippet,
                            reproducible=True
                        )
                    )

                # 3. Check session cookie attributes on page load
                set_cookie_headers = [v for k, v in response.headers.items() if k.lower() == "set-cookie"]
                for header in set_cookie_headers:
                    cookie_parts = [p.strip().lower() for p in header.split(";")]
                    cookie_name = cookie_parts[0].split("=")[0] if "=" in cookie_parts[0] else ""

                    session_cookie_names = {
                        "session", "phpsessid", "jsessionid", "asp.net_sessionid",
                        "token", "auth", "jwt", "sid", "sessid",
                    }
                    if any(tok in cookie_name.lower() for tok in session_cookie_names):
                        if cookie_name in reported_session_cookies:
                            continue

                        missing_attrs = []
                        if "httponly" not in cookie_parts:
                            missing_attrs.append("HttpOnly")
                        if "secure" not in cookie_parts:
                            missing_attrs.append("Secure")
                        if not any(p.startswith("samesite") for p in cookie_parts):
                            missing_attrs.append("SameSite")

                        if missing_attrs:
                            reported_session_cookies.add(cookie_name)
                            findings.append(
                                Finding(
                                    category=OwaspCategory.a02,
                                    vuln_type="Insecure Session Cookie Attributes",
                                    severity=SeverityLevel.medium,
                                    url=url,
                                    evidence=(
                                        f"Session cookie '{cookie_name}' is missing security attributes: "
                                        f"{', '.join(missing_attrs)}."
                                    ),
                                    verified=True,
                                    verification_request_snippet=response.request_snippet,
                                    verification_response_snippet=response.response_snippet,
                                    reproducible=True,
                                )
                            )

                # 2. Check Set-Cookie secure flags
                set_cookie_headers = [v for k, v in response.headers.items() if k.lower() == "set-cookie"]
                for header in set_cookie_headers:
                    cookie_parts = [p.strip().lower() for p in header.split(";")]
                    cookie_name = cookie_parts[0].split("=")[0] if "=" in cookie_parts[0] else ""
                    if "secure" not in cookie_parts:
                        findings.append(
                            Finding(
                                category=OwaspCategory.a02,
                                vuln_type="Cookie Without Secure Flag",
                                severity=SeverityLevel.medium,
                                url=url,
                                evidence=f"Cookie '{cookie_name}' is set without the Secure attribute over HTTPS, allowing transmission over plaintext HTTP.",
                                verified=True,
                                verification_request_snippet=response.request_snippet,
                                verification_response_snippet=response.response_snippet,
                                reproducible=True
                            )
                        )

            # Heuristically check sensitive params in GET URLs
            for url in urls:
                lowered = url.lower()
                if any(token in lowered for token in ["token=", "password=", "secret="]):
                    findings.append(
                        Finding(
                            category=OwaspCategory.a02,
                            vuln_type="Sensitive Data in URL",
                            severity=SeverityLevel.high,
                            url=url,
                            evidence="Potential secret found in query string.",
                            verified=False
                        )
                    )

        except Exception as e:
            logger.error("Crypto Failures check failed: %s", e)
        finally:
            await verifier.close()

        return findings
