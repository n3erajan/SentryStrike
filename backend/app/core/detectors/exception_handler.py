import httpx

from app.config import get_settings
from app.core.detectors.base_detector import BaseDetector, Finding
from app.models.vulnerability import OwaspCategory, SeverityLevel


class ExceptionHandlingDetector(BaseDetector):
    name = "exception_handling"

    def __init__(self) -> None:
        self.settings = get_settings()

    async def detect(self, urls: list[str], forms: list[object], **kwargs: object) -> list[Finding]:
        findings: list[Finding] = []
        test_suffix = "non-existent-sentry-strike-endpoint"

        async with httpx.AsyncClient(timeout=self.settings.request_timeout_seconds) as client:
            for url in urls[:10]:
                test_url = f"{url.rstrip('/')}/{test_suffix}"
                try:
                    response = await client.get(test_url)
                except Exception:
                    continue

                body = response.text.lower()
                status_markers = {500, 501, 502, 503, 504}
                markers = [
                    "traceback",
                    "exception",
                    "stack trace",
                    "sql syntax",
                    "nullreference",
                    "fatal error",
                    "warning:",
                    "undefined index",
                    "unhandled",
                    "internal server error",
                    "pdoexception",
                    "sqlstate",
                ]
                if response.status_code in status_markers or any(marker in body for marker in markers):
                    findings.append(
                        Finding(
                            category=OwaspCategory.a10,
                            vuln_type="Verbose Error Handling",
                            severity=SeverityLevel.medium,
                            url=test_url,
                            evidence="Error response appears to leak internal exception details.",
                        )
                    )
        return findings
