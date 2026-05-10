from urllib.parse import parse_qsl, urlparse

from app.core.detectors.base_detector import BaseDetector, Finding
from app.models.vulnerability import OwaspCategory, SeverityLevel


class AccessControlDetector(BaseDetector):
    name = "access_control"

    sensitive_path_tokens = {
        "admin",
        "manage",
        "internal",
        "debug",
        "private",
        "config",
        "settings",
        "backup",
        "console",
        "panel",
        "restricted",
        "staff",
    }

    idor_param_tokens = {"id", "user", "user_id", "account", "account_id", "order", "order_id", "record", "record_id", "doc", "file", "item"}

    async def detect(self, urls: list[str], forms: list[object], **kwargs: object) -> list[Finding]:
        findings: list[Finding] = []
        for url in urls:
            parsed = urlparse(url)
            path_tokens = {segment.lower() for segment in parsed.path.split("/") if segment}
            if path_tokens.intersection(self.sensitive_path_tokens):
                findings.append(
                    Finding(
                        category=OwaspCategory.a01,
                        vuln_type="Potential Forced Browsing",
                        severity=SeverityLevel.medium,
                        url=url,
                        evidence="Sensitive path discovered without auth context.",
                    )
                )

            for param_name, _ in parse_qsl(parsed.query, keep_blank_values=True):
                lowered_name = param_name.lower()
                if lowered_name in self.idor_param_tokens or any(token in lowered_name for token in ["id", "user", "account", "order", "record", "doc", "file"]):
                    findings.append(
                        Finding(
                            category=OwaspCategory.a01,
                            vuln_type="Potential IDOR",
                            severity=SeverityLevel.high,
                            url=url,
                            parameter=param_name,
                            evidence="Object identifier parameter might be user-controlled.",
                        )
                    )

        for form in forms:
            input_names = {i.name.lower() for i in getattr(form, "inputs", [])}
            if input_names.intersection(self.idor_param_tokens):
                findings.append(
                    Finding(
                        category=OwaspCategory.a01,
                        vuln_type="Potential IDOR",
                        severity=SeverityLevel.high,
                        url=getattr(form, "action", getattr(form, "page_url", "")),
                        parameter=sorted(input_names.intersection(self.idor_param_tokens))[0],
                        method=getattr(form, "method", "POST"),
                        evidence="Form contains object identifier fields that should be authorization-checked.",
                    )
                )

        return findings
