import re

from app.core.detectors.base_detector import Finding
from shared.models.vulnerability import OwaspCategory, SeverityLevel


class ObservedAuthEvidenceMixin:
    _CREDENTIAL_DISCLOSURE_PATTERNS: list[re.Pattern] = [
        re.compile(p, re.IGNORECASE)
        for p in [
            r"password\s*=",
            r"db_password|database_password|db_pass",
        ]
    ]

    # SQL-statement keywords used to recognise a reflected query echo (see
    # ``_is_reflected_sql_echo``). Injection detectors surface DB error bodies
    # that echo the application's own query — ``... WHERE email = '<payload>' AND
    # password = '<hash>' ...`` — where ``password =`` is a SQL comparison, not a
    # disclosed credential. Framework-agnostic: SQL keyword syntax is universal.
    _SQL_STATEMENT_RE = re.compile(r"\b(?:select|insert|update|delete)\b", re.IGNORECASE)
    _SQL_PASSWORD_COMPARISON_RE = re.compile(
        r"(?:where\b[^;]{0,300}?)?password\s*=\s*['\"]", re.IGNORECASE | re.DOTALL
    )

    @classmethod
    def _is_reflected_sql_echo(cls, text: str) -> bool:
        """True when a ``password =`` match is part of an echoed SQL statement.

        A DB error that reflects the query (``SELECT ... WHERE ... password =
        '...'``) is not a credential/config disclosure — it is the injected query
        surfaced by the source injection finding, already reported there. Only a
        genuine config-style assignment (``db_password=...`` outside any SQL
        statement) should survive as credential disclosure.
        """
        if not cls._SQL_STATEMENT_RE.search(text):
            return False
        return bool(cls._SQL_PASSWORD_COMPARISON_RE.search(text))

    @classmethod
    def _filter_reflected_credential_matches(
        cls, text: str, matched_patterns: list[str]
    ) -> list[str]:
        if not matched_patterns:
            return matched_patterns
        if not cls._is_reflected_sql_echo(text):
            return matched_patterns
        # Drop the bare ``password =`` comparison echoed from SQL; keep explicit
        # config keys (db_password/database_password/db_pass) which never appear
        # as a SQL comparison operand.
        return [p for p in matched_patterns if p != r"password\s*="]

    def findings_from_observed_evidence(
        self,
        observed_findings: list[Finding],
    ) -> list[Finding]:
        """Derive credential/config disclosure findings from other detectors' evidence snippets.

        When the response body of another detector's confirmed finding (e.g. SQLi, LFI)
        contains database credential or configuration keys leaked in error output, this
        method independently reports it under A07 / Authentication Failures.
        """
        findings: list[Finding] = []
        seen: set[tuple] = set()

        for source in observed_findings or []:
            observed_text = source.verification_response_snippet or ""
            if not observed_text:
                continue

            matched_patterns = [
                p.pattern for p in self._CREDENTIAL_DISCLOSURE_PATTERNS
                if p.search(observed_text)
            ]
            matched_patterns = self._filter_reflected_credential_matches(
                observed_text, matched_patterns
            )
            if not matched_patterns:
                continue

            dedup_key = (source.url or "", "Credential / Config Disclosure in Response Body")
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            findings.append(
                Finding(
                    category=OwaspCategory.a07,
                    vuln_type="Credential / Config Disclosure in Response Body",
                    severity=SeverityLevel.high,
                    url=source.url or "",
                    parameter=source.parameter,
                    method=source.method,
                    evidence=(
                        f"Credential or configuration key disclosed in response body: "
                        f"{', '.join(matched_patterns[:2])}. "
                        f"Observed during {source.vuln_type} verification."
                    ),
                    confidence_score=85.0,
                    detection_method="observed_credential_disclosure",
                    detection_evidence={
                        "source_vuln_type": source.vuln_type,
                        "source_detection_method": getattr(source, "detection_method", None),
                        "matched_patterns": matched_patterns,
                    },
                    verified=True,
                    reproducible=getattr(source, "reproducible", False),
                    verification_request_snippet=getattr(source, "verification_request_snippet", None),
                    verification_response_snippet=observed_text or getattr(source, "verification_response_snippet", None),
                )
            )

        return findings
