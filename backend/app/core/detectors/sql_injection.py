"""
SQL Injection Detector - Active Verification Version

Redesigned for:
- Active exploitation testing
- Response differential analysis
- Confidence scoring
- Reduced false positives

Architecture:
1. Reconnaissance: Extract and prioritize candidates
2. Active Testing: Send verification payloads
3. Verification: Analyze responses for exploitation indicators
4. Reporting: Generate findings with confidence scores
"""

import asyncio
import logging
from urllib.parse import parse_qsl, urlparse

from app.core.detectors.base_detector import BaseDetector, Finding
from app.core.verification.sqli_verifier import SQLiVerifier
from app.core.verification.verification_framework import FindingDeduplicator
from app.models.vulnerability import OwaspCategory, SeverityLevel
from app.utils.payloads import payload_manager

logger = logging.getLogger(__name__)


class SQLInjectionDetector(BaseDetector):
    """Active verification-based SQL injection detector."""

    name = "injection_sql_command"

    # Parameter name heuristics for prioritization (not direct findings)
    PRIORITY_1_PARAMS = {
        # Database identity/keys
        "id", "ids", "uid", "uuid", "pid", "user_id", "userid",
        # Search/query
        "q", "query", "search", "keyword",
        # Common data parameters
        "order", "sort", "filter",
    }

    PRIORITY_2_PARAMS = {
        "name", "email", "username", "user", "account",
        "category", "product", "item", "page",
        "date", "time", "from", "to",
    }

    def __init__(self):
        super().__init__()
        self.verifier = SQLiVerifier(timeout_seconds=10.0)

    async def detect(self, urls: list[str], forms: list[object], **kwargs: object) -> list[Finding]:
        """
        Execute SQL injection detection using active verification.

        Returns only verified findings with confidence scores >= 50.
        """
        findings: list[Finding] = []

        # Phase 1: Reconnaissance - Extract candidates
        candidates = self._extract_candidates(urls, forms)
        logger.info(f"Found {len(candidates)} SQL injection candidates")

        # Phase 2: Active Testing - Verify each candidate
        verification_results = await self._verify_candidates(candidates)
        findings.extend(verification_results)

        # Phase 3: Filtering & Deduplication
        # Filter by confidence threshold
        findings = FindingDeduplicator.filter_by_confidence(findings, min_confidence=50.0)

        # Deduplicate (same url+param+type = merge evidence)
        findings = FindingDeduplicator.deduplicate(findings)

        logger.info(f"Returned {len(findings)} verified SQL injection findings")
        return findings

    def _extract_candidates(
        self,
        urls: list[str],
        forms: list[object],
    ) -> list[tuple[str, str, str, str]]:
        """
        Phase 1: Reconnaissance - Extract candidates without verifying.

        Returns list of (url, parameter, method, baseline_value) tuples.
        """
        candidates = []

        # --- URL parameter analysis ---
        for url in urls:
            parsed = urlparse(url)
            query_params = parse_qsl(parsed.query, keep_blank_values=True)

            for param_name, param_value in query_params:
                priority = self._get_parameter_priority(param_name)

                # Only test parameters with heuristic priority
                if priority >= 0:
                    candidates.append((url, param_name, "GET", param_value))

        # --- Form parameter analysis ---
        for form in forms:
            form_inputs = getattr(form, "inputs", [])
            if not form_inputs:
                continue

            form_url = getattr(form, "action", getattr(form, "page_url", ""))
            form_method = getattr(form, "method", "POST").upper()

            for input_elem in form_inputs:
                input_name = getattr(input_elem, "name", "")
                input_type = getattr(input_elem, "type", "text")

                # Skip submit buttons, file uploads, etc.
                if input_type in ("submit", "button", "reset", "file", "checkbox", "radio"):
                    continue

                priority = self._get_parameter_priority(input_name)

                # Only test parameters with heuristic priority
                if priority >= 0:
                    input_value = getattr(input_elem, "value", "")
                    candidates.append((form_url, input_name, form_method, input_value))

        return candidates

    def _get_parameter_priority(self, param_name: str) -> int:
        """
        Determine testing priority for a parameter.

        Returns:
            2 = high priority (P1), 1 = medium (P2), 0 = low/generic, -1 = skip
        """
        lowered = param_name.lower()

        # P1 params
        if lowered in self.PRIORITY_1_PARAMS:
            return 2

        # P2 params
        if lowered in self.PRIORITY_2_PARAMS:
            return 1

        # Generic suspicious tokens
        if any(tok in lowered for tok in ["id", "user", "query", "search", "filter"]):
            return 1

        # Command-like params (higher priority for other vulnerability class)
        if any(tok in lowered for tok in ["cmd", "exec", "run", "shell", "command"]):
            return 0  # Skip SQLi, let command detector handle it

        # Skip uninteresting params
        if lowered in ["lang", "locale", "theme", "format", "page_size"]:
            return -1

        # Medium priority for other unknown params
        return 1

    async def _verify_candidates(
        self,
        candidates: list[tuple[str, str, str, str]],
    ) -> list[Finding]:
        """
        Phase 2: Active Testing - Verify each candidate.

        Returns findings from successful verifications.
        """
        findings: list[Finding] = []

        # Process sequentially to avoid overwhelming target
        for url, param_name, method, baseline_value in candidates:
            try:
                result = await self.verifier.verify(
                    url=url,
                    parameter=param_name,
                    method=method,
                    value=baseline_value,
                )

                findings.extend(result.findings)

                # Small delay between tests to be respectful
                await asyncio.sleep(0.1)

            except Exception as e:
                logger.warning(f"Verification failed for {url}:{param_name}: {e}")
                continue

        return findings

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.verifier.close()
