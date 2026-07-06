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

from app.config import get_settings
from app.core.detectors.base_detector import BaseDetector, Finding
from app.core.detectors.attack_surface import AttackSurface, AttackTarget
from app.core.verification.sqli_verifier import SQLiVerifier
from app.core.verification.verification_framework import FindingDeduplicator

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
        "category", "product", "item",
        "date", "time", "from", "to",
    }

    EXCLUDED_PARAMS = {
        "page", "file", "path", "include", "template", "doc", "dir", "load",
        "cmd", "exec", "command", "run", "shell", "ping",
    }

    # Input types to skip (submit buttons, file uploads, etc.)
    _SKIP_INPUT_TYPES = {"submit", "button", "reset", "image", "file", "checkbox", "radio"}

    def __init__(self):
        super().__init__()
        self.verifier = SQLiVerifier(timeout_seconds=10.0)

    async def detect(self, urls: list[str], forms: list[object], **kwargs: object) -> list[Finding]:
        """
        Execute SQL injection detection using active verification.

        Returns only verified findings with confidence scores >= 50.
        """
        findings: list[Finding] = []
        session_cookies = kwargs.get("session_cookies") or {}
        await self.verifier.http_verifier.configure_auth(
            cookies=session_cookies,
            auth_headers=kwargs.get("auth_headers"),
        )
        scan_config = kwargs.get("scan_config")
        settings = get_settings()
        self.verifier.blind_timing_threshold = (
            scan_config.get_val("blind_injection_timing_threshold", settings.blind_injection_timing_threshold)
            if scan_config else settings.blind_injection_timing_threshold
        )
        # Phase 1: Reconnaissance - Extract candidates
        candidates = self._extract_candidates(
            urls,
            forms,
            parameters=kwargs.get("parameters") or [],
            api_endpoints=kwargs.get("api_endpoints") or [],
            requests=kwargs.get("requests") or [],
        )
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
        *,
        parameters: list[object] | None = None,
        api_endpoints: list[object] | None = None,
        requests: list[object] | None = None,
    ) -> list[AttackTarget]:
        """
        Phase 1 & 2: Reconnaissance - Extract candidates using ParamDiscovery.
        """
        return AttackSurface.build(
            urls,
            forms,
            parameters=parameters,
            api_endpoints=api_endpoints,
            requests=requests,
            filter_fn=lambda p: self._get_parameter_priority(p) >= 0,
        )

    def _get_parameter_priority(self, param_name: str) -> int:
        """
        Determine testing priority for a parameter.

        Returns:
            2 = high priority (P1), 1 = medium (P2), 0 = low/generic, -1 = skip
        """
        lowered = param_name.lower()

        if lowered in self.EXCLUDED_PARAMS:
            return -1

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
        candidates: list[AttackTarget],
    ) -> list[Finding]:
        """
        Phase 2: Active Testing - Verify each candidate.

        Returns findings from successful verifications.
        Handles both 4-tuple (GET/URL) and 5-tuple (POST form) candidates.
        """
        findings: list[Finding] = []

        # Process sequentially to avoid overwhelming target
        for candidate in candidates:
            try:
                result = await self.verifier.verify(
                    url=candidate.url,
                    parameter=candidate.parameter,
                    method=candidate.method,
                    value=str(candidate.value),
                    form_inputs=candidate.form_inputs,
                    target=candidate,
                )

                findings.extend(result.findings)

                # Small delay between tests to be respectful
                await asyncio.sleep(0.1)

            except Exception as e:
                logger.warning("Verification failed for %s:%s: %s", candidate.url, candidate.parameter, e)
                continue

        return findings

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.verifier.close()
