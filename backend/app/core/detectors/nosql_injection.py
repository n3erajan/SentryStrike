"""NoSQL Injection Detector — active-verification wrapper.

Selects JSON-body parameters (the only location a document-DB parses an operator
object as query logic) and runs :class:`NoSqliVerifier` against each. Verified
findings only. Structured like the command-injection detector.
"""

import asyncio
import logging

from app.config import get_settings
from app.core.crawler.models import ParameterLocation
from app.core.detectors.base_detector import BaseDetector, Finding
from app.core.detectors.attack_surface import AttackSurface, AttackTarget
from app.core.verification.nosqli_verifier import NoSqliVerifier

logger = logging.getLogger(__name__)

_JSON_BODY_LOCATIONS = {ParameterLocation.json_body, ParameterLocation.graphql_variable}
_BRACKET_LOCATIONS = {ParameterLocation.query, ParameterLocation.form}


class NoSqlInjectionDetector(BaseDetector):
    name = "nosql_injection"

    async def detect(self, urls: list[str], forms: list[object], **kwargs: object) -> list[Finding]:
        findings: list[Finding] = []
        session_cookies = kwargs.get("session_cookies") or {}
        scan_config = kwargs.get("scan_config")

        planner = kwargs.get("attack_planner")
        surface = (
            planner.targets_for(self.name)
            if planner is not None and hasattr(planner, "targets_for")
            else AttackSurface.build(
                urls,
                forms,
                parameters=kwargs.get("parameters") or [],
                api_endpoints=kwargs.get("api_endpoints") or [],
                requests=kwargs.get("requests") or [],
            )
        )
        candidates = [cand for cand in surface if self._is_nosql_candidate(cand)]
        if not candidates:
            return []

        semaphore = asyncio.Semaphore(4)
        verifier = NoSqliVerifier(timeout_seconds=10.0)
        await verifier.http_verifier.configure_auth(
            cookies=session_cookies,
            auth_headers=kwargs.get("auth_headers"),
        )
        settings = get_settings()
        verifier.blind_timing_threshold = (
            scan_config.get_val("blind_injection_timing_threshold", settings.blind_injection_timing_threshold)
            if scan_config else settings.blind_injection_timing_threshold
        )

        async def verify_candidate(cand: AttackTarget) -> list[Finding]:
            async with semaphore:
                try:
                    result = await verifier.verify(
                        cand.url,
                        cand.parameter,
                        cand.method,
                        str(cand.value),
                        form_inputs=cand.form_inputs,
                        target=cand,
                    )
                    if result.is_vulnerable:
                        return result.findings
                except Exception as e:
                    logger.error(
                        "NoSQL injection verification failed for %s param %s: %s",
                        cand.url, cand.parameter, e,
                    )
                return []

        tasks = [verify_candidate(c) for c in candidates]
        results = await asyncio.gather(*tasks)
        for res in results:
            findings.extend(res)

        await verifier.close()
        return findings

    @staticmethod
    def _is_nosql_candidate(target: AttackTarget) -> bool:
        """Select a target that can carry an operator object.

        Two transports reach a document-DB filter with a nested operator:
          * a JSON body (``{"field": {"$ne": …}}``) — always in scope, and
          * a query/form param via bracket notation (``field[$ne]=…``, which the
            qs parser re-nests) — in scope when the param is a real observed one
            (``replayable``), which bounds the fan-out to genuine inputs rather
            than static-synthesis guesses.
        Path/header/cookie locations cannot express a nested operator."""
        if target.location in _JSON_BODY_LOCATIONS:
            return True
        if target.location in _BRACKET_LOCATIONS:
            return bool(getattr(target, "replayable", True))
        return False
