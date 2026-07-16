import asyncio
import logging

from app.config import get_settings
from app.core.detectors.base_detector import BaseDetector, Finding
from app.core.detectors.attack_surface import AttackSurface, AttackTarget
from app.core.detectors.param_selection import command_candidate, is_opaque_timing_value
from app.core.verification.command_verifier import CommandInjectionVerifier

logger = logging.getLogger(__name__)


class CommandInjectionDetector(BaseDetector):
    name = "command_injection"

    async def detect(self, urls: list[str], forms: list[object], **kwargs: object) -> list[Finding]:
        findings: list[Finding] = []
        session_cookies = kwargs.get("session_cookies") or {}
        scan_config = kwargs.get("scan_config")

        # Build the surface UNFILTERED, then select value-aware so that params
        # with a generic name still qualify via a shell/host-shaped value or a
        # diagnostic endpoint context. Command injection is often blind (no value
        # shape at all), so any *replayable* param carrying a substantive opaque
        # value is also allowed through to the timing probe — a positive signal
        # is preferred, but its absence must not zero out coverage.
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
        candidates = [cand for cand in surface if self._is_command_candidate(cand)]

        if not candidates:
            return []

        # 2. Active verification
        semaphore = asyncio.Semaphore(4)
        verifier = CommandInjectionVerifier(timeout_seconds=10.0)
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
                        "Command injection verification failed for %s param %s: %s",
                        cand.url, cand.parameter, e,
                    )
                return []

        tasks = [verify_candidate(c) for c in candidates]
        results = await asyncio.gather(*tasks)
        for res in results:
            findings.extend(res)

        await verifier.close()
        return findings

    def _is_command_candidate(self, target: AttackTarget) -> bool:
        """Select a target for command-injection probing.

        Positive signal — a command-token name, a shell/host-shaped value, or a
        diagnostic endpoint context (via the shared value-aware selection). Or,
        for blind command injection (no value shape), any *replayable* target
        whose baseline value is a substantive opaque string, so replayable
        params are never silently dropped for lacking a positive signal.
        """
        if command_candidate(target.parameter, target.value, target.url):
            return True
        return bool(getattr(target, "replayable", False)) and is_opaque_timing_value(target.value)
