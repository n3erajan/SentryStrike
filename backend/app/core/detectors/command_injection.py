import asyncio
import logging

from app.core.detectors.base_detector import BaseDetector, Finding
from app.core.detectors.attack_surface import AttackSurface, AttackTarget
from app.core.verification.command_verifier import CommandInjectionVerifier

logger = logging.getLogger(__name__)


class CommandInjectionDetector(BaseDetector):
    name = "command_injection"

    cmd_param_tokens = {
        "ip", "host", "cmd", "exec", "ping", "command", "run", "args", "query", "target", "addr", "address"
    }

    async def detect(self, urls: list[str], forms: list[object], **kwargs: object) -> list[Finding]:
        findings: list[Finding] = []
        session_cookies = kwargs.get("session_cookies") or {}

        def cmd_filter(param_name: str) -> bool:
            param_lower = param_name.lower()
            return param_lower in self.cmd_param_tokens or any(
                token in param_lower for token in ["cmd", "command", "exec", "run", "shell", "ping"]
            )

        candidates = AttackSurface.build(
            urls,
            forms,
            parameters=kwargs.get("parameters") or [],
            api_endpoints=kwargs.get("api_endpoints") or [],
            requests=kwargs.get("requests") or [],
            filter_fn=cmd_filter,
        )

        if not candidates:
            return []

        # 2. Active verification
        semaphore = asyncio.Semaphore(4)
        verifier = CommandInjectionVerifier(timeout_seconds=10.0)
        verifier.http_verifier.cookies = session_cookies

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
