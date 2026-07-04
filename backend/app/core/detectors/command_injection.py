import asyncio
import logging
from urllib.parse import urlparse

from app.config import get_settings
from app.core.detectors.base_detector import BaseDetector, Finding
from app.core.detectors.attack_surface import AttackSurface, AttackTarget
from app.core.verification.command_verifier import CommandInjectionVerifier

logger = logging.getLogger(__name__)


class CommandInjectionDetector(BaseDetector):
    name = "command_injection"

    cmd_param_tokens = {
        "ip", "host", "cmd", "exec", "ping", "command", "run", "args", "query", "target", "addr", "address",
        "domain", "server", "destination", "uri", "url"
    }
    endpoint_context_tokens = {
        "ping", "trace", "traceroute", "lookup", "nslookup", "dns", "whois", "network", "diagnostic",
        "command", "exec", "shell", "run", "proxy", "connect",
    }
    contextual_param_tokens = {
        "target", "value", "input", "query", "host", "ip", "addr", "address", "domain", "server",
        "destination", "url", "uri",
    }

    async def detect(self, urls: list[str], forms: list[object], **kwargs: object) -> list[Finding]:
        findings: list[Finding] = []
        session_cookies = kwargs.get("session_cookies") or {}
        scan_config = kwargs.get("scan_config")

        def cmd_filter(param_name: str) -> bool:
            return self._name_may_be_command_input(param_name)

        candidates = AttackSurface.build(
            urls,
            forms,
            parameters=kwargs.get("parameters") or [],
            api_endpoints=kwargs.get("api_endpoints") or [],
            requests=kwargs.get("requests") or [],
            filter_fn=cmd_filter,
        )
        candidates = [cand for cand in candidates if self._is_command_candidate(cand)]

        if not candidates:
            return []

        # 2. Active verification
        semaphore = asyncio.Semaphore(4)
        verifier = CommandInjectionVerifier(timeout_seconds=10.0)
        verifier.http_verifier.cookies = session_cookies
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

    def _name_may_be_command_input(self, param_name: str) -> bool:
        param_lower = param_name.lower()
        return (
            param_lower in self.cmd_param_tokens
            or param_lower in self.contextual_param_tokens
            or any(token in param_lower for token in ["cmd", "command", "exec", "run", "shell", "ping"])
        )

    def _is_command_candidate(self, target: AttackTarget) -> bool:
        param_lower = target.parameter.lower()
        if param_lower in self.cmd_param_tokens or any(
            token in param_lower for token in ["cmd", "command", "exec", "run", "shell", "ping"]
        ):
            return True

        path_tokens = {
            token
            for token in urlparse(target.url).path.lower().replace("-", "/").replace("_", "/").split("/")
            if token
        }
        has_endpoint_context = not path_tokens.isdisjoint(self.endpoint_context_tokens)
        return has_endpoint_context and param_lower in self.contextual_param_tokens
