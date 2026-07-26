"""Scoped detect()-based re-verification strategies."""

from __future__ import annotations

from app.core.detectors.crypto_failures import CryptoFailuresDetector
from app.core.detectors.csrf_detector import CSRFDetector
from app.core.detectors.exception_handler import ExceptionHandlingDetector
from app.core.detectors.open_redirect import OpenRedirectDetector
from app.core.detectors.security_headers import SecurityHeadersDetector
from app.core.detectors.sensitive_paths import SensitivePathsDetector
from app.reverification_strategies import ResolvedSessions, register_strategy
from app.reverification_strategies.common import (
    inconclusive,
    match_findings,
    origin_url,
    outcome_from_matches,
)
from shared.models.reverification import ReverificationEvidence, ReverificationOutcome
from shared.models.scan import ScanAuthAccount
from shared.models.vulnerability import AuthContext, VerificationTarget
from shared.reverification.policy import ReverifyFamily


class _DetectStrategy:
    family: ReverifyFamily
    detector_factory: type

    def __init__(self, family: ReverifyFamily, detector_factory: type) -> None:
        self.family = family
        self.detector_factory = detector_factory

    async def run(
        self,
        target: VerificationTarget,
        *,
        sessions: ResolvedSessions,
        auth_accounts: list[ScanAuthAccount],
        vuln_type: str | None = None,
    ) -> tuple[ReverificationOutcome, list[ReverificationEvidence]]:
        _ = auth_accounts
        requires_auth = target.auth_context in {
            AuthContext.authenticated,
            AuthContext.requires_user_session,
        }
        if requires_auth and not sessions.main_usable:
            return inconclusive(
                url=target.url,
                method=target.method,
                reason="The finding requires authentication, but no usable session was resolved.",
            )

        detector = self.detector_factory()
        kwargs: dict = {
            "root_url": origin_url(target.url),
            "session_cookies": dict(sessions.main_cookies),
            "auth_headers": dict(sessions.main_headers),
        }
        if self.family == ReverifyFamily.sensitive_paths:
            # Sensitive-path discovery normally expands a site root into a large
            # candidate catalog. A focused replay must instead request the exact
            # route that produced the original content proof; otherwise custom
            # documentation, source-map, backup, and listing paths are never retried.
            kwargs["focused_probe_urls"] = [target.url]
        forms: list[object] = []
        template = target.request_template if isinstance(target.request_template, dict) else {}
        form_inputs = template.get("form_inputs")
        if form_inputs:
            forms.append(
                type(
                    "ReverifyForm",
                    (),
                    {
                        "page_url": target.url,
                        "action": target.url,
                        "method": (target.method or "GET").upper(),
                        "inputs": form_inputs,
                    },
                )()
            )

        error: Exception | None = None
        findings: list = []
        try:
            findings = await detector.detect([target.url], forms, **kwargs)
        except Exception as exc:  # noqa: BLE001 - surface as inconclusive evidence
            error = exc
        finally:
            close = getattr(detector, "close", None) or getattr(
                getattr(detector, "verifier", None), "close", None
            )
            if close is not None:
                try:
                    await close()
                except Exception:  # noqa: BLE001
                    pass

        if error is not None:
            return inconclusive(
                url=target.url,
                method=target.method,
                reason=f"Scoped detector run failed: {type(error).__name__}: {error}",
            )

        matches = match_findings(
            findings,
            url=target.url,
            vuln_type=vuln_type,
            parameter=target.parameter,
        )
        return outcome_from_matches(matches, url=target.url, method=target.method)


def _register(family: ReverifyFamily, factory: type) -> None:
    register_strategy(family, lambda f=family, det=factory: _DetectStrategy(f, det))


_register(ReverifyFamily.security_headers, SecurityHeadersDetector)
_register(ReverifyFamily.crypto_failures, CryptoFailuresDetector)
_register(ReverifyFamily.sensitive_paths, SensitivePathsDetector)
_register(ReverifyFamily.exception_handling, ExceptionHandlingDetector)
_register(ReverifyFamily.csrf, CSRFDetector)
_register(ReverifyFamily.open_redirect, OpenRedirectDetector)
