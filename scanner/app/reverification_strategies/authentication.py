"""Authentication-failure re-verification for self-contained findings."""

from __future__ import annotations

from app.core.detectors.auth_detector import AuthenticationFailuresDetector
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


class AuthenticationStrategy:
    family = ReverifyFamily.authentication

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

        detector = AuthenticationFailuresDetector()
        template = target.request_template if isinstance(target.request_template, dict) else {}
        forms: list[object] = []
        form_inputs = template.get("form_inputs")
        if form_inputs:
            forms.append(
                type(
                    "ReverifyForm",
                    (),
                    {
                        "page_url": target.url,
                        "action": target.url,
                        "method": (target.method or "POST").upper(),
                        "inputs": form_inputs,
                    },
                )()
            )

        kwargs = {
            "root_url": origin_url(target.url),
            "session_cookies": dict(sessions.main_cookies),
            "auth_headers": dict(sessions.main_headers),
        }
        try:
            findings = await detector.detect([target.url], forms, **kwargs)
        except Exception as exc:  # noqa: BLE001
            return inconclusive(
                url=target.url,
                method=target.method,
                reason=f"Authentication detector failed: {type(exc).__name__}: {exc}",
            )

        matches = match_findings(
            findings,
            url=target.url,
            vuln_type=vuln_type,
            parameter=target.parameter,
        )
        return outcome_from_matches(matches, url=target.url, method=target.method)


register_strategy(ReverifyFamily.authentication, AuthenticationStrategy)
