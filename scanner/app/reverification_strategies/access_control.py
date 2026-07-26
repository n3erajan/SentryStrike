"""Access-control re-verification using dual-identity sessions."""

from __future__ import annotations

from app.core.detectors.access_control import AccessControlDetector
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


class AccessControlStrategy:
    family = ReverifyFamily.access_control

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

        haystack = f"{vuln_type or target.vuln_type or ''} {target.proof_type or ''}".lower()
        needs_secondary = "forced browsing" not in haystack
        if needs_secondary and not sessions.second_usable and not sessions.admin_usable:
            return inconclusive(
                url=target.url,
                method=target.method,
                reason=(
                    "Access-control re-verification requires a usable secondary "
                    "(second or admin) session."
                ),
            )

        detector = AccessControlDetector()
        kwargs = {
            "root_url": origin_url(target.url),
            "session_cookies": dict(sessions.main_cookies),
            "auth_headers": dict(sessions.main_headers),
            "second_user_cookies": dict(sessions.second_cookies) if sessions.second_usable else None,
            "second_user_headers": dict(sessions.second_headers) if sessions.second_usable else None,
            "privileged_cookies": dict(sessions.admin_cookies) if sessions.admin_usable else None,
            "privileged_headers": dict(sessions.admin_headers) if sessions.admin_usable else None,
        }
        # Prefer replaying the captured request observation when present.
        template = target.request_template if isinstance(target.request_template, dict) else {}
        if template:
            kwargs["requests"] = [
                type(
                    "ReverifyRequestObservation",
                    (),
                    {
                        "url": target.url,
                        "method": (target.method or "GET").upper(),
                        "post_data": (
                            template.get("form_body")
                            or template.get("json_body")
                            or template.get("body")
                            or ""
                        ),
                        "request_headers": template.get("headers") or {},
                        "replayable": True,
                        "body_schema": template.get("body_schema") or [],
                    },
                )()
            ]

        try:
            findings = await detector.detect([target.url], [], **kwargs)
        except Exception as exc:  # noqa: BLE001
            return inconclusive(
                url=target.url,
                method=target.method,
                reason=f"Access-control detector failed: {type(exc).__name__}: {exc}",
            )

        matches = match_findings(
            findings,
            url=target.url,
            vuln_type=vuln_type or target.vuln_type,
            parameter=target.parameter,
        )
        return outcome_from_matches(matches, url=target.url, method=target.method)


register_strategy(ReverifyFamily.access_control, AccessControlStrategy)
