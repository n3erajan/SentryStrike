"""Verifier-backed (and scoped-detect fallback) injection re-verification."""

from __future__ import annotations

from typing import Any

from app.core.detectors.file_inclusion import FileInclusionDetector
from app.core.detectors.file_upload import FileUploadDetector
from app.core.detectors.ssrf_detector import SSRFDetector
from app.core.verification.command_verifier import CommandInjectionVerifier
from app.core.verification.nosqli_verifier import NoSqliVerifier
from app.core.verification.sqli_verifier import SQLiVerifier
from app.core.verification.xss_verifier import PLAYWRIGHT_AVAILABLE, XSSVerifier
from app.reverification_strategies import ResolvedSessions, register_strategy
from app.reverification_strategies.common import (
    inconclusive,
    match_findings,
    origin_url,
    outcome_from_matches,
    rebuild_attack_target,
)
from shared.models.reverification import ReverificationEvidence, ReverificationOutcome
from shared.models.scan import ScanAuthAccount
from shared.models.vulnerability import AuthContext, VerificationTarget
from shared.reverification.policy import ReverifyFamily


class _VerifierStrategy:
    family: ReverifyFamily

    def __init__(self, family: ReverifyFamily, verifier_factory) -> None:
        self.family = family
        self.verifier_factory = verifier_factory

    async def run(
        self,
        target: VerificationTarget,
        *,
        sessions: ResolvedSessions,
        auth_accounts: list[ScanAuthAccount],
        vuln_type: str | None = None,
    ) -> tuple[ReverificationOutcome, list[ReverificationEvidence]]:
        _ = auth_accounts, vuln_type
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
        if not target.parameter:
            return inconclusive(
                url=target.url,
                method=target.method,
                reason="Injection re-verification requires a captured parameter.",
            )

        attack_target = rebuild_attack_target(target)
        verifier = self.verifier_factory()
        try:
            await verifier.http_verifier.configure_auth(
                cookies=sessions.main_cookies,
                auth_headers=sessions.main_headers,
            )
            result = await verifier.verify(
                url=attack_target.url,
                parameter=attack_target.parameter,
                method=attack_target.method,
                value=str(attack_target.value or ""),
                form_inputs=attack_target.form_inputs,
                target=attack_target,
            )
        except Exception as exc:  # noqa: BLE001
            return inconclusive(
                url=target.url,
                method=target.method,
                reason=f"Verifier run failed: {type(exc).__name__}: {exc}",
            )
        finally:
            close = getattr(verifier, "close", None)
            if close is not None:
                try:
                    await close()
                except Exception:  # noqa: BLE001
                    pass

        if result.is_vulnerable:
            snippet = None
            if result.findings:
                top = result.findings[0]
                snippet = (top.verification_response_snippet or top.evidence or "")[:2000]
            return (
                ReverificationOutcome.reproduced,
                [
                    ReverificationEvidence(
                        request_url=target.url,
                        request_method=(target.method or "GET").upper(),
                        reason=(
                            f"Verifier re-confirmed the finding via {result.detection_method} "
                            f"(confidence {result.confidence_score:.0f})."
                        ),
                        response_snippet=snippet,
                        proof_matched=True,
                    )
                ],
            )
        return (
            ReverificationOutcome.not_reproduced,
            [
                ReverificationEvidence(
                    request_url=target.url,
                    request_method=(target.method or "GET").upper(),
                    reason="Verifier did not re-confirm the original injection finding.",
                    proof_matched=False,
                )
            ],
        )


class _XSSStrategy(_VerifierStrategy):
    """Replay XSS with the same browser phases used by the full detector."""

    def __init__(self) -> None:
        super().__init__(ReverifyFamily.xss, XSSVerifier)

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

        proof_haystack = f"{vuln_type or target.vuln_type or ''} {target.proof_type or ''}".lower()
        is_dom_xss = "dom" in proof_haystack and "xss" in proof_haystack
        if is_dom_xss and not PLAYWRIGHT_AVAILABLE:
            return inconclusive(
                url=target.url,
                method=target.method,
                reason="DOM XSS re-verification requires the browser runtime, which is unavailable.",
            )
        if not target.parameter and not is_dom_xss:
            return inconclusive(
                url=target.url,
                method=target.method,
                reason="Injection re-verification requires a captured parameter.",
            )

        verifier = XSSVerifier()
        try:
            await verifier.http_verifier.configure_auth(
                cookies=sessions.main_cookies,
                auth_headers=sessions.main_headers,
            )

            if is_dom_xss:
                parameter = (target.parameter or "").strip()
                if parameter and parameter.lower() != "javascript":
                    browser_result = await verifier.verify_reflected_dom(
                        target.url,
                        parameter,
                        target.parameter_location or "query",
                    )
                    reproduced = bool(browser_result.get("fired"))
                    surface = browser_result.get("surface") or target.parameter_location or "DOM"
                    proof_url = str(browser_result.get("url") or target.url)
                    proof_detail = (
                        f"Browser re-confirmed DOM XSS through the {surface} surface."
                        if reproduced
                        else "Browser probes did not re-confirm DOM XSS execution."
                    )
                else:
                    reproduced = await verifier.verify_dom_xss_execution(target.url)
                    proof_url = target.url
                    proof_detail = (
                        "Browser re-confirmed DOM XSS execution."
                        if reproduced
                        else "Browser probes did not re-confirm DOM XSS execution."
                    )
                return (
                    ReverificationOutcome.reproduced
                    if reproduced
                    else ReverificationOutcome.not_reproduced,
                    [
                        ReverificationEvidence(
                            request_url=proof_url,
                            request_method="GET",
                            reason=proof_detail,
                            proof_matched=reproduced,
                        )
                    ],
                )

            attack_target = rebuild_attack_target(target)
            result = await verifier.verify(
                url=attack_target.url,
                parameter=attack_target.parameter,
                method=attack_target.method,
                value=str(attack_target.value or ""),
                form_inputs=attack_target.form_inputs,
                target=attack_target,
            )
            if result.is_vulnerable:
                snippet = None
                if result.findings:
                    top = result.findings[0]
                    snippet = (top.verification_response_snippet or top.evidence or "")[:2000]
                return (
                    ReverificationOutcome.reproduced,
                    [
                        ReverificationEvidence(
                            request_url=target.url,
                            request_method=(target.method or "GET").upper(),
                            reason=(
                                f"Verifier re-confirmed the finding via {result.detection_method} "
                                f"(confidence {result.confidence_score:.0f})."
                            ),
                            response_snippet=snippet,
                            proof_matched=True,
                        )
                    ],
                )

            pending_jobs = list(result.evidence.get("pending_jobs") or [])
            if not pending_jobs and result.evidence.get("browser_verification_pending"):
                pending_job = result.evidence.get("pending_job")
                if pending_job is not None:
                    pending_jobs.append(pending_job)
            if pending_jobs:
                if not PLAYWRIGHT_AVAILABLE:
                    return inconclusive(
                        url=target.url,
                        method=target.method,
                        reason="XSS execution confirmation requires the browser runtime, which is unavailable.",
                    )
                for pending_job in pending_jobs:
                    browser_findings = await verifier.run_browser_verification(pending_job)
                    if browser_findings:
                        top = browser_findings[0]
                        return (
                            ReverificationOutcome.reproduced,
                            [
                                ReverificationEvidence(
                                    request_url=target.url,
                                    request_method=(target.method or "GET").upper(),
                                    reason="Browser execution re-confirmed the original XSS finding.",
                                    response_snippet=(
                                        top.verification_response_snippet or top.evidence or ""
                                    )[:2000]
                                    or None,
                                    proof_matched=True,
                                )
                            ],
                        )
                    browser_error = getattr(
                        verifier, "_last_browser_verification_error", None
                    )
                    if browser_error is not None:
                        return inconclusive(
                            url=target.url,
                            method=target.method,
                            reason=(
                                "XSS browser confirmation failed: "
                                f"{type(browser_error).__name__}: {browser_error}"
                            ),
                        )
        except Exception as exc:  # noqa: BLE001
            return inconclusive(
                url=target.url,
                method=target.method,
                reason=f"XSS verifier run failed: {type(exc).__name__}: {exc}",
            )
        finally:
            try:
                await verifier.close()
            except Exception:  # noqa: BLE001
                pass

        return (
            ReverificationOutcome.not_reproduced,
            [
                ReverificationEvidence(
                    request_url=target.url,
                    request_method=(target.method or "GET").upper(),
                    reason="Verifier did not re-confirm the original XSS finding.",
                    proof_matched=False,
                )
            ],
        )


class _ScopedInjectionDetectStrategy:
    """For injection detectors that lack a BaseVerifier.verify entry point."""

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
        kwargs: dict[str, Any] = {
            "root_url": origin_url(target.url),
            "session_cookies": dict(sessions.main_cookies),
            "auth_headers": dict(sessions.main_headers),
        }
        try:
            findings = await detector.detect([target.url], [], **kwargs)
        except Exception as exc:  # noqa: BLE001
            return inconclusive(
                url=target.url,
                method=target.method,
                reason=f"Scoped injection detector failed: {type(exc).__name__}: {exc}",
            )

        matches = match_findings(
            findings,
            url=target.url,
            vuln_type=vuln_type,
            parameter=target.parameter,
        )
        return outcome_from_matches(matches, url=target.url, method=target.method)


def _register_verifier(family: ReverifyFamily, factory) -> None:
    register_strategy(family, lambda f=family, fac=factory: _VerifierStrategy(f, fac))


def _register_detect(family: ReverifyFamily, factory: type) -> None:
    register_strategy(
        family, lambda f=family, det=factory: _ScopedInjectionDetectStrategy(f, det)
    )


_register_verifier(ReverifyFamily.sql_injection, SQLiVerifier)
_register_verifier(ReverifyFamily.nosql_injection, NoSqliVerifier)
_register_verifier(ReverifyFamily.command_injection, CommandInjectionVerifier)
register_strategy(ReverifyFamily.xss, _XSSStrategy)
_register_detect(ReverifyFamily.file_inclusion, FileInclusionDetector)
_register_detect(ReverifyFamily.ssrf, SSRFDetector)
_register_detect(ReverifyFamily.file_upload, FileUploadDetector)
