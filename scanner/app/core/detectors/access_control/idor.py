import asyncio
import logging

from app.core.detectors.attack_surface import AttackTarget, PreparedAttackRequest
from app.core.detectors.base_detector import Finding
from app.core.verification.verification_framework import HttpVerifier
from shared.models.vulnerability import OwaspCategory, SeverityLevel

from app.core.detectors.access_control.common import (
    _MUTATING_AUTHZ_METHODS,
    _looks_like_login_page,
    _looks_like_error_page,
    _mutate_id,
    _differential_idor_verdict,
    _body_similarity,
)

logger = logging.getLogger("app.core.detectors.access_control")


class IdorMixin:
    @staticmethod
    def _reverification_request_evidence(request: PreparedAttackRequest) -> dict:
        """Capture the exact non-secret request shape used to prove an IDOR."""
        template: dict = {"replay_exact": True}
        if request.json_body is not None:
            template["json_body"] = request.json_body
        elif request.data is not None:
            template["form_body"] = request.data
        return {
            "request_url": request.url,
            "request_template": template,
        }

    async def _check_idor(
        self,
        urls: list[str],
        forms: list[object],
        unauthed_verifier: HttpVerifier,
        authed_verifier: HttpVerifier,
        privileged_verifier: HttpVerifier | None,
        second_verifier: HttpVerifier | None,
        **kwargs: object,
    ) -> list[Finding]:
        findings: list[Finding] = []
        semaphore = asyncio.Semaphore(self._CONCURRENCY)
        response_ids = self._response_body_ids(kwargs.get("requests") or [])
        idor_targets = self._build_idor_targets(urls, forms, **kwargs)

        if not idor_targets:
            return findings

        async def _verify(target: AttackTarget) -> list[Finding]:
            cand_findings: list[Finding] = []
            baseline_values = self._baseline_values_for_target(target, response_ids)

            async with semaphore:
                for val in baseline_values:
                    try:
                        target_findings = await self._verify_idor_baseline(
                            target,
                            str(val),
                            unauthed_verifier,
                            authed_verifier,
                            privileged_verifier,
                            second_verifier,
                        )
                        cand_findings.extend(target_findings)
                        if target_findings:
                            break
                    except Exception:
                        logger.exception("IDOR verification failed for %s param=%s", target.url, target.parameter)

            return cand_findings

        results = await asyncio.gather(*[_verify(target) for target in idor_targets])
        for r in results:
            findings.extend(r)
        return findings

    async def _verify_idor_baseline(
        self,
        target: AttackTarget,
        val: str,
        unauthed_verifier: HttpVerifier,
        authed_verifier: HttpVerifier,
        privileged_verifier: HttpVerifier | None,
        second_verifier: HttpVerifier | None,
    ) -> list[Finding]:
        cand_findings: list[Finding] = []

        # SAFETY: the read-oriented IDOR baseline fires ``target.method`` on the
        # OWNER's real value first (``idor_authed_own``). For a state-changing
        # method that would mutate/destroy the owner's real resource, and the
        # body-similarity verdict is meaningless on the empty/204 response anyway.
        # Mutating-method authorization is handled non-destructively (synthetic
        # non-existent id + status differential) by ``_check_mutating_authorization``.
        if target.method.upper() in _MUTATING_AUTHZ_METHODS:
            return []

        mutated_vals = _mutate_id(val)

        own_request = self._build_request_for_value(target, val)
        unauth_own_resp = await self._send_prepared_request(
            unauthed_verifier, own_request, test_phase="idor_unauth_own"
        )

        if self._is_public_resource_response(unauth_own_resp):
            logger.debug(
                "IDOR skip: original resource is public at %s param=%s val=%s",
                target.url,
                target.parameter,
                val,
            )
            return []

        auth_own_resp = await self._send_prepared_request(
            authed_verifier, own_request, test_phase="idor_authed_own"
        )

        if auth_own_resp.status_code not in (200, 201):
            logger.debug(
                "IDOR skip: authed session cannot access own resource %s param=%s",
                target.url,
                target.parameter,
            )
            return []

        if _looks_like_error_page(auth_own_resp.body):
            logger.debug(
                "IDOR skip: own resource response looks like an error page %s param=%s",
                target.url,
                target.parameter,
            )
            return []

        if second_verifier is not None:
            second_own_resp = await self._send_prepared_request(
                second_verifier, own_request, test_phase="idor_second_user_own"
            )
            if (
                second_own_resp.status_code in (200, 201)
                and not _looks_like_login_page(second_own_resp.body)
                and not _looks_like_error_page(second_own_resp.body)
            ):
                similarity = _body_similarity(auth_own_resp.body, second_own_resp.body)
                own_profile = self._response_profile(auth_own_resp)
                second_profile = self._response_profile(second_own_resp)
                if similarity > 0.70 and (
                    self._shared_identifiers(own_profile, second_profile)
                    or self._profile_has_sensitive_data(own_profile)
                ):
                    is_create = target.method.upper() == "POST"
                    cand_findings.append(
                        Finding(
                            category=OwaspCategory.a01,
                            vuln_type=(
                                "Broken Object-Level Authorization"
                                if is_create
                                else "Insecure Direct Object Reference (IDOR)"
                            ),
                            severity=SeverityLevel.high,
                            url=target.url,
                            parameter=target.parameter,
                            method=target.method,
                            payload=val,
                            evidence=(
                                (
                                    "Cross-identity ownership assignment: a second authenticated "
                                    f"identity submitted '{target.parameter}'={val} and the server "
                                    "accepted an object carrying that reference. "
                                )
                                if is_create
                                else (
                                    "Horizontal IDOR confirmed with second-user credentials: "
                                    f"second user accessed low-user object reference "
                                    f"'{target.parameter}'={val}. "
                                )
                            )
                            + f"Unauthenticated baseline returned HTTP {unauth_own_resp.status_code}. "
                            + f"Body similarity (low vs second user): {similarity:.0%}.",
                            confidence_score=95.0,
                            detection_method="second_user_idor",
                            detection_evidence={
                                "parameter_location": target.location.value,
                                "source": target.source,
                                "shared_identifiers": sorted(self._shared_identifiers(own_profile, second_profile)),
                                "status_code": second_own_resp.status_code,
                                **self._reverification_request_evidence(own_request),
                            },
                            verified=True,
                            verification_request_snippet=second_own_resp.request_snippet,
                            verification_response_snippet=second_own_resp.response_snippet,
                            reproducible=True,
                        )
                    )
                    return cand_findings

        # A successful create after changing one body field proves only that the
        # application accepted a different input. It does not prove the referenced
        # object belongs to another principal, and it creates target-side state.
        # Create-style BOLA therefore requires the cross-identity proof above.
        if target.method.upper() == "POST":
            return cand_findings

        for mutated_val in mutated_vals:
            mod_request = self._build_request_for_value(target, mutated_val)
            auth_mod_resp = await self._send_prepared_request(
                authed_verifier, mod_request, test_phase="idor_authed_mod"
            )

            if auth_mod_resp.status_code not in (200, 201):
                continue
            if _looks_like_login_page(auth_mod_resp.body):
                continue

            unauth_mod_resp = await self._send_prepared_request(
                unauthed_verifier, mod_request, test_phase="idor_unauth_mod"
            )
            mutated_unauthed_body: str | None = (
                unauth_mod_resp.body
                if self._is_public_resource_response(unauth_mod_resp)
                else None
            )

            is_idor, similarity, reason = _differential_idor_verdict(
                own_body=auth_own_resp.body,
                mutated_authed_body=auth_mod_resp.body,
                mutated_unauthed_body=mutated_unauthed_body,
            )

            if not is_idor:
                logger.debug(
                    "IDOR false-positive suppressed at %s param=%s mutated=%s: %s",
                    target.url,
                    target.parameter,
                    mutated_val,
                    reason,
                )
                continue

            cand_findings.append(
                Finding(
                    category=OwaspCategory.a01,
                    vuln_type="Insecure Direct Object Reference (IDOR)",
                    severity=SeverityLevel.high,
                    url=target.url,
                    parameter=target.parameter,
                    method=target.method,
                    payload=mutated_val,
                    evidence=(
                        f"Horizontal privilege escalation: authenticated session accessed "
                        f"'{target.parameter}'={mutated_val} (modified from owned value '{val}'). "
                        f"Parameter location: {target.location.value}. "
                        f"Unauthenticated baseline for original value returned HTTP "
                        f"{unauth_own_resp.status_code}. "
                        f"Unauthenticated access to mutated value: "
                        f"{'blocked' if mutated_unauthed_body is None else 'public (skipped)'}. "
                        f"Body similarity (own vs mutated): {similarity:.0%}. "
                        f"Differential verdict: {reason}."
                    ),
                    confidence_score=90.0,
                    detection_method="differential_idor",
                    detection_evidence={
                        "parameter_location": target.location.value,
                        "parent_path": target.parent_path,
                        "source": target.source,
                        "status_code": auth_mod_resp.status_code,
                        **self._reverification_request_evidence(mod_request),
                    },
                    verified=True,
                    verification_request_snippet=auth_mod_resp.request_snippet,
                    verification_response_snippet=auth_mod_resp.response_snippet,
                    reproducible=True,
                )
            )
            break

        if privileged_verifier and not cand_findings:
            for mutated_val in mutated_vals:
                mod_request = self._build_request_for_value(target, mutated_val)
                priv_resp = await self._send_prepared_request(
                    privileged_verifier, mod_request, test_phase="vertical_priv_check"
                )
                auth_check_resp = await self._send_prepared_request(
                    authed_verifier, mod_request, test_phase="vertical_authed_check"
                )
                if (
                    priv_resp.status_code in (200, 201)
                    and auth_check_resp.status_code in (200, 201)
                    and not _looks_like_login_page(auth_check_resp.body)
                    and not _looks_like_error_page(auth_check_resp.body)
                ):
                    similarity = _body_similarity(priv_resp.body, auth_check_resp.body)
                    if similarity > 0.7:
                        cand_findings.append(
                            Finding(
                                category=OwaspCategory.a01,
                                vuln_type="Vertical Privilege Escalation (IDOR)",
                                severity=SeverityLevel.critical,
                                url=target.url,
                                parameter=target.parameter,
                                method=target.method,
                                payload=mutated_val,
                                evidence=(
                                    f"Low-privilege session accessed resource "
                                    f"'{target.parameter}'={mutated_val} which is also accessible to a "
                                    f"high-privilege session (body similarity: {similarity:.0%}). "
                                    f"Parameter location: {target.location.value}."
                                ),
                                confidence_score=90.0,
                                detection_method="vertical_idor",
                                detection_evidence={
                                    "parameter_location": target.location.value,
                                    "source": target.source,
                                    "status_code": auth_check_resp.status_code,
                                    **self._reverification_request_evidence(mod_request),
                                },
                                verified=True,
                                verification_request_snippet=auth_check_resp.request_snippet,
                                verification_response_snippet=auth_check_resp.response_snippet,
                                reproducible=True,
                            )
                        )
                        break

        return cand_findings
