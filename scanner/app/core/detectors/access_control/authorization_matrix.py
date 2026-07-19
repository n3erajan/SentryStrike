import asyncio
from typing import Any
import logging

from app.core.detectors.base_detector import Finding
from app.core.verification.verification_framework import HttpVerifier
from shared.models.vulnerability import OwaspCategory, SeverityLevel

from app.core.detectors.access_control.common import (
    _MatrixTarget,
    _ResponseProfile,
    _is_valid_id_value,
    _looks_like_login_page,
    _looks_like_error_page,
    _body_similarity,
)

logger = logging.getLogger("app.core.detectors.access_control")


class AuthorizationMatrixMixin:
    async def _check_api_authorization_matrix(
        self,
        urls: list[str],
        forms: list[object],
        unauthed_verifier: HttpVerifier,
        authed_verifier: HttpVerifier,
        second_verifier: HttpVerifier | None,
        privileged_verifier: HttpVerifier | None,
        **kwargs: object,
    ) -> list[Finding]:
        findings: list[Finding] = []
        targets = self._build_matrix_targets(urls, forms, **kwargs)
        if not targets:
            return findings

        semaphore = asyncio.Semaphore(self._CONCURRENCY)

        async def _verify(target: _MatrixTarget) -> list[Finding]:
            async with semaphore:
                try:
                    return await self._verify_matrix_target(
                        target,
                        unauthed_verifier,
                        authed_verifier,
                        second_verifier,
                        privileged_verifier,
                    )
                except Exception:
                    logger.exception("authorization matrix failed for %s", target.request.url)
                    return []

        results = await asyncio.gather(*[_verify(target) for target in targets])
        for result in results:
            findings.extend(result)
        return findings

    async def _verify_matrix_target(
        self,
        target: _MatrixTarget,
        unauthed_verifier: HttpVerifier,
        authed_verifier: HttpVerifier,
        second_verifier: HttpVerifier | None,
        privileged_verifier: HttpVerifier | None,
    ) -> list[Finding]:
        request = target.request
        unauth = await self._send_prepared_request(
            unauthed_verifier, request, test_phase="auth_matrix_unauth"
        )
        low = await self._send_prepared_request(
            authed_verifier, request, test_phase="auth_matrix_low"
        )
        second = (
            await self._send_prepared_request(
                second_verifier, request, test_phase="auth_matrix_second"
            )
            if second_verifier
            else None
        )
        privileged = (
            await self._send_prepared_request(
                privileged_verifier, request, test_phase="auth_matrix_privileged"
            )
            if privileged_verifier
            else None
        )

        unauth_profile = self._response_profile(unauth)
        low_profile = self._response_profile(low)
        second_profile = self._response_profile(second) if second is not None else None
        privileged_profile = self._response_profile(privileged) if privileged is not None else None

        findings: list[Finding] = []
        protected_low = low_profile.success and not _looks_like_login_page(low.body)
        unauth_success = unauth_profile.success and not _looks_like_login_page(unauth.body)
        unauth_sensitive = self._profile_exposes_nonpublic_data(target, unauth_profile)
        # An endpoint that authenticates via credentials carried in the REQUEST
        # body (login / token / authenticate) is doing its designed job when it
        # returns 200 with a session token — stripping ambient session state does
        # not make the call "unauthenticated", because the body itself carries the
        # credential. Framework-agnostic: never treat such a response as an
        # unauthorized data leak.
        is_auth_endpoint = self._request_carries_credentials(request)

        # PUBLIC-ENDPOINT SUPPRESSION (framework-agnostic).
        # An endpoint that returns a response structurally identical to what an
        # authenticated identity receives is *public by design*: identity does
        # not change the result, so there is no authorization boundary being
        # bypassed (product catalogues, language lists, public config, captcha,
        # feedback walls, …). This is the single largest source of noise — a bare
        # 200 JSON collection is not, on its own, a data leak. Only genuine secret
        # material in the anonymous body overrides this, because such values must
        # never be world-readable regardless of the endpoint's intended audience.
        serves_secret = bool(unauth_profile.secret_fields)
        authed_states = [
            (profile, body)
            for profile, body in (
                (low_profile, low.body),
                (second_profile, second.body if second is not None else ""),
                (privileged_profile, privileged.body if privileged is not None else ""),
            )
            if profile is not None and profile.success
        ]
        serves_public_data = not serves_secret and any(
            self._profiles_compatible(unauth_profile, profile, unauth.body, body)
            for profile, body in authed_states
        )

        if (
            unauth_success
            and unauth_sensitive
            and not is_auth_endpoint
            and not serves_public_data
            and not _looks_like_error_page(unauth.body)
        ):
            findings.append(
                Finding(
                    category=OwaspCategory.a01,
                    vuln_type="Unauthenticated API Data Exposure",
                    severity=SeverityLevel.high if unauth_profile.secret_fields else SeverityLevel.medium,
                    url=request.url,
                    parameter=target.parameter,
                    method=request.method,
                    evidence=(
                        f"API authorization matrix: unauthenticated request returned HTTP "
                        f"{unauth.status_code} with sensitive/object data. "
                        f"Low-privilege baseline returned HTTP {low.status_code}. "
                        f"Sensitive fields: {', '.join(sorted(unauth_profile.sensitive_fields)) or 'none'}. "
                        f"Stable identifiers observed: {len(unauth_profile.identifiers)}."
                    ),
                    confidence_score=88.0,
                    detection_method="authorization_matrix",
                    detection_evidence=self._matrix_evidence(
                        unauth_profile, low_profile, second_profile, privileged_profile, target,
                        serves_public_data=serves_public_data,
                    ),
                    verified=True,
                    verification_request_snippet=unauth.request_snippet,
                    verification_response_snippet=unauth.response_snippet,
                    reproducible=True,
                )
            )

        if (
            second is not None
            and second_profile is not None
            and protected_low
            and second_profile.success
            and not unauth_success
            and not target.has_object_reference
            and self._shared_identifiers(low_profile, second_profile)
            and (bool(low_profile.sensitive_fields) or target.admin_like)
        ):
            findings.append(
                Finding(
                    category=OwaspCategory.a01,
                    vuln_type="Horizontal Authorization Bypass",
                    severity=SeverityLevel.high,
                    url=request.url,
                    parameter=target.parameter,
                    method=request.method,
                    evidence=(
                        "API authorization matrix: a second authenticated user received "
                        "the same stable object identifiers as the low-privilege baseline "
                        f"while unauthenticated access was blocked with HTTP {unauth.status_code}."
                    ),
                    confidence_score=90.0,
                    detection_method="authorization_matrix_second_user",
                    detection_evidence=self._matrix_evidence(
                        unauth_profile, low_profile, second_profile, privileged_profile, target
                    ),
                    verified=True,
                    verification_request_snippet=second.request_snippet,
                    verification_response_snippet=second.response_snippet,
                    reproducible=True,
                )
            )

        if (
            privileged is not None
            and privileged_profile is not None
            and protected_low
            and privileged_profile.success
            and target.admin_like
            and self._profiles_compatible(low_profile, privileged_profile, low.body, privileged.body)
        ):
            findings.append(
                Finding(
                    category=OwaspCategory.a01,
                    vuln_type="Vertical Privilege Bypass",
                    severity=SeverityLevel.critical,
                    url=request.url,
                    parameter=target.parameter,
                    method=request.method,
                    evidence=(
                        "API authorization matrix: low-privilege credentials reached an "
                        "admin/privileged API target with a response compatible with the "
                        f"privileged baseline (low HTTP {low.status_code}, privileged HTTP "
                        f"{privileged.status_code})."
                    ),
                    confidence_score=92.0,
                    detection_method="authorization_matrix_privileged_baseline",
                    detection_evidence=self._matrix_evidence(
                        unauth_profile, low_profile, second_profile, privileged_profile, target
                    ),
                    verified=True,
                    verification_request_snippet=low.request_snippet,
                    verification_response_snippet=low.response_snippet,
                    reproducible=True,
                )
            )

        # BROKEN OBJECT-LEVEL AUTHORIZATION (cross-identity, framework-agnostic).
        # An object-scoped request (an id names ONE record) that is denied to
        # anonymous callers (401/403/login/redirect) but returns the SAME record
        # to two DISTINCT authenticated identities is not scoped to its owner:
        # any authenticated user can read another user's object. The id-mutation
        # path deliberately drops this — identical values across identities look
        # like a "generic template" under its val_sim==1.0 short-circuit — so the
        # matrix consumes {unauth, low, second} directly, regardless of val_sim.
        # The "same record to both" signal is value-level (shared stable object
        # identifiers), so genuine per-owner objects (different ids per identity)
        # do not fire. Complements the horizontal check above, which handles the
        # non-object-scoped (list/collection) case.
        unauth_denied = (
            unauth_profile.status_code in (401, 403)
            or 300 <= unauth_profile.status_code < 400
            or _looks_like_login_page(unauth.body)
        )
        if (
            second is not None
            and second_profile is not None
            and second_profile.success
            and protected_low
            and target.has_object_reference
            and unauth_denied
            and not is_auth_endpoint
            and not _looks_like_error_page(low.body)
            and self._profile_has_sensitive_data(low_profile)
            and bool(self._shared_identifiers(low_profile, second_profile))
        ):
            shared = sorted(self._shared_identifiers(low_profile, second_profile))
            findings.append(
                Finding(
                    category=OwaspCategory.a01,
                    vuln_type="Broken Object-Level Authorization",
                    severity=SeverityLevel.high,
                    url=request.url,
                    parameter=target.parameter,
                    method=request.method,
                    evidence=(
                        "API authorization matrix: an object-scoped resource denied to "
                        f"anonymous callers (HTTP {unauth.status_code}) returned the same "
                        "object identifiers to two distinct authenticated identities "
                        f"(low HTTP {low.status_code}, second HTTP {second.status_code}). "
                        f"Shared identifiers: {', '.join(shared) or 'none'}. "
                        f"Sensitive fields: {', '.join(sorted(low_profile.sensitive_fields)) or 'none'}."
                    ),
                    confidence_score=85.0,
                    detection_method="authorization_matrix_cross_identity",
                    detection_evidence=self._matrix_evidence(
                        unauth_profile, low_profile, second_profile, privileged_profile, target
                    ),
                    verified=True,
                    verification_request_snippet=low.request_snippet,
                    verification_response_snippet=low.response_snippet,
                    reproducible=True,
                )
            )

        return findings

    def _response_profile(self, response) -> _ResponseProfile:
        if response is None:
            return _ResponseProfile(0, "", False, False)
        content_type = str((response.headers or {}).get("content-type", "")).lower()
        parsed = self._parse_json(response.body)
        is_json = isinstance(parsed, (dict, list)) or "json" in content_type
        json_shape: set[str] = set()
        identifiers: set[str] = set()
        sensitive_fields: set[str] = set()
        secret_fields: set[str] = set()
        item_count = 0

        def walk(value: Any, path: str = "") -> None:
            nonlocal item_count
            if isinstance(value, dict):
                for key, child in value.items():
                    child_path = f"{path}.{key}" if path else key
                    json_shape.add(child_path)
                    lowered = key.lower()
                    if self._is_sensitive_field(lowered):
                        sensitive_fields.add(child_path)
                    if self._is_secret_field(lowered):
                        secret_fields.add(child_path)
                    if self._is_idor_param(key) and isinstance(child, (str, int)):
                        child_value = str(child)
                        if _is_valid_id_value(child_value):
                            identifiers.add(f"{self._normalize_param_name(key)}={child_value}")
                    walk(child, child_path)
            elif isinstance(value, list):
                item_count = max(item_count, len(value))
                for child in value[:10]:
                    walk(child, path + "[]")

        if parsed is not None:
            walk(parsed)

        return _ResponseProfile(
            status_code=response.status_code,
            content_type=content_type,
            success=response.status_code in (200, 201, 202, 206),
            is_json=is_json,
            json_shape=frozenset(json_shape),
            identifiers=frozenset(identifiers),
            sensitive_fields=frozenset(sensitive_fields),
            secret_fields=frozenset(secret_fields),
            item_count=item_count,
            body_length=len(response.body or ""),
        )

    def _matrix_evidence(
        self,
        unauth: _ResponseProfile,
        low: _ResponseProfile,
        second: _ResponseProfile | None,
        privileged: _ResponseProfile | None,
        target: _MatrixTarget,
        *,
        serves_public_data: bool | None = None,
    ) -> dict[str, Any]:
        return {
            "source": target.source,
            "parameter_location": target.parameter_location,
            "has_object_reference": target.has_object_reference,
            "admin_like": target.admin_like,
            # The key discriminative signal for the AI: whether anonymous and
            # authenticated responses are identical (public by design). When
            # True, the endpoint has no authorization boundary — the AI should
            # flag it as a false positive.
            "serves_public_data": serves_public_data,
            "states": {
                "unauthenticated": self._profile_summary(unauth),
                "low": self._profile_summary(low),
                "second": self._profile_summary(second) if second else None,
                "privileged": self._profile_summary(privileged) if privileged else None,
            },
        }

    @staticmethod
    def _profile_summary(profile: _ResponseProfile) -> dict[str, Any]:
        return {
            "status_code": profile.status_code,
            "success": profile.success,
            "is_json": profile.is_json,
            "json_shape": sorted(profile.json_shape)[:20],
            "identifiers": sorted(profile.identifiers)[:20],
            "sensitive_fields": sorted(profile.sensitive_fields)[:20],
            "secret_fields": sorted(profile.secret_fields)[:20],
            "item_count": profile.item_count,
        }

    def _profiles_compatible(
        self,
        left: _ResponseProfile,
        right: _ResponseProfile,
        left_body: str,
        right_body: str,
    ) -> bool:
        if not left.success or not right.success:
            return False
        if left.is_json and right.is_json:
            if left.json_shape and right.json_shape:
                overlap = len(left.json_shape & right.json_shape)
                smaller = max(1, min(len(left.json_shape), len(right.json_shape)))
                if overlap / smaller >= 0.70:
                    return True
            if self._shared_identifiers(left, right):
                return True
        return _body_similarity(left_body or "", right_body or "") > 0.85

    @staticmethod
    def _shared_identifiers(left: _ResponseProfile, right: _ResponseProfile) -> set[str]:
        return set(left.identifiers & right.identifiers)

    @staticmethod
    def _profile_has_sensitive_data(profile: _ResponseProfile) -> bool:
        return bool(profile.sensitive_fields or profile.identifiers or profile.item_count > 0)

    @staticmethod
    def _profile_exposes_nonpublic_data(target: _MatrixTarget, profile: _ResponseProfile) -> bool:
        # Non-public exposure must be evidenced by the anonymous response BODY
        # carrying data that is not meant to be world-readable. Two structural,
        # framework-agnostic signals qualify:
        #   1. Secret material — passwords, tokens, API keys, crypto seeds, etc.
        #      A secret in an anonymous response is a leak regardless of design.
        #   2. Object-scoped data — the request targets a specific object (id in
        #      path/query/body) and the response returns that record. Whether it
        #      is truly a leak is then decided by the public-endpoint suppression
        #      in ``_verify_matrix_target`` (a public detail page is identical
        #      across auth states and is dropped there).
        # A bare public collection (a product/feedback/language list with no
        # secret fields and no object scoping) is NOT, on its own, evidence of a
        # leak — such listings are public on the overwhelming majority of sites.
        # An admin-looking URL is likewise not evidence: a public
        # ``{"version": "x.y.z"}`` under ``/admin/*`` is not a data leak.
        if profile.secret_fields:
            return True
        if target.has_object_reference and (profile.identifiers or profile.item_count > 0):
            return True
        return False

    @staticmethod
    def _is_sensitive_field(name: str) -> bool:
        return any(
            token in name
            for token in (
                "email",
                "username",
                "password",
                "passwd",
                "token",
                "secret",
                "role",
                "permission",
                "address",
                "phone",
                "balance",
                "credit",
                "card",
                "ssn",
                "jwt",
                "api_key",
                "apikey",
            )
        )

    # Narrow secret-material tokens. Deliberately excludes broad PII names
    # (email/username/role/address/phone) that legitimately appear in public
    # listings: those are not, by themselves, a secret disclosure. A field whose
    # name carries one of these tokens holds a credential, key, or crypto seed
    # whose presence in an anonymous response is an unambiguous leak.
    _SECRET_FIELD_TOKENS: tuple[str, ...] = (
        "password",
        "passwd",
        "passwrd",
        "pwd",
        "secret",
        "token",
        "apikey",
        "api_key",
        "accesskey",
        "access_key",
        "privatekey",
        "private_key",
        "jwt",
        "ssn",
        "cvv",
        "seed",
        "mnemonic",
        "passphrase",
        "otp",
        "totp",
    )

    @classmethod
    def _is_secret_field(cls, name: str) -> bool:
        return any(token in name for token in cls._SECRET_FIELD_TOKENS)
