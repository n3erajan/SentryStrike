import asyncio
import base64
import json
import re
from typing import Any
from urllib.parse import urlparse
import logging

from app.config import get_settings
from app.core.crawler.spa import SpaFallbackDetector
from app.core.detectors.attack_surface import PreparedAttackRequest
from app.core.detectors.base_detector import Finding
from app.core.verification.verification_framework import HttpVerifier

from app.core.detectors.access_control.common import (
    _AuthMaterial,
    _looks_like_login_page,
    _looks_like_error_page,
)

logger = logging.getLogger("app.core.detectors.access_control")


class RuntimeMixin:
    _CREDENTIAL_BODY_KEYS = frozenset(
        {"password", "passwd", "pass", "pwd", "otp", "totp", "credential", "credentials"}
    )

    async def detect(
        self, urls: list[str], forms: list[object], **kwargs: object
    ) -> list[Finding]:
        findings: list[Finding] = []
        self._scan_config = kwargs.get("scan_config")
        settings = get_settings()
        session_cookies: dict[str, str] = dict(kwargs.get("session_cookies") or {})
        auth_headers: dict[str, str] = dict(kwargs.get("auth_headers") or {})
        # Auth material is provided per-scan via kwargs (sessions minted from the
        # submitted low/second/privileged accounts). There is no env fallback:
        # without submitted accounts these stay empty and the cross-identity
        # checks that need them are simply skipped.
        low_auth = _AuthMaterial(
            label="low",
            cookies=session_cookies,
            headers=auth_headers,
        )
        second_auth = self._build_auth_material(
            label="second",
            cookie_value=kwargs.get("second_user_cookies"),
            header_value=kwargs.get("second_user_headers"),
        )
        privileged_auth = self._build_auth_material(
            label="privileged",
            cookie_value=kwargs.get("privileged_cookies"),
            header_value=kwargs.get("privileged_headers"),
        )
        if second_auth.configured and self._auth_materials_same_identity(low_auth, second_auth):
            logger.warning(
                "second-user auth material resolves to the low-user principal; "
                "cross-identity checks are disabled"
            )
            second_auth = _AuthMaterial(label="second")
        if privileged_auth.configured and self._auth_materials_same_identity(low_auth, privileged_auth):
            logger.warning(
                "privileged auth material resolves to the low-user principal; "
                "cross-role checks are disabled"
            )
            privileged_auth = _AuthMaterial(label="privileged")
        is_spa = bool(kwargs.get("is_spa", False))
        spa_root_html = str(kwargs.get("spa_root_html") or "")
        root_url = str(kwargs.get("root_url") or "")

        spa_detector: SpaFallbackDetector | None = None
        if is_spa and spa_root_html:
            spa_detector = SpaFallbackDetector()
            spa_detector.configure_root(root_url, spa_root_html)
            if not spa_detector.root_looks_like_spa():
                spa_detector = None

        authed_verifier = HttpVerifier(cookies=low_auth.cookies, headers=low_auth.headers)
        authed_verifier.set_request_context(module="access_control")

        unauthed_verifier = HttpVerifier()
        unauthed_verifier.set_request_context(module="access_control")

        privileged_verifier: HttpVerifier | None = None
        if privileged_auth.configured:
            privileged_verifier = HttpVerifier(cookies=privileged_auth.cookies, headers=privileged_auth.headers)
            privileged_verifier.set_request_context(module="access_control")

        second_verifier: HttpVerifier | None = None
        if second_auth.configured:
            second_verifier = HttpVerifier(cookies=second_auth.cookies, headers=second_auth.headers)
            second_verifier.set_request_context(module="access_control")

        try:
            forced_browsing_task = self._check_forced_browsing(
                urls, unauthed_verifier, authed_verifier, spa_detector=spa_detector
            )
            idor_task = self._check_idor(
                urls,
                forms,
                unauthed_verifier,
                authed_verifier,
                privileged_verifier,
                second_verifier,
                **kwargs,
            )
            matrix_task = self._check_api_authorization_matrix(
                urls,
                forms,
                unauthed_verifier,
                authed_verifier,
                second_verifier,
                privileged_verifier,
                **kwargs,
            )
            mass_assignment_task = self._check_mass_assignment(
                authed_verifier,
                **kwargs,
            )
            mutating_authz_task = self._check_mutating_authorization(
                urls,
                forms,
                unauthed_verifier,
                authed_verifier,
                second_verifier,
                privileged_verifier,
                **kwargs,
            )
            (
                fb_findings,
                idor_findings,
                matrix_findings,
                mass_assignment_findings,
                mutating_authz_findings,
            ) = await asyncio.gather(
                forced_browsing_task,
                idor_task,
                matrix_task,
                mass_assignment_task,
                mutating_authz_task,
            )
            findings.extend(fb_findings)
            findings.extend(idor_findings)
            findings.extend(matrix_findings)
            findings.extend(mass_assignment_findings)
            findings.extend(mutating_authz_findings)
        finally:
            await authed_verifier.close()
            await unauthed_verifier.close()
            if privileged_verifier:
                await privileged_verifier.close()
            if second_verifier:
                await second_verifier.close()

        return findings

    def _build_auth_material(
        self,
        *,
        label: str,
        cookie_value: object,
        header_value: object,
    ) -> _AuthMaterial:
        return _AuthMaterial(
            label=label,
            cookies=self._parse_cookie_string(cookie_value),
            headers=self._parse_header_string(header_value),
        )

    @classmethod
    def _auth_materials_same_identity(
        cls,
        left: _AuthMaterial,
        right: _AuthMaterial,
    ) -> bool:
        """Return True when two credential sets identify the same principal.

        Opaque sessions are compared directly. JWT-like values are decoded only
        to compare stable identity claims; their signatures are not trusted here.
        This works independently of the target framework and auth carrier.
        """
        if not left.configured or not right.configured:
            return False

        left_claims = cls._identity_claims_from_auth_material(left)
        right_claims = cls._identity_claims_from_auth_material(right)
        for key in (
            "sub",
            "userid",
            "uid",
            "accountid",
            "customerid",
            "id",
            "email",
            "username",
        ):
            if key in left_claims and key in right_claims:
                return bool(left_claims[key] & right_claims[key])

        left_opaque = cls._opaque_identity_credentials(left)
        right_opaque = cls._opaque_identity_credentials(right)
        for key in left_opaque.keys() & right_opaque.keys():
            if left_opaque[key] & right_opaque[key]:
                return True

        return cls._canonical_auth_material(left) == cls._canonical_auth_material(right)

    @classmethod
    def _identity_claims_from_auth_material(
        cls,
        material: _AuthMaterial,
    ) -> dict[str, set[str]]:
        claims: dict[str, set[str]] = {}

        for raw_value in [*material.headers.values(), *material.cookies.values()]:
            token = str(raw_value or "").strip().strip('"').strip("'")
            if token.lower().startswith("bearer "):
                token = token[7:].strip()
            parts = token.split(".")
            if len(parts) != 3:
                continue
            try:
                payload_segment = parts[1] + "=" * (-len(parts[1]) % 4)
                payload = json.loads(
                    base64.urlsafe_b64decode(payload_segment.encode("ascii")).decode("utf-8")
                )
            except Exception:
                continue

            def walk(value: Any, path: tuple[str, ...] = ()) -> None:
                if isinstance(value, dict):
                    for key, child in value.items():
                        normalized_key = re.sub(r"[^a-z0-9]", "", str(key).lower())
                        is_identity_id = normalized_key == "id" and (
                            not path
                            or path[-1]
                            in {"data", "user", "account", "identity", "principal", "profile", "claims"}
                        )
                        if (
                            normalized_key
                            in {"sub", "userid", "uid", "accountid", "customerid", "email", "username"}
                            or is_identity_id
                        ) and isinstance(child, (str, int)) and str(child).strip():
                            claims.setdefault(normalized_key, set()).add(str(child).strip())
                        walk(child, (*path, normalized_key))
                elif isinstance(value, list):
                    for child in value[:10]:
                        walk(child, path)

            walk(payload)

        return claims

    @staticmethod
    def _opaque_identity_credentials(material: _AuthMaterial) -> dict[str, set[str]]:
        credentials: dict[str, set[str]] = {}
        for carrier, values in (("header", material.headers), ("cookie", material.cookies)):
            for key, value in values.items():
                normalized_key = re.sub(r"[^a-z0-9]", "", str(key).lower())
                if any(marker in normalized_key for marker in ("csrf", "xsrf", "nonce")):
                    continue
                if not any(
                    marker in normalized_key
                    for marker in ("authorization", "session", "token", "jwt", "sid")
                ):
                    continue
                credential = str(value or "").strip()
                if credential:
                    credentials.setdefault(f"{carrier}:{normalized_key}", set()).add(credential)
        return credentials

    @staticmethod
    def _canonical_auth_material(material: _AuthMaterial) -> tuple[tuple[str, str, str], ...]:
        entries = [
            ("header", str(key).lower(), str(value))
            for key, value in material.headers.items()
        ]
        entries.extend(
            ("cookie", str(key).lower(), str(value))
            for key, value in material.cookies.items()
        )
        return tuple(sorted(entries))

    @staticmethod
    def _parse_cookie_string(value: object) -> dict[str, str]:
        if isinstance(value, dict):
            return {str(k): str(v) for k, v in value.items()}
        if not isinstance(value, str):
            return {}
        cookies: dict[str, str] = {}
        for cookie in value.split(";"):
            cookie = cookie.strip()
            if "=" in cookie:
                key, val = cookie.split("=", 1)
                cookies[key.strip()] = val.strip()
        return cookies

    @staticmethod
    def _parse_header_string(value: object) -> dict[str, str]:
        if isinstance(value, dict):
            return {str(k): str(v) for k, v in value.items()}
        if not isinstance(value, str) or ":" not in value:
            return {}
        key, val = value.split(":", 1)
        return {key.strip(): val.strip()} if key.strip() and val.strip() else {}

    @staticmethod
    def _parse_json(value: Any) -> Any:
        if isinstance(value, (dict, list)):
            return value
        if not isinstance(value, str) or not value.strip():
            return None
        try:
            return json.loads(value)
        except Exception:
            return None

    def _is_idor_param(self, name: str) -> bool:
        """Return True if *name* looks like an object-reference parameter."""
        if not name:
            return False
        raw = str(name).strip()
        lower = raw.lower()
        if lower in self.idor_param_tokens:
            return True
        if re.search(r"(?:^|[_\-.])(?:id|uuid)$", lower):
            return True
        return bool(re.search(r"(?:Id|ID|Uuid|UUID)$", raw))

    @staticmethod
    def _normalize_param_name(name: str) -> str:
        return re.sub(r"[^a-z0-9]", "", name.lower())

    def _is_matrix_relevant_param(self, name: str) -> bool:
        return self._is_idor_param(name) or any(
            token in name.lower()
            for token in ("role", "admin", "tenant", "org", "owner", "account", "user")
        )

    def _is_public_resource_response(self, response) -> bool:
        return (
            response.status_code == 200
            and not _looks_like_login_page(response.body)
            and not _looks_like_error_page(response.body)
        )

    def _is_admin_like_url(self, url: str) -> bool:
        path = urlparse(url).path
        # Dotfile / VCS-metadata paths are file exposure (A02), not gated
        # functionality — never "admin-like". Excluding them keeps this ranking
        # signal aligned with the forced-browsing scope and avoids the
        # ``.git/config`` → ``config`` token collision.
        if any(seg.startswith(".") for seg in path.split("/") if seg):
            return False
        lowered = path.lower()
        return any(token in lowered for token in self.sensitive_path_tokens)

    def _request_carries_credentials(self, request: PreparedAttackRequest) -> bool:
        """True when the request itself carries login credentials in its body.

        Such an endpoint (login / authenticate / token / sign-in) is *meant* to
        accept anonymous callers and return a session token, so a 200 under the
        unauthenticated verifier is expected behaviour — not an authorization
        bypass. Detection is structural (a password-like body key), so it holds
        for any framework, not just a specific app's ``/login`` path.
        """
        body = request.json_body if request.json_body is not None else request.data
        return self._body_has_credential_key(body)

    def _body_has_credential_key(self, value: Any) -> bool:
        if isinstance(value, dict):
            for key, child in value.items():
                if str(key).strip().lower() in self._CREDENTIAL_BODY_KEYS:
                    return True
                if self._body_has_credential_key(child):
                    return True
            return False
        if isinstance(value, list):
            return any(self._body_has_credential_key(child) for child in value[:5])
        return False
