import asyncio
import json
import re
import uuid
from typing import Any
from urllib.parse import urlparse
import logging

from app.core.crawler.models import RequestObservation
from app.core.detectors.attack_surface import PreparedAttackRequest
from app.core.detectors.base_detector import Finding
from app.core.verification.verification_framework import HttpVerifier
from shared.models.vulnerability import OwaspCategory, SeverityLevel

from app.core.detectors.access_control.common import (
    _looks_like_error_page,
)

logger = logging.getLogger("app.core.detectors.access_control")


class MassAssignmentMixin:
    _MASS_ASSIGNMENT_PROBES: tuple[tuple[str, Any], ...] = (
        ("role", "admin"),
        ("roles", ["admin"]),
        ("isAdmin", True),
        ("admin", True),
        ("is_admin", True),
        ("is_staff", True),
        ("permissions", ["admin"]),
    )

    # Entire-value email match (a bare address, not free text that mentions one).
    _BARE_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

    # Body keys whose values carry a uniqueness constraint on a create.
    _IDENTITY_KEY_TOKENS: tuple[str, ...] = ("email", "username", "user_name", "login")

    async def _check_mass_assignment(
        self,
        authed_verifier: HttpVerifier,
        **kwargs: object,
    ) -> list[Finding]:
        findings: list[Finding] = []
        requests = kwargs.get("requests") if isinstance(kwargs.get("requests"), list) else []
        candidates = self._build_mass_assignment_requests(requests)
        if not candidates:
            return findings

        semaphore = asyncio.Semaphore(self._CONCURRENCY)

        async def _verify(candidate: PreparedAttackRequest) -> list[Finding]:
            async with semaphore:
                try:
                    return await self._verify_mass_assignment_candidate(authed_verifier, candidate)
                except Exception:
                    logger.exception("mass-assignment check failed for %s", candidate.url)
                    return []

        results = await asyncio.gather(*[_verify(candidate) for candidate in candidates])
        for result in results:
            findings.extend(result)
        return findings

    def _build_mass_assignment_requests(self, requests: list[RequestObservation]) -> list[PreparedAttackRequest]:
        candidates: list[PreparedAttackRequest] = []
        seen: set[tuple[str, str, str]] = set()
        for observation in requests:
            prepared = self._request_from_observation(observation)
            if prepared is None or not self._is_mass_assignment_candidate(prepared):
                continue
            key = (
                prepared.method.upper(),
                self._canonical_request_url(prepared.url),
                self._body_schema_key(prepared.json_body or prepared.data),
            )
            if key in seen:
                continue
            seen.add(key)
            candidates.append(prepared)
        return candidates[:25]

    def _is_mass_assignment_candidate(self, request: PreparedAttackRequest) -> bool:
        if not self._is_replayable_matrix_request(request):
            return False
        method = request.method.upper()
        if method not in {"POST", "PUT", "PATCH"}:
            return False
        body = request.json_body if request.json_body is not None else request.data
        if not isinstance(body, dict) or not body:
            return False
        path = urlparse(request.url).path.lower()
        if any(token in path for token in ("login", "logout", "token", "password", "reset")):
            return False
        return any(token in path for token in ("user", "account", "profile", "register", "signup")) or any(
            token in str(key).lower() for key in body for token in ("email", "user", "account", "profile")
        )

    @classmethod
    def _freshen_unique_identity_fields(cls, body: dict[str, Any]) -> dict[str, Any]:
        """Return a shallow copy of a create-request body with uniqueness-
        constrained identity fields replaced by fresh unique values.

        Replaying a captured CREATE (e.g. user registration) verbatim collides
        with the record it originally created; the server rejects the duplicate
        identity (``email must be unique``) with a 4xx, which would abort
        replay-based checks before the real probe runs. Giving each replayed
        create a unique identity lets it succeed so the actual probe is
        evaluated. Framework-agnostic: identity fields are matched by common
        key tokens or a bare-email-shaped value, and each replacement keeps the
        observed shape (an email stays an email on its original domain).
        """
        if not isinstance(body, dict):
            return body
        fresh = dict(body)
        unique = uuid.uuid4().hex[:12]
        for key, value in list(fresh.items()):
            if not isinstance(value, str):
                continue
            lowered = str(key).lower()
            key_is_email = "email" in lowered
            value_is_email = bool(cls._BARE_EMAIL_RE.match(value))
            if key_is_email or value_is_email:
                domain = value.split("@", 1)[1] if value_is_email else "sentrystrike.test"
                fresh[key] = f"ss_ma_{unique}@{domain}"
            elif any(token in lowered for token in cls._IDENTITY_KEY_TOKENS):
                fresh[key] = f"ss_ma_{unique}"
        return fresh

    async def _verify_mass_assignment_candidate(
        self,
        verifier: HttpVerifier,
        request: PreparedAttackRequest,
    ) -> list[Finding]:
        body = request.json_body if request.json_body is not None else request.data
        if not isinstance(body, dict):
            return []

        # A replayed CREATE (registration/signup) collides with the record it
        # originally created — the server rejects the duplicate identity (e.g.
        # "email must be unique") with a 4xx. That aborts the check before the
        # privilege-field probe ever runs, producing a false negative. For POST
        # (create) requests, give each replayed body a fresh unique identity so
        # the create succeeds and the probe can be evaluated. UPDATE (PUT/PATCH)
        # replays keep the observed identity (updating a record to its own value
        # never collides).
        is_create = request.method.upper() == "POST"

        def _prepare_body(source: dict[str, Any]) -> dict[str, Any]:
            return self._freshen_unique_identity_fields(source) if is_create else dict(source)

        def _build(new_body: dict[str, Any]) -> PreparedAttackRequest:
            return PreparedAttackRequest(
                url=request.url,
                method=request.method,
                params=request.params,
                data=new_body if request.data is not None and request.json_body is None else None,
                json_body=new_body if request.json_body is not None else None,
                headers=request.headers,
                cookies=request.cookies,
            )

        baseline = await self._send_prepared_request(
            verifier, _build(_prepare_body(body)), test_phase="mass_assignment_baseline"
        )
        baseline_profile = self._response_profile(baseline)
        if not baseline_profile.success or _looks_like_error_page(baseline.body):
            return []

        for field, value in self._MASS_ASSIGNMENT_PROBES:
            if field in body:
                continue
            mutated_body = _prepare_body(body)
            mutated_body[field] = value
            mutated = _build(mutated_body)
            response = await self._send_prepared_request(
                verifier,
                mutated,
                test_phase="mass_assignment_probe",
            )
            if not (200 <= response.status_code < 300) or _looks_like_error_page(response.body):
                continue
            response_json = self._parse_json(response.body)
            confirmed = self._json_contains_assignment(response_json, field, value)
            response_profile = self._response_profile(response)
            shape_changed = bool(response_profile.json_shape - baseline_profile.json_shape)
            if not confirmed and not shape_changed:
                continue
            return [
                Finding(
                    category=OwaspCategory.a01,
                    vuln_type="Mass Assignment / Privilege Field Injection",
                    severity=SeverityLevel.high if confirmed else SeverityLevel.medium,
                    url=request.url,
                    parameter=field,
                    method=request.method,
                    payload=json.dumps({field: value}, separators=(",", ":"), default=str),
                    evidence=(
                        f"Authenticated request accepted an unexpected privilege-control field '{field}'. "
                        f"Baseline HTTP {baseline.status_code}; mutated HTTP {response.status_code}. "
                        f"Field reflected/accepted: {confirmed}."
                    ),
                    confidence_score=90.0 if confirmed else 65.0,
                    detection_method="mass_assignment_privilege_field",
                    detection_evidence={
                        "field": field,
                        "value": value,
                        "field_confirmed_in_response": confirmed,
                        "baseline_shape": sorted(baseline_profile.json_shape)[:20],
                        "mutated_shape": sorted(response_profile.json_shape)[:20],
                    },
                    verified=True,
                    verification_request_snippet=response.request_snippet,
                    verification_response_snippet=response.response_snippet,
                    reproducible=True,
                )
            ]
        return []

    def _json_contains_assignment(self, value: Any, field: str, expected: Any) -> bool:
        expected_norm = self._normalize_assignment_value(expected)
        field_lower = field.lower()

        def walk(child: Any) -> bool:
            if isinstance(child, dict):
                for key, val in child.items():
                    if str(key).lower() == field_lower and self._normalize_assignment_value(val) == expected_norm:
                        return True
                    if walk(val):
                        return True
            elif isinstance(child, list):
                return any(walk(item) for item in child[:10])
            return False

        return walk(value)

    @staticmethod
    def _normalize_assignment_value(value: Any) -> Any:
        if isinstance(value, list):
            return [AccessControlDetector._normalize_assignment_value(item) for item in value]
        if isinstance(value, dict):
            return {str(key).lower(): AccessControlDetector._normalize_assignment_value(val) for key, val in value.items()}
        if isinstance(value, str):
            return value.strip().lower()
        return value
