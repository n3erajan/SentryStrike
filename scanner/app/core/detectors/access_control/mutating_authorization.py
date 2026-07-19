import asyncio
from urllib.parse import urlparse, urlunparse
import logging

from app.config import get_settings
from app.core.detectors.attack_surface import PreparedAttackRequest
from app.core.detectors.base_detector import Finding
from app.core.verification.verification_framework import HttpVerifier
from shared.models.vulnerability import OwaspCategory, SeverityLevel

from app.core.detectors.access_control.common import (
    _MUTATING_AUTHZ_METHODS,
    _NUMERIC_RE,
    _UUID_RE,
    _LONG_HEX_RE,
    _looks_like_path_id_segment,
    _looks_like_login_page,
)

logger = logging.getLogger("app.core.detectors.access_control")


class MutatingAuthorizationMixin:
    async def _check_mutating_authorization(
        self,
        urls: list[str],
        forms: list[object],
        unauthed_verifier: HttpVerifier,
        authed_verifier: HttpVerifier,
        second_verifier: HttpVerifier | None,
        privileged_verifier: HttpVerifier | None,
        **kwargs: object,
    ) -> list[Finding]:
        settings = get_settings()
        if not getattr(settings, "access_control_probe_mutating_methods", True):
            return []
        targets = self._build_mutating_authz_targets(**kwargs)
        if not targets:
            return []
        allow_destructive = bool(getattr(settings, "allow_destructive_authz_confirmation", False))
        semaphore = asyncio.Semaphore(self._CONCURRENCY)

        async def _verify(entry: tuple[PreparedAttackRequest, PreparedAttackRequest | None]) -> list[Finding]:
            synth_req, real_req = entry
            async with semaphore:
                try:
                    return await self._verify_mutating_authz(
                        synth_req,
                        real_req if allow_destructive else None,
                        unauthed_verifier,
                        authed_verifier,
                        second_verifier,
                    )
                except Exception:
                    logger.exception("mutating-authz check failed for %s", synth_req.url)
                    return []

        results = await asyncio.gather(*[_verify(entry) for entry in targets])
        findings: list[Finding] = []
        for result in results:
            findings.extend(result)
        return findings

    def _build_mutating_authz_targets(
        self, **kwargs: object
    ) -> list[tuple[PreparedAttackRequest, PreparedAttackRequest | None]]:
        """Build (synthetic-id, real-id) request pairs for id-bearing mutating
        endpoints. ``synthetic`` is always safe to fire (non-existent id); ``real``
        is the original self-observed request (concrete id) used only for opt-in
        destructive confirmation, or ``None`` when the source was a template with
        no observed real id."""
        requests = kwargs.get("requests") if isinstance(kwargs.get("requests"), list) else []
        api_endpoints = kwargs.get("api_endpoints") if isinstance(kwargs.get("api_endpoints"), list) else []
        out: list[tuple[PreparedAttackRequest, PreparedAttackRequest | None]] = []
        seen: set[tuple[str, str]] = set()

        def _add(req: PreparedAttackRequest | None, real: PreparedAttackRequest | None) -> None:
            if req is None or req.method.upper() not in _MUTATING_AUTHZ_METHODS:
                return
            synth = self._request_with_synthetic_id(req)
            if synth is None:
                # No id-bearing path segment: not safe to fire (an id-less
                # destructive action like DELETE /account would hit the real
                # principal). Skipped in safe mode.
                return
            key = (synth.method.upper(), self._canonical_request_url(synth.url))
            if key in seen:
                return
            seen.add(key)
            out.append((synth, real))

        for observation in requests:
            req = self._request_from_observation(observation)
            if req is None or req.method.upper() not in _MUTATING_AUTHZ_METHODS:
                continue
            # The observed request already carries a concrete (self-owned) id, so
            # it doubles as the real-id request for destructive confirmation.
            real = req if self._request_with_synthetic_id(req) is not None else None
            _add(req, real)

        for endpoint in api_endpoints:
            req = self._request_from_endpoint(endpoint)
            _add(req, None)

        return out[:40]

    def _request_with_synthetic_id(self, request: PreparedAttackRequest) -> PreparedAttackRequest | None:
        """Return ``request`` with its last object-id path segment replaced by a
        synthetic value guaranteed not to exist, or ``None`` when the path has no
        id-bearing segment."""
        parsed = urlparse(request.url)
        segments = parsed.path.split("/")
        target_index: int | None = None
        for index in range(len(segments) - 1, -1, -1):
            if segments[index] and _looks_like_path_id_segment(segments[index]):
                target_index = index
                break
        if target_index is None:
            return None
        segments[target_index] = self._synthetic_nonexistent_id(segments[target_index])
        new_url = urlunparse(parsed._replace(path="/".join(segments)))
        return PreparedAttackRequest(
            url=new_url,
            method=request.method.upper(),
            params=request.params,
            data=request.data,
            json_body=request.json_body,
            headers=request.headers,
            cookies=request.cookies,
        )

    @staticmethod
    def _synthetic_nonexistent_id(original: str) -> str:
        """A deterministic, same-shape id that will not resolve to any record."""
        original = str(original)
        if _NUMERIC_RE.match(original):
            return "988000762197"  # far beyond any plausible sequential id
        if _UUID_RE.match(original):
            return "ffffffff-ffff-4fff-8fff-ffffffffffff"  # valid v4 shape, never assigned
        if _LONG_HEX_RE.match(original):
            return "f" * len(original)
        return "sentrystrike-nonexistent-000000"

    async def _verify_mutating_authz(
        self,
        synth_req: PreparedAttackRequest,
        real_req: PreparedAttackRequest | None,
        unauthed_verifier: HttpVerifier,
        authed_verifier: HttpVerifier,
        second_verifier: HttpVerifier | None,
    ) -> list[Finding]:
        _DENY = {401, 403}
        owner = await self._send_prepared_request(
            authed_verifier, synth_req, test_phase="mutating_authz_owner"
        )
        # Skip when even the authenticated owner is denied (creds insufficient for
        # this endpoint) or the method is simply unsupported (405/501) — no
        # reliable signal. A 404 for the OWNER is expected and fine: the object id
        # is synthetic, so the endpoint (which we observed/extracted as live) ran
        # the auth check, passed it, then failed the object lookup. That "auth
        # passed, object not found" 404 is exactly the owner baseline we compare
        # the unauthenticated principal against.
        if owner.status_code in _DENY or owner.status_code in (405, 501):
            return []

        unauth = await self._send_prepared_request(
            unauthed_verifier, synth_req, test_phase="mutating_authz_unauth"
        )
        # Missing authentication: the unauthenticated principal is treated the
        # same as the authenticated owner (both processed past the auth gate). A
        # protected endpoint returns 401/403 to unauth BEFORE object lookup.
        if unauth.status_code in _DENY or _looks_like_login_page(unauth.body):
            return []
        if unauth.status_code != owner.status_code:
            # Different handling for unauth vs owner (e.g. unauth 400 vs owner 204)
            # is ambiguous; require identical treatment for a high-confidence call.
            return []

        confirmed = False
        confirm_note = ""
        if real_req is not None:
            # Opt-in destructive confirmation (caller already gated on the flag):
            # fire the mutating method with a REAL self-observed id under the
            # unauthenticated context. A success proves an actual unauthorised
            # state change, not merely reachable business logic.
            real_unauth = await self._send_prepared_request(
                unauthed_verifier, real_req, test_phase="mutating_authz_confirm_unauth"
            )
            if real_unauth.status_code in (200, 201, 202, 204):
                confirmed = True
                confirm_note = (
                    f" Destructive confirmation: an unauthenticated {real_req.method} on the "
                    f"real object id returned HTTP {real_unauth.status_code} (state change performed)."
                )

        # The shared owner/unauth status only demonstrates missing authorization
        # when the mutating operation was actually PROCESSED. A matching non-success
        # status (404 not-found, 400 bad-request, 409 conflict, 5xx, ...) proves the
        # opposite: the mutation never ran, so no record changed and no auth signal
        # exists — a 404 for a synthetic id short-circuits at routing/object-lookup
        # and can occur whether or not the endpoint enforces auth. Identical 404s
        # therefore say nothing about authorization. Require either a processed
        # (2xx/3xx) shared status, or a destructive confirmation on a real id (which
        # directly observed an unauthenticated state change).
        if owner.status_code >= 400 and not confirmed:
            return []

        evidence = (
            f"Missing authentication on state-changing endpoint: an unauthenticated "
            f"{synth_req.method} to {synth_req.url} returned HTTP {unauth.status_code}, identical to "
            f"the authenticated owner's HTTP {owner.status_code} — the endpoint does not enforce "
            f"authentication for a mutating operation. Probed with a synthetic non-existent object id, "
            f"so no real record was modified." + confirm_note
        )
        return [
            Finding(
                category=OwaspCategory.a01,
                vuln_type="Missing Authorization on State-Changing Request",
                severity=SeverityLevel.critical if confirmed else SeverityLevel.high,
                url=synth_req.url,
                parameter="",
                method=synth_req.method,
                payload=self._synthetic_nonexistent_id(""),
                evidence=evidence,
                confidence_score=95.0 if confirmed else 80.0,
                detection_method="mutating_authz_differential",
                detection_evidence={
                    "unauth_status": unauth.status_code,
                    "owner_status": owner.status_code,
                    "destructive_confirmed": confirmed,
                },
                verified=True,
                verification_request_snippet=unauth.request_snippet,
                verification_response_snippet=unauth.response_snippet,
                reproducible=True,
            )
        ]
