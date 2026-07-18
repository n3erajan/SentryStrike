import secrets

from app.core.detectors.base_detector import Finding
from shared.models.vulnerability import SeverityLevel


class ActiveJwtForgeryMixin:
    async def _active_jwt_forgery_findings(
        self,
        kwargs: dict[str, object],
        session_cookies: dict,
    ) -> list[Finding]:
        """Actively forge the scanner's own JWT and flag only if the forgery is accepted.

        Upgrades passive ``alg=none``/signature notes to a VERIFIED finding: a forged
        token accepted by an endpoint that distinguishes authenticated from anonymous
        access proves signature verification is broken. The oracle differential is
        measured by status code OR response body (identity claim reflection), and the
        forged token is replayed in the SAME carrier (Authorization header or cookie)
        the application actually reads — so the check works for header- and cookie-
        based JWT auth alike. Idempotent GET only; runs solely when an observed
        JWT-carrying GET oracle exists, so it adds near-zero cost otherwise. Session
        cookies are excluded so acceptance is attributable to the forged token alone.
        """
        candidates = self._forgery_oracle_candidates(kwargs)
        if not candidates:
            return []

        from app.core.verification.verification_framework import HttpVerifier

        verifier = HttpVerifier()  # no session cookies: the presented token is the only auth factor
        try:
            for candidate in candidates:
                url = candidate["url"]
                oracle = await self._establish_forgery_oracle(verifier, url, candidate["carriers"])
                if oracle is None:
                    continue

                carrier = oracle["carrier"]
                header, payload = self._decode_jwt(oracle["base_token"])

                # (label, token, canary) — canary None means unchanged payload.
                forged: list[tuple[str, str, str | None]] = [
                    (label, token, None) for label, token in self._forge_alg_none(header, payload)
                ]
                canary = "sentryjwt" + secrets.token_hex(6)
                canary_payload = self._inject_canary(payload, canary)
                if canary_payload is not None:
                    forged.append(("alg=none (identity-forged)", self._unsigned_token(header, canary_payload), canary))
                if str(header.get("alg", "")).upper().startswith(("RS", "ES", "PS")):
                    for pem in await self._fetch_jwks_pems(kwargs, verifier):
                        confused = self._forge_key_confusion(header, payload, pem)
                        if confused:
                            forged.append(("algorithm confusion (RS→HS256)", confused, None))

                for label, token, tok_canary in forged:
                    resp = await self._send_via_carrier(verifier, url, token, carrier, phase="jwt_forgery_attempt")
                    proof = self._judge_forgery(resp, oracle, tok_canary)
                    if proof is None:
                        continue

                    is_none = label.startswith("alg=")
                    carrier_desc = (
                        f"cookie '{carrier['name']}'" if carrier["loc"] == "cookie"
                        else f"'{carrier['name']}' header"
                    )
                    if proof["mode"] == "identity-injection":
                        proof_text = (
                            "the forged token's attacker-chosen identity claim was reflected in the "
                            f"response (marker '{self._mask_marker(proof['markers'][0])}'), proving arbitrary "
                            "identity/role forgery"
                        )
                    elif proof["mode"] == "identity-reflection":
                        proof_text = (
                            "the forged token reproduced the authenticated identity in the response "
                            f"(marker {self._mask_marker(proof['markers'][0])}) that the anonymous baseline did not"
                        )
                    else:
                        proof_text = (
                            f"the no-auth baseline was denied {oracle['noauth_status']} and the forged token "
                            f"returned {proof['status']}"
                        )
                    return [
                        self._finding(
                            vuln_type=(
                                "JWT alg=none Forgery Accepted" if is_none
                                else "JWT Algorithm-Confusion Forgery Accepted"
                            ),
                            url=url,
                            severity=SeverityLevel.critical,
                            evidence=(
                                f"A forged JWT ({label}) built from the scanner's own token, presented via the "
                                f"{carrier_desc}, was accepted by an authentication-gated endpoint: {proof_text}. "
                                "Signature verification is not enforced — any user or role can be impersonated."
                            ),
                            verified=True,
                            detection_method="jwt_active_forgery",
                            confidence_score=95.0,
                            verification_request_snippet=getattr(resp, "request_snippet", None),
                            verification_response_snippet=getattr(resp, "response_snippet", None),
                            detection_evidence={
                                "forgery": label,
                                "proof_mode": proof["mode"],
                                "carrier": f"{carrier['loc']}:{carrier['name']}",
                                "oracle_url": url,
                                "real_status": oracle["real_status"],
                                "noauth_status": oracle["noauth_status"],
                                "forged_status": proof["status"],
                            },
                        )
                    ]
            return []
        finally:
            await verifier.close()
