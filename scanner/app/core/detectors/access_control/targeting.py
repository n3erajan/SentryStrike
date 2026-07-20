import re
from typing import Any
from urllib.parse import parse_qsl, unquote, urlparse, urlunparse
import logging

from app.config import get_settings
from app.core.crawler.models import ApiEndpoint, ParameterCandidate, ParameterLocation, RequestObservation
from app.core.detectors.attack_surface import AttackSurface, AttackTarget, PreparedAttackRequest
from app.core.verification.verification_framework import HttpVerifier

from app.core.detectors.access_control.common import (
    _MatrixTarget,
    _MUTATING_AUTHZ_METHODS,
    _NUMERIC_RE,
    _UUID_RE,
    _looks_like_path_id_segment,
    _is_valid_id_value,
)

logger = logging.getLogger("app.core.detectors.access_control")


class TargetingMixin:
    # Generic REST resource nouns that commonly hold user-scoped / privileged data.
    # Used only to PRIORITISE authorization-matrix targets (never to gate detection),
    # so high-value endpoints survive the request-budget cap. Target-agnostic.
    _IDENTITY_RESOURCE_TOKENS = (
        "user", "account", "member", "customer", "profile", "card", "address",
        "order", "payment", "wallet", "invoice", "credential", "token", "admin",
        "ssn", "email", "phone", "message", "notification", "secret", "key",
    )

    # Public/telemetry/static noise that carries no authorization boundary.
    _MATRIX_NOISE_TOKENS = (
        "/assets/", "/i18n/", "/fonts/", "/static/", ".js", ".css", ".png", ".svg",
        ".ico", ".map", "languages", "application-version", "web3", "nft",
        "captcha", "metrics",
    )

    async def _send_prepared_request(
        self,
        verifier: HttpVerifier | None,
        request: PreparedAttackRequest,
        *,
        test_phase: str,
    ):
        if verifier is None:
            raise ValueError("verifier is required")
        headers = self._sanitize_replay_headers(request.headers or {})
        return await verifier.send_request(
            request.url,
            request.method,
            request.params,
            request.data,
            headers=headers or None,
            cookies=request.cookies or None,
            json_body=request.json_body,
            test_phase=test_phase,
            parameter="",
        )

    def _build_request_for_value(self, target: AttackTarget, value: Any) -> PreparedAttackRequest:
        if target.location == ParameterLocation.path and target.parameter.startswith("__path_seg_"):
            return PreparedAttackRequest(
                url=self._replace_concrete_path_segment(target.url, target.parameter, str(value)),
                method=target.method.upper(),
                headers=target.headers or None,
                cookies=target.cookies or None,
            )
        return target.build_request(value)

    @staticmethod
    def _replace_concrete_path_segment(url: str, parameter: str, value: str) -> str:
        match = re.match(r"__path_seg_(?P<index>\d+)__:(?P<original>.*)", parameter)
        if not match:
            return url
        index = int(match.group("index"))
        original = match.group("original")
        parsed = urlparse(url)
        segments = parsed.path.split("/")
        non_empty_index = -1
        for i, segment in enumerate(segments):
            if not segment:
                continue
            non_empty_index += 1
            if non_empty_index == index and segment == original:
                segments[i] = value
                break
        return urlunparse(parsed._replace(path="/".join(segments)))

    def _request_from_observation(self, observation: RequestObservation) -> PreparedAttackRequest | None:
        method = str(getattr(observation, "method", "GET") or "GET").upper()
        headers = self._sanitize_replay_headers(getattr(observation, "request_headers", {}) or {})
        post_data = getattr(observation, "post_data", None)
        json_body = self._parse_json(post_data)
        data = None
        if json_body is None and isinstance(post_data, str) and post_data.strip():
            data = dict(parse_qsl(post_data, keep_blank_values=True)) or None
        return PreparedAttackRequest(
            url=str(getattr(observation, "url", "") or ""),
            method=method,
            data=data,
            json_body=json_body,
            headers=headers or None,
        )

    def _request_from_endpoint(self, endpoint: ApiEndpoint) -> PreparedAttackRequest | None:
        url = endpoint.url
        if "{" in url or re.search(r"/:[A-Za-z_]", url):
            params = [p for p in self._parameters_from_endpoint(endpoint) if p.location == ParameterLocation.path]
            if not params:
                return None
            target = AttackTarget(
                url=url,
                parameter=params[0].name,
                method=endpoint.method,
                value=params[0].baseline_value,
                location=ParameterLocation.path,
                source="api_path",
            )
            built = self._build_request_for_value(target, params[0].baseline_value or "1")
            if "{" in built.url or re.search(r"/:[A-Za-z_]", built.url):
                return None
            return built

        headers = self._sanitize_replay_headers(endpoint.headers or {})
        body = self._parse_json(endpoint.request_body)
        data = None
        if body is None and isinstance(endpoint.request_body, str):
            data = dict(parse_qsl(endpoint.request_body, keep_blank_values=True)) or None
        return PreparedAttackRequest(
            url=url,
            method=endpoint.method.upper(),
            data=data,
            json_body=body,
            headers=headers or None,
        )

    @staticmethod
    def _parameters_from_endpoint(endpoint: ApiEndpoint) -> list[ParameterCandidate]:
        from app.core.crawler.api_extractor import ApiExtractor

        return ApiExtractor.parameters_from_endpoint(endpoint)

    def _concrete_path_idor_targets(self, urls: list[str]) -> list[AttackTarget]:
        targets: list[AttackTarget] = []
        for url in urls:
            parsed = urlparse(url)
            segments = [s for s in parsed.path.split("/") if s]
            for i, segment in enumerate(segments):
                if _looks_like_path_id_segment(segment):
                    targets.append(
                        AttackTarget(
                            url=url,
                            parameter=f"__path_seg_{i}__:{segment}",
                            method="GET",
                            value=segment,
                            location=ParameterLocation.path,
                            source="path_segment",
                            security_relevance={"access_control"},
                        )
                    )
        return targets

    def _api_path_template_idor_targets(self, endpoints: list[ApiEndpoint]) -> list[AttackTarget]:
        targets: list[AttackTarget] = []
        for endpoint in endpoints:
            for parameter in self._parameters_from_endpoint(endpoint):
                if parameter.location != ParameterLocation.path:
                    continue
                if not self._is_idor_param(parameter.name):
                    continue
                targets.append(
                    AttackTarget(
                        url=endpoint.url,
                        parameter=parameter.name,
                        method=endpoint.method.upper(),
                        value=parameter.baseline_value or "1",
                        location=ParameterLocation.path,
                        source="api_path_template",
                        security_relevance={"access_control"},
                    )
                )
        return targets

    def _baseline_values_for_target(
        self,
        target: AttackTarget,
        response_ids: dict[str, set[str]],
    ) -> list[str]:
        values: list[str] = []
        raw = str(target.value if target.value is not None else "")
        # Concrete path-segment ids are already vetted by
        # ``_looks_like_path_id_segment`` and may exceed the opaque-token length
        # cap (SHA/base64), so trust the discovered value directly.
        if target.source == "path_segment" and raw:
            values.append(raw)
        elif _is_valid_id_value(raw):
            values.append(raw)
        elif raw in {"", "test", "sample.txt"} and self._target_has_access_control_relevance(target):
            values.append("1")

        param_key = self._normalize_param_name(target.parameter)
        for key, ids in response_ids.items():
            if key == param_key or key.endswith(param_key) or param_key.endswith(key):
                for value in ids:
                    if value not in values:
                        values.append(value)
        # Do not borrow arbitrary ids for concrete body/query fields. The wildcard
        # pool is only a last resort for unresolved path-like object references.
        if not values and target.location == ParameterLocation.path:
            for value in response_ids.get("*", set()):
                if len(values) >= 3:
                    break
                if value not in values:
                    values.append(value)
        return values[:3]

    def _response_body_ids(self, requests: list[RequestObservation]) -> dict[str, set[str]]:
        ids: dict[str, set[str]] = {"*": set()}
        for request in requests:
            body = self._parse_json(getattr(request, "response_snippet", None))
            self._collect_json_ids(body, ids)
        return ids

    def _collect_json_ids(self, value: Any, ids: dict[str, set[str]], parent: str = "") -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                path = f"{parent}.{key}" if parent else key
                if isinstance(child, (str, int)):
                    child_value = str(child)
                    if self._is_idor_param(key) and _is_valid_id_value(child_value):
                        normalized = self._normalize_param_name(key)
                        ids.setdefault(normalized, set()).add(child_value)
                        ids["*"].add(child_value)
                self._collect_json_ids(child, ids, path)
        elif isinstance(value, list):
            for child in value[:10]:
                self._collect_json_ids(child, ids, parent)

    @staticmethod
    def _sanitize_replay_headers(headers: dict[str, str]) -> dict[str, str]:
        stripped = {}
        blocked = {
            "authorization",
            "proxy-authorization",
            "cookie",
            "set-cookie",
            "x-api-key",
            "api-key",
            "host",
            "content-length",
        }
        for key, value in headers.items():
            if key.lower() in blocked:
                continue
            stripped[key] = value
        return stripped

    def _build_idor_targets(self, urls: list[str], forms: list[object], **kwargs: object) -> list[AttackTarget]:
        parameters = kwargs.get("parameters")
        api_endpoints = kwargs.get("api_endpoints")
        requests = kwargs.get("requests")
        targets = AttackSurface.build(
            urls,
            forms,
            parameters=parameters if isinstance(parameters, list) else None,
            api_endpoints=api_endpoints if isinstance(api_endpoints, list) else None,
            requests=requests if isinstance(requests, list) else None,
            filter_fn=self._is_idor_param,
        )

        concrete_path_targets = self._concrete_path_idor_targets(urls)
        targets.extend(concrete_path_targets)
        targets.extend(self._api_path_template_idor_targets(api_endpoints if isinstance(api_endpoints, list) else []))

        deduped: list[AttackTarget] = []
        seen: set[tuple[str, str, str, str, str]] = set()
        for target in targets:
            if not self._target_has_access_control_relevance(target):
                continue
            key = (
                target.url,
                target.method.upper(),
                target.parameter,
                target.location.value,
                target.parent_path or "",
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(target)
        return deduped[:80]

    def _build_matrix_targets(self, urls: list[str], forms: list[object], **kwargs: object) -> list[_MatrixTarget]:
        targets: list[_MatrixTarget] = []
        api_endpoints = kwargs.get("api_endpoints") if isinstance(kwargs.get("api_endpoints"), list) else []
        requests = kwargs.get("requests") if isinstance(kwargs.get("requests"), list) else []
        parameters = kwargs.get("parameters") if isinstance(kwargs.get("parameters"), list) else None

        for observation in requests:
            request = self._request_from_observation(observation)
            if request is None:
                continue
            targets.append(
                _MatrixTarget(
                    request=request,
                    source="browser_request",
                    has_object_reference=self._request_has_object_reference(request),
                    admin_like=self._is_admin_like_url(request.url),
                )
            )

        for endpoint in api_endpoints:
            request = self._request_from_endpoint(endpoint)
            if request is None:
                continue
            targets.append(
                _MatrixTarget(
                    request=request,
                    source="api_endpoint",
                    has_object_reference=self._request_has_object_reference(request),
                    admin_like=self._is_admin_like_url(request.url),
                )
            )

        for attack_target in AttackSurface.build(
            urls,
            forms,
            parameters=parameters,
            api_endpoints=api_endpoints,
            requests=requests,
            filter_fn=self._is_matrix_relevant_param,
        ):
            request = self._build_request_for_value(attack_target, attack_target.value or "1")
            targets.append(
                _MatrixTarget(
                    request=request,
                    source=attack_target.source,
                    parameter=attack_target.parameter,
                    parameter_location=attack_target.location.value,
                    has_object_reference=self._target_has_access_control_relevance(attack_target),
                    admin_like=self._is_admin_like_url(request.url),
                )
            )

        # Collection LIST-read probes. A GET on a REST collection (e.g. GET
        # /api/Users) is a prime broken-authorization target, but it is frequently
        # never observed: the listing is often only reachable from an admin/privileged
        # UI that a low-privilege crawl never renders, and the same endpoint may be
        # known only under a state-changing verb (e.g. POST /api/Users to register).
        # Synthesize the read variant for every collection we know about so the
        # authorization matrix can test it. GET is idempotent/read-only, so this is
        # safe; genuinely public collections are suppressed by the matrix's own
        # public-endpoint gate, and non-existent reads simply 404.
        targets.extend(self._synthesize_collection_read_targets(requests, api_endpoints))

        deduped: list[_MatrixTarget] = []
        seen: set[tuple[str, str, str, str]] = set()
        for target in targets:
            if not self._is_replayable_matrix_request(target.request):
                continue
            # SAFETY: an id-bearing state-changer (DELETE/PUT/PATCH /x/:id) would,
            # in the matrix, fire against the REAL object id under every auth
            # context — destroying/altering a real record. Those are covered
            # non-destructively (synthetic non-existent id) by
            # ``_check_mutating_authorization``, so exclude them here. POST creates
            # (no owner id in the path) stay in the matrix.
            if target.request.method.upper() in _MUTATING_AUTHZ_METHODS and self._request_with_synthetic_id(
                target.request
            ) is not None:
                continue
            key = (
                target.request.method.upper(),
                self._canonical_request_url(target.request.url),
                self._body_schema_key(target.request.json_body or target.request.data),
                target.parameter or "",
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(target)
        # The matrix is request-budget-capped, so ORDER matters: rank targets that
        # actually expose an authorization boundary (collection reads, object
        # references, identity/PII resources) above public noise (static assets,
        # catalogues, version/telemetry endpoints) so high-value targets are not
        # crowded out of the cap. Stable sort keeps discovery order within a tier.
        deduped.sort(key=self._matrix_target_priority, reverse=True)
        return deduped[:80]

    def _synthesize_collection_read_targets(
        self, requests: list[object], api_endpoints: list[object]
    ) -> list[_MatrixTarget]:
        """Build read-only GET matrix targets for every known REST collection."""
        bases: dict[str, str] = {}
        for source in (requests or []):
            url = str(getattr(source, "url", "") or "")
            base = self._collection_base_url(url) if url else None
            if base:
                bases.setdefault(self._canonical_request_url(base), base)
        for endpoint in (api_endpoints or []):
            url = str(getattr(endpoint, "url", "") or "")
            base = self._collection_base_url(url) if url else None
            if base:
                bases.setdefault(self._canonical_request_url(base), base)

        targets: list[_MatrixTarget] = []
        for base in bases.values():
            request = PreparedAttackRequest(url=base, method="GET")
            targets.append(
                _MatrixTarget(
                    request=request,
                    source="collection_read_probe",
                    has_object_reference=False,
                    admin_like=self._is_admin_like_url(base),
                )
            )
        return targets

    @staticmethod
    def _collection_base_url(url: str) -> str | None:
        """Return the REST collection URL for *url*, or ``None`` if not applicable.

        ``/api/Users/1`` and ``/api/Users`` both map to ``…/api/Users``. Scoped to
        API namespaces (``/api/`` or ``/rest/``) so HTML/static pages are ignored.
        A trailing object-id segment is dropped so an object URL still yields its
        parent collection listing.
        """
        parsed = urlparse(url)
        low_path = parsed.path.lower()
        if "/api/" not in low_path and "/rest/" not in low_path:
            return None
        segments = [s for s in parsed.path.split("/") if s]
        if segments and _looks_like_path_id_segment(segments[-1]):
            segments = segments[:-1]
        if not segments:
            return None
        last = segments[-1]
        # The collection segment must be a plain resource name, not an id/token.
        if _looks_like_path_id_segment(last) or not re.match(r"^[A-Za-z][A-Za-z0-9_-]*$", last):
            return None
        return f"{parsed.scheme}://{parsed.netloc}/" + "/".join(segments)

    def _matrix_target_priority(self, target: _MatrixTarget) -> int:
        """Rank an authorization-matrix target; higher survives the budget cap."""
        path = urlparse(target.request.url).path.lower()
        score = 0
        if target.admin_like:
            score += 5
        if target.has_object_reference:
            score += 3
        if target.source == "collection_read_probe":
            score += 4
        if any(token in path for token in self._IDENTITY_RESOURCE_TOKENS):
            score += 3
        if any(token in path for token in self._MATRIX_NOISE_TOKENS):
            score -= 6
        return score

    @staticmethod
    def _canonical_request_url(url: str) -> str:
        parsed = urlparse(url)
        query_names = "&".join(sorted(name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)))
        suffix = f"?{query_names}" if query_names else ""
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}{suffix}".lower()

    def _body_schema_key(self, value: Any) -> str:
        if value is None:
            return ""
        paths: set[str] = set()

        def walk(child: Any, prefix: str = "") -> None:
            if isinstance(child, dict):
                for key, grandchild in child.items():
                    path = f"{prefix}.{key}" if prefix else str(key)
                    paths.add(path)
                    walk(grandchild, path)
            elif isinstance(child, list):
                for item in child[:1]:
                    walk(item, prefix + "[]")

        walk(value)
        return "|".join(sorted(paths))

    @staticmethod
    def _has_placeholder_segment(url: str) -> bool:
        """True when a URL path still contains an unresolved template/placeholder
        segment rather than a concrete value.

        Crawlers frequently capture route templates before the SPA binds real
        data — ``/rest/track-order/:id``, ``/rest/track-order/undefined``,
        ``/api/orders/{orderId}`` — and these are not real, replayable endpoints.
        Detection is structural (segment shape), so it holds for any framework or
        client router, and covers URL-encoded ``:`` (``%3A``) which the simple
        ``/:`` literal check misses.
        """
        path = unquote(urlparse(url).path)
        for segment in path.split("/"):
            if not segment:
                continue
            lowered = segment.lower()
            if lowered in {"undefined", "null", "nan", "none"}:
                return True
            if segment[0] in ":{[" or segment[-1] in "}]":
                return True
        return False

    def _is_replayable_matrix_request(self, request: PreparedAttackRequest) -> bool:
        if not request.url or "{" in request.url or re.search(r"/:[A-Za-z_]", request.url):
            return False
        if self._has_placeholder_segment(request.url):
            return False
        method = request.method.upper()
        if method in {"OPTIONS", "HEAD"}:
            return False
        if method == "DELETE":
            return False
        if method in {"POST", "PUT", "PATCH"} and request.data is None and request.json_body is None:
            return False
        path = urlparse(request.url).path.lower()
        destructive_tokens = ("delete", "remove", "purchase", "checkout", "pay", "transfer", "withdraw")
        settings = get_settings()
        scan_mode = self._scan_config.get_val("scan_mode", getattr(settings, "scan_mode", "verified")) if getattr(self, "_scan_config", None) else getattr(settings, "scan_mode", "verified")
        if scan_mode != "aggressive" and any(token in path for token in destructive_tokens):
            return False
        return True

    def _request_has_object_reference(self, request: PreparedAttackRequest) -> bool:
        parsed = urlparse(request.url)
        if any(_NUMERIC_RE.match(seg) or _UUID_RE.match(seg) for seg in parsed.path.split("/") if seg):
            return True
        if any(self._is_idor_param(name) for name, _ in parse_qsl(parsed.query, keep_blank_values=True)):
            return True
        body = request.json_body if request.json_body is not None else request.data
        return self._body_has_idor_key(body)

    def _body_has_idor_key(self, value: Any) -> bool:
        if isinstance(value, dict):
            return any(self._is_idor_param(str(key)) or self._body_has_idor_key(child) for key, child in value.items())
        if isinstance(value, list):
            return any(self._body_has_idor_key(child) for child in value[:5])
        return False

    def _target_has_access_control_relevance(self, target: AttackTarget) -> bool:
        if "access_control" in target.security_relevance:
            return True
        return self._is_idor_param(target.parameter)
