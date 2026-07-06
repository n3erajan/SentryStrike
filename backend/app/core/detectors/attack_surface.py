from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import parse_qs, quote, unquote, urlencode, urlparse, urlunparse

from app.core.crawler.api_extractor import ApiExtractor
from app.core.crawler.models import (
    ApiEndpoint,
    ParameterCandidate,
    ParameterLocation,
    RequestObservation,
)
from app.core.crawler.param_discovery import ParamDiscovery


@dataclass
class PreparedAttackRequest:
    url: str
    method: str
    params: dict[str, Any] | None = None
    data: Any = None
    json_body: Any = None
    headers: dict[str, str] | None = None
    cookies: dict[str, str] | None = None
    files: dict[str, Any] | None = None


@dataclass
class _ObservedFormInput:
    name: str
    input_type: str = "text"
    value: str = ""


@dataclass
class AttackTarget:
    url: str
    parameter: str
    method: str = "GET"
    value: Any = ""
    location: ParameterLocation = ParameterLocation.query
    form_inputs: list | None = None
    content_type: str | None = None
    parent_path: str | None = None
    source: str = "observed"
    json_template: Any = None
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    security_relevance: set[str] = field(default_factory=set)
    replayable: bool = True
    body_schema: list[str] = field(default_factory=list)
    source_confidence: str = "observed"

    def legacy_tuple(self) -> tuple:
        return (self.url, self.parameter, self.method, str(self.value), self.form_inputs)

    def build_request(self, injected_value: Any, *, merge_with_baseline: bool = False) -> PreparedAttackRequest:
        value = f"{self.value}{injected_value}" if merge_with_baseline else injected_value
        method = self.method.upper()
        headers = dict(self.headers or {})
        cookies = dict(self.cookies or {})

        if self.location == ParameterLocation.path:
            return PreparedAttackRequest(
                url=inject_path_parameter(self.url, self.parameter, str(value)),
                method=method,
                headers=headers or None,
                cookies=cookies or None,
            )

        if self.location == ParameterLocation.query:
            url, params, data = inject_url_or_form_parameter(
                self.url, self.parameter, str(value), method, self.form_inputs
            )
            return PreparedAttackRequest(
                url=url,
                method=method,
                params=params or None,
                data=data or None,
                headers=headers or None,
                cookies=cookies or None,
            )

        if self.location == ParameterLocation.form:
            if _is_multipart_content_type(self.content_type):
                data, files = build_multipart_payload(self.form_inputs, self.parameter, value)
                headers = {
                    key: header_value
                    for key, header_value in headers.items()
                    if key.lower() not in {"content-type", "content-length"}
                }
                return PreparedAttackRequest(
                    url=self.url,
                    method=method,
                    data=data or None,
                    files=files or None,
                    headers=headers or None,
                    cookies=cookies or None,
                )
            url, params, data = inject_url_or_form_parameter(
                self.url, self.parameter, str(value), method, self.form_inputs
            )
            return PreparedAttackRequest(
                url=url,
                method=method,
                params=params or None,
                data=data or None,
                headers=headers or None,
                cookies=cookies or None,
            )

        if self.location in {ParameterLocation.json_body, ParameterLocation.graphql_variable}:
            headers.setdefault("Content-Type", "application/json")
            return PreparedAttackRequest(
                url=self.url,
                method=method,
                json_body=build_json_body(self.json_template, self, value),
                headers=headers or None,
                cookies=cookies or None,
            )

        if self.location == ParameterLocation.header:
            headers[self.parameter] = str(value)
            return PreparedAttackRequest(url=self.url, method=method, headers=headers or None, cookies=cookies or None)

        if self.location == ParameterLocation.cookie:
            cookies[self.parameter] = str(value)
            return PreparedAttackRequest(url=self.url, method=method, headers=headers or None, cookies=cookies or None)

        return PreparedAttackRequest(url=self.url, method=method, headers=headers or None, cookies=cookies or None)


class AttackSurface:
    """Build replayable detector inputs from crawler URL/form/API/browser output."""

    @classmethod
    def build(
        cls,
        urls: list[str],
        forms: list[object],
        *,
        parameters: list[ParameterCandidate] | None = None,
        api_endpoints: list[ApiEndpoint] | None = None,
        requests: list[RequestObservation] | None = None,
        filter_fn: Callable[[str], bool] | None = None,
    ) -> list[AttackTarget]:
        candidates = list(parameters or [])
        if not candidates:
            candidates = ParamDiscovery.build_parameter_inventory(
                urls,
                forms,
                filter_fn=filter_fn,
                api_endpoints=api_endpoints,
            )
        elif filter_fn:
            candidates = [candidate for candidate in candidates if filter_fn(candidate.name)]

        endpoint_templates = cls._endpoint_templates(api_endpoints or [])
        endpoint_form_templates = cls._endpoint_form_templates(api_endpoints or [])
        request_templates = cls._request_templates(requests or [])
        targets: list[AttackTarget] = []
        seen: set[tuple[str, str, str, str, str]] = set()

        for candidate in candidates:
            if cls._is_transport_layer_url(candidate.url):
                continue
            if cls._has_unresolved_path_placeholder(candidate.url):
                continue
            template = None
            form_inputs = candidate.context.get("form_inputs")
            headers: dict[str, str] = {}
            if candidate.location in {ParameterLocation.json_body, ParameterLocation.graphql_variable}:
                template, headers = cls._find_template(candidate, endpoint_templates, request_templates)
            elif candidate.location == ParameterLocation.form and form_inputs is None:
                form_inputs, headers = cls._find_form_template(candidate, endpoint_form_templates)

            key = (
                candidate.url,
                candidate.method.upper(),
                candidate.name,
                candidate.location.value,
                candidate.parent_path or "",
            )
            if key in seen:
                continue
            seen.add(key)
            targets.append(
                AttackTarget(
                    url=candidate.url,
                    parameter=candidate.name,
                    method=candidate.method.upper(),
                    value=candidate.baseline_value,
                    location=candidate.location,
                    form_inputs=form_inputs,
                    content_type=candidate.content_type,
                    parent_path=candidate.parent_path,
                    source=candidate.source,
                    json_template=template,
                    headers=headers,
                    cookies=candidate.context.get("cookies") or {},
                    security_relevance=set(candidate.security_relevance),
                    replayable=bool(candidate.context.get("replayable", True)),
                    body_schema=list(candidate.context.get("body_schema") or []),
                )
            )

        for request in requests or []:
            if not request.post_data:
                continue
            content_type = cls._request_content_type(request)
            body = cls._parse_json(request.post_data)
            if not isinstance(body, dict):
                form_body = cls._parse_form_data(request.post_data, request.request_headers or {}, content_type)
                multipart_fields = cls._observed_multipart_inputs(request) or cls._parse_multipart_fields(
                    request.post_data,
                    request.request_headers or {},
                    content_type,
                )
                if not form_body and not multipart_fields:
                    continue
                if multipart_fields:
                    form_body = {field.name: field.value for field in multipart_fields}
                    form_inputs = multipart_fields
                    content_type = "multipart/form-data"
                else:
                    form_inputs = [
                        _ObservedFormInput(name=name, value=str(value))
                        for name, value in form_body.items()
                    ]
                    content_type = "application/x-www-form-urlencoded"
                for name, value in form_body.items():
                    if filter_fn and not filter_fn(name):
                        continue
                    key = (
                        request.url,
                        request.method.upper(),
                        name,
                        ParameterLocation.form.value,
                        "",
                    )
                    if key in seen:
                        continue
                    seen.add(key)
                    targets.append(
                        AttackTarget(
                            url=request.url,
                            parameter=name,
                            method=request.method.upper(),
                            value=value,
                            location=ParameterLocation.form,
                            form_inputs=form_inputs,
                            content_type=content_type,
                            source="browser_form_request",
                            headers={
                                key: value
                                for key, value in (request.request_headers or {}).items()
                                if key.lower() not in {"content-length"}
                            },
                            cookies=dict(getattr(request, "request_cookies", {}) or {}),
                            security_relevance=ApiExtractor.classify_parameter(name),
                            replayable=bool(getattr(request, "replayable", True)),
                            body_schema=list(getattr(request, "body_schema", []) or []),
                            source_confidence="browser_replayable" if getattr(request, "replayable", False) else "browser_observed",
                        )
                    )
            else:
                endpoint = ApiEndpoint(
                    url=request.url,
                    method=request.method,
                    request_body=body,
                    headers=request.request_headers,
                )
                for parameter in ApiExtractor.parameters_from_endpoint(endpoint):
                    if filter_fn and not filter_fn(parameter.name):
                        continue
                    key = (
                        parameter.url,
                        parameter.method.upper(),
                        parameter.name,
                        parameter.location.value,
                        parameter.parent_path or "",
                    )
                    if key in seen:
                        continue
                    seen.add(key)
                    targets.append(
                        AttackTarget(
                            url=parameter.url,
                            parameter=parameter.name,
                            method=parameter.method.upper(),
                            value=parameter.baseline_value,
                            location=parameter.location,
                            parent_path=parameter.parent_path,
                            source="browser_request",
                            json_template=body,
                            headers=request.request_headers,
                            cookies=dict(getattr(request, "request_cookies", {}) or {}),
                            security_relevance=set(parameter.security_relevance),
                            replayable=bool(getattr(request, "replayable", True)),
                            body_schema=list(getattr(request, "body_schema", []) or []),
                            source_confidence="browser_replayable" if getattr(request, "replayable", False) else "browser_observed",
                        )
                    )

        cls._synthesize_body_targets(
            api_endpoints or [],
            requests or [],
            targets,
            seen,
            filter_fn,
        )

        return targets

    @staticmethod
    def _is_transport_layer_url(url: str) -> bool:
        """True for WebSocket/long-poll transport-library URLs that are not application APIs.

        Socket.IO, SockJS, and SignalR expose polling URLs whose query parameters
        (EIO, transport, sid, t) are wire-protocol identifiers, not application data.
        Injecting into them wastes the verification budget and never yields findings.
        Filtered by well-known library path tokens and protocol-level query signatures.
        """
        try:
            parsed = urlparse(url)
            path = parsed.path.lower()
            for lib_segment in ("/socket.io", "/engine.io", "/sockjs", "/signalr/hubs"):
                if lib_segment in path:
                    return True
            qs = parse_qs(parsed.query)
            if "EIO" in qs and "transport" in qs:
                return True
        except Exception:
            pass
        return False

    # Maximum synthesized leaf targets per endpoint (bounds combinatorial growth).
    _SYNTH_LEAF_CAP = 25

    @classmethod
    def _synthesize_body_targets(
        cls,
        api_endpoints: list[ApiEndpoint],
        requests: list[RequestObservation],
        targets: list[AttackTarget],
        seen: set[tuple[str, str, str, str, str]],
        filter_fn: Callable[[str], bool] | None,
    ) -> None:
        """Emit static-synthesis body targets for endpoints the browser never hit.

        For each mutating endpoint without an observed body, synthesize a skeleton
        JSON/form body and add one lower-confidence ``AttackTarget`` per leaf field
        (``replayable=False``, ``source_confidence="static_synth"``). Observed and
        already-emitted targets win via ``seen`` and the observed-body key set.
        """
        observed_body_keys = {
            (request.url, request.method.upper())
            for request in requests
            if request.post_data
        }
        for endpoint in api_endpoints:
            if (endpoint.url, endpoint.method.upper()) in observed_body_keys:
                continue
            if cls._has_unresolved_path_placeholder(endpoint.url):
                continue
            # Task C (RC-C): only synthesize bodies for genuine API/JSON/form
            # endpoints. SPA HTML navigation routes (e.g. a POST /login route
            # returning the 200 HTML shell) exercise no vulnerable code, so
            # placeholder bodies aimed at them waste the injection budget.
            # Observed bodies always win (deduped out above), so this gate only
            # affects static synthesis.
            if not ApiExtractor.is_api_endpoint(endpoint):
                continue
            # The endpoint is a confirmed API surface (gate above), so opt in to
            # the generic single-leaf body: a mutating API endpoint with no
            # observed body and no static schema still gets one low-confidence
            # (``replayable=False``/``static_synth``) body-injection target
            # instead of zero coverage (RC3).
            content_type, template = ApiExtractor.synthesize_body_schema(
                endpoint, allow_generic_body=True
            )
            if not template:
                continue
            synth_endpoint = ApiEndpoint(
                url=endpoint.url,
                method=endpoint.method,
                content_type=content_type,
                request_body=template,
                multipart_fields=endpoint.multipart_fields,
            )
            is_multipart = _is_multipart_content_type(content_type)
            is_form = is_multipart or "x-www-form-urlencoded" in (content_type or "").lower()
            form_inputs = None
            if is_form and isinstance(template, dict):
                form_inputs = [
                    _ObservedFormInput(
                        name=name,
                        input_type="file" if (is_multipart and _looks_like_file_field(name)) else "text",
                        value=str(value),
                    )
                    for name, value in template.items()
                    if name and not isinstance(value, (dict, list))
                ]
            emitted = 0
            for parameter in ApiExtractor.parameters_from_endpoint(synth_endpoint):
                if parameter.location not in {
                    ParameterLocation.json_body,
                    ParameterLocation.form,
                    ParameterLocation.graphql_variable,
                }:
                    continue
                if filter_fn and not filter_fn(parameter.name):
                    continue
                key = (
                    parameter.url,
                    parameter.method.upper(),
                    parameter.name,
                    parameter.location.value,
                    parameter.parent_path or "",
                )
                if key in seen:
                    continue
                seen.add(key)
                is_body_json = parameter.location in {
                    ParameterLocation.json_body,
                    ParameterLocation.graphql_variable,
                }
                targets.append(
                    AttackTarget(
                        url=parameter.url,
                        parameter=parameter.name,
                        method=parameter.method.upper(),
                        value=parameter.baseline_value,
                        location=parameter.location,
                        form_inputs=None if is_body_json else form_inputs,
                        content_type=content_type,
                        parent_path=parameter.parent_path,
                        source="static_synth",
                        json_template=template if is_body_json else None,
                        security_relevance=set(parameter.security_relevance),
                        replayable=False,
                        source_confidence="static_synth",
                    )
                )
                emitted += 1
                if emitted >= cls._SYNTH_LEAF_CAP:
                    break

    @classmethod
    def body_target_telemetry(
        cls,
        *,
        api_endpoints: list[ApiEndpoint] | None = None,
        requests: list[RequestObservation] | None = None,
    ) -> dict[str, int]:
        targets = cls.build(
            [],
            [],
            api_endpoints=api_endpoints or [],
            requests=requests or [],
        )
        return {
            "observed_json_body_targets": sum(
                1
                for target in targets
                if target.location in {ParameterLocation.json_body, ParameterLocation.graphql_variable}
                and target.source_confidence != "static_synth"
            ),
            "observed_form_body_targets": sum(
                1
                for target in targets
                if target.location == ParameterLocation.form
                and target.source_confidence != "static_synth"
            ),
            "static_synth_body_targets": sum(
                1 for target in targets if target.source_confidence == "static_synth"
            ),
            "skipped_unresolved_body_targets": cls._count_unresolved_static_body_targets(
                api_endpoints or [],
                requests or [],
            ),
        }

    @classmethod
    def _count_unresolved_static_body_targets(
        cls,
        api_endpoints: list[ApiEndpoint],
        requests: list[RequestObservation],
    ) -> int:
        observed_body_keys = {
            (request.url, request.method.upper())
            for request in requests
            if request.post_data
        }
        count = 0
        for endpoint in api_endpoints:
            if (endpoint.url, endpoint.method.upper()) in observed_body_keys:
                continue
            if not cls._has_unresolved_path_placeholder(endpoint.url):
                continue
            if not ApiExtractor.is_api_endpoint(endpoint):
                continue
            _content_type, template = ApiExtractor.synthesize_body_schema(
                endpoint,
                allow_generic_body=True,
            )
            if template:
                count += 1
        return count

    @staticmethod
    def _has_unresolved_path_placeholder(url: str) -> bool:
        try:
            path = unquote(urlparse(url).path or "")
        except Exception:
            return False
        for segment in path.split("/"):
            if not segment:
                continue
            if segment.startswith("{") and segment.endswith("}"):
                return True
            if segment.startswith("[") and segment.endswith("]"):
                return True
            if segment.startswith("<") and segment.endswith(">"):
                return True
            if segment.startswith(":") and len(segment) > 1:
                return True
        return False

    @staticmethod
    def _endpoint_templates(endpoints: list[ApiEndpoint]) -> dict[tuple[str, str], tuple[Any, dict[str, str]]]:
        templates: dict[tuple[str, str], tuple[Any, dict[str, str]]] = {}
        for endpoint in endpoints:
            body = AttackSurface._parse_json(endpoint.request_body)
            if isinstance(body, dict):
                templates[(endpoint.url, endpoint.method.upper())] = (body, endpoint.headers or {})
        return templates

    @staticmethod
    def _endpoint_form_templates(
        endpoints: list[ApiEndpoint],
    ) -> dict[tuple[str, str], tuple[list[_ObservedFormInput], dict[str, str]]]:
        templates: dict[tuple[str, str], tuple[list[_ObservedFormInput], dict[str, str]]] = {}
        for endpoint in endpoints:
            content_type = (endpoint.content_type or "").lower()
            if (
                "application/x-www-form-urlencoded" not in content_type
                and "multipart/form-data" not in content_type
            ):
                continue
            body = AttackSurface._parse_json(endpoint.request_body)
            if not isinstance(body, dict):
                continue
            templates[(endpoint.url, endpoint.method.upper())] = (
                [
                    _ObservedFormInput(
                        name=name,
                        input_type=(
                            "file"
                            if "multipart/form-data" in content_type
                            and _looks_like_file_field(name)
                            else "text"
                        ),
                        value=str(value),
                    )
                    for name, value in body.items()
                    if name and not isinstance(value, (dict, list))
                ],
                {
                    key: value
                    for key, value in (endpoint.headers or {}).items()
                    if key.lower() not in {"content-length"}
                },
            )
        return templates

    @staticmethod
    def _request_templates(requests: list[RequestObservation]) -> dict[tuple[str, str], tuple[Any, dict[str, str]]]:
        templates: dict[tuple[str, str], tuple[Any, dict[str, str]]] = {}
        for request in requests:
            body = AttackSurface._parse_json(request.post_data)
            if isinstance(body, dict):
                templates[(request.url, request.method.upper())] = (body, request.request_headers or {})
        return templates

    @staticmethod
    def _find_template(
        candidate: ParameterCandidate,
        endpoint_templates: dict[tuple[str, str], tuple[Any, dict[str, str]]],
        request_templates: dict[tuple[str, str], tuple[Any, dict[str, str]]],
    ) -> tuple[Any, dict[str, str]]:
        key = (candidate.url, candidate.method.upper())
        if key in request_templates:
            return request_templates[key]
        if key in endpoint_templates:
            return endpoint_templates[key]
        return None, {}

    @staticmethod
    def _find_form_template(
        candidate: ParameterCandidate,
        endpoint_form_templates: dict[tuple[str, str], tuple[list[_ObservedFormInput], dict[str, str]]],
    ) -> tuple[list[_ObservedFormInput] | None, dict[str, str]]:
        key = (candidate.url, candidate.method.upper())
        if key in endpoint_form_templates:
            return endpoint_form_templates[key]
        return None, {}

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

    @staticmethod
    def _parse_form_data(value: Any, headers: dict[str, str], content_type: str | None = None) -> dict[str, str]:
        content_type = (content_type or " ".join(
            str(header_value).lower()
            for header_name, header_value in headers.items()
            if header_name.lower() == "content-type"
        )).lower()
        if "application/x-www-form-urlencoded" not in content_type:
            return {}
        if isinstance(value, bytes):
            value = value.decode("utf-8", "ignore")
        if not isinstance(value, str) or not value.strip():
            return {}
        parsed = parse_qs(value, keep_blank_values=True)
        return {
            name: values[0] if values else ""
            for name, values in parsed.items()
            if name
        }

    @staticmethod
    def _parse_multipart_fields(
        value: Any,
        headers: dict[str, str],
        content_type: str | None = None,
    ) -> list[_ObservedFormInput]:
        content_type = (content_type or " ".join(
            str(header_value).lower()
            for header_name, header_value in headers.items()
            if header_name.lower() == "content-type"
        )).lower()
        if "multipart/form-data" not in content_type:
            return []
        if isinstance(value, bytes):
            value = value.decode("utf-8", "ignore")
        if not isinstance(value, str) or not value.strip():
            return []
        inputs: list[_ObservedFormInput] = []
        seen: set[str] = set()
        for match in re.finditer(
            r'Content-Disposition:\s*form-data;\s*name="(?P<name>[^"]+)"(?P<rest>[^\r\n]*)',
            value,
            re.I,
        ):
            name = match.group("name")
            if not name or name in seen:
                continue
            seen.add(name)
            is_file = "filename=" in match.group("rest").lower() or _looks_like_file_field(name)
            inputs.append(
                _ObservedFormInput(
                    name=name,
                    input_type="file" if is_file else "text",
                    value="" if is_file else "sentry_test_val",
                )
            )
        return inputs

    @staticmethod
    def _observed_multipart_inputs(request: RequestObservation) -> list[_ObservedFormInput]:
        inputs: list[_ObservedFormInput] = []
        for field in getattr(request, "multipart_fields", []) or []:
            name = field.get("name")
            if not name:
                continue
            input_type = "file" if field.get("type") == "file" else "text"
            inputs.append(_ObservedFormInput(name=name, input_type=input_type, value=""))
        return inputs

    @staticmethod
    def _request_content_type(request: RequestObservation) -> str | None:
        if getattr(request, "request_content_type", None):
            return request.request_content_type
        for name, value in (request.request_headers or {}).items():
            if name.lower() == "content-type":
                return value
        return None


def build_json_body(template: Any, target: AttackTarget, injected_value: Any) -> Any:
    body = copy.deepcopy(template) if template is not None else {}
    if not isinstance(body, dict):
        body = {}

    path = target.parent_path or target.parameter
    _set_json_path(body, path, injected_value)
    return body


def inject_url_or_form_parameter(
    base_url: str,
    parameter_name: str,
    parameter_value: str,
    method: str = "GET",
    form_inputs: list | None = None,
) -> tuple[str, dict[str, Any], dict[str, Any]]:
    parsed = urlparse(base_url)
    query_params = parse_qs(parsed.query, keep_blank_values=True)
    for key in query_params:
        if isinstance(query_params[key], list):
            query_params[key] = query_params[key][0] if query_params[key] else ""

    if form_inputs is not None:
        payload = build_form_payload(form_inputs, parameter_name, parameter_value)
        merged_params = {**query_params, **payload}
        if method.upper() == "GET":
            new_query = urlencode(merged_params, doseq=False)
            return urlunparse(parsed._replace(query=new_query)), {}, {}
        return base_url, {}, merged_params

    query_params[parameter_name] = parameter_value
    new_query = urlencode(query_params, doseq=False)
    new_url = urlunparse(parsed._replace(query=new_query))
    if method.upper() == "GET":
        return new_url, {}, {}
    return base_url, {}, query_params


def build_form_payload(form_inputs: list, target_param: str, target_value: str) -> dict[str, str]:
    payload: dict[str, str] = {}
    for inp in form_inputs:
        name = getattr(inp, "name", "")
        if not name:
            continue
        inp_type = getattr(inp, "input_type", "text").lower()
        if name == target_param:
            payload[name] = target_value
        elif inp_type == "password":
            payload[name] = "sentry_password123"
        elif inp_type in ("submit", "button"):
            payload[name] = getattr(inp, "value", "Submit") or "Submit"
        elif inp_type == "hidden":
            payload[name] = getattr(inp, "value", "")
        else:
            payload[name] = getattr(inp, "value", "") or "sentry_test_val"
    if target_param not in payload:
        payload[target_param] = target_value
    return payload


def build_multipart_payload(
    form_inputs: list | None,
    target_param: str,
    target_value: Any,
) -> tuple[dict[str, str], dict[str, Any]]:
    data: dict[str, str] = {}
    files: dict[str, Any] = {}
    inputs = list(form_inputs or [])

    for inp in inputs:
        name = getattr(inp, "name", "")
        if not name:
            continue
        inp_type = getattr(inp, "input_type", "text").lower()
        if inp_type == "file":
            value = target_value if name == target_param else getattr(inp, "value", "") or b"SENTRY_UPLOAD_TEST_CANARY"
            files[name] = _multipart_file_tuple(value)
        elif name == target_param:
            data[name] = str(target_value)
        else:
            data[name] = getattr(inp, "value", "") or "sentry_test_val"

    if target_param not in data and target_param not in files:
        if _looks_like_file_field(target_param):
            files[target_param] = _multipart_file_tuple(target_value)
        else:
            data[target_param] = str(target_value)
    return data, files


def _multipart_file_tuple(value: Any) -> Any:
    if isinstance(value, tuple):
        return value
    if isinstance(value, bytes):
        return ("sentry_upload.bin", value, "application/octet-stream")
    if isinstance(value, str) and value:
        return ("sentry_upload.txt", value.encode("utf-8"), "text/plain")
    return ("sentry_upload.txt", b"SENTRY_UPLOAD_TEST_CANARY", "text/plain")


def _is_multipart_content_type(value: str | None) -> bool:
    return "multipart/form-data" in (value or "").lower()


def _looks_like_file_field(name: str) -> bool:
    lowered = (name or "").lower()
    return any(token in lowered for token in ("file", "upload", "avatar", "image", "document", "attachment"))


def inject_path_parameter(url: str, parameter_name: str, parameter_value: str) -> str:
    parsed = urlparse(url)
    placeholder = "{" + parameter_name + "}"
    path = parsed.path
    encoded_value = quote(parameter_value, safe="")
    if placeholder in path:
        path = path.replace(placeholder, encoded_value)
    elif f":{parameter_name}" in path:
        path = path.replace(f":{parameter_name}", encoded_value)
    return urlunparse(parsed._replace(path=path))


def _set_json_path(body: dict, path: str, value: Any) -> None:
    if not path:
        body["value"] = value
        return

    parts = [part for part in path.replace("[", ".[").split(".") if part]
    current: Any = body
    for index, part in enumerate(parts):
        is_last = index == len(parts) - 1
        if part.startswith("["):
            continue
        if is_last:
            if isinstance(current, dict):
                current[part] = value
            return
        if not isinstance(current, dict):
            return
        current = current.setdefault(part, {})


def query_or_form_targets(targets: list[AttackTarget]) -> list[tuple]:
    return [
        target.legacy_tuple()
        for target in targets
        if target.location in {ParameterLocation.query, ParameterLocation.form, ParameterLocation.path}
    ]
