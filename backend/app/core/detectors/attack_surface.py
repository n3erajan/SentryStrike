from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import parse_qs, quote, urlencode, urlparse, urlunparse

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
                )
            )

        for request in requests or []:
            if not request.post_data:
                continue
            body = cls._parse_json(request.post_data)
            if not isinstance(body, dict):
                form_body = cls._parse_form_data(request.post_data, request.request_headers or {})
                if not form_body:
                    continue
                form_inputs = [
                    _ObservedFormInput(name=name, value=str(value))
                    for name, value in form_body.items()
                ]
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
                            source="browser_form_request",
                            headers={
                                key: value
                                for key, value in (request.request_headers or {}).items()
                                if key.lower() not in {"content-length"}
                            },
                            security_relevance=ApiExtractor.classify_parameter(name),
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
                            security_relevance=set(parameter.security_relevance),
                        )
                    )

        return targets

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
                    _ObservedFormInput(name=name, value=str(value))
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
    def _parse_form_data(value: Any, headers: dict[str, str]) -> dict[str, str]:
        content_type = " ".join(
            str(header_value).lower()
            for header_name, header_value in headers.items()
            if header_name.lower() == "content-type"
        )
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
