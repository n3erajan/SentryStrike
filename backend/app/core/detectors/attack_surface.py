from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import parse_qsl, urlparse

from app.core.crawler.api_extractor import ApiExtractor
from app.core.crawler.models import (
    ApiEndpoint,
    ParameterCandidate,
    ParameterLocation,
    RequestObservation,
)
from app.core.crawler.param_discovery import ParamDiscovery


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
    security_relevance: set[str] = field(default_factory=set)

    def legacy_tuple(self) -> tuple:
        return (self.url, self.parameter, self.method, str(self.value), self.form_inputs)


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
        request_templates = cls._request_templates(requests or [])
        targets: list[AttackTarget] = []
        seen: set[tuple[str, str, str, str, str]] = set()

        for candidate in candidates:
            template = None
            headers: dict[str, str] = {}
            if candidate.location in {ParameterLocation.json_body, ParameterLocation.graphql_variable}:
                template, headers = cls._find_template(candidate, endpoint_templates, request_templates)

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
                    form_inputs=candidate.context.get("form_inputs"),
                    content_type=candidate.content_type,
                    parent_path=candidate.parent_path,
                    source=candidate.source,
                    json_template=template,
                    headers=headers,
                    security_relevance=set(candidate.security_relevance),
                )
            )

        for request in requests or []:
            if not request.post_data:
                continue
            body = cls._parse_json(request.post_data)
            if not isinstance(body, dict):
                continue
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
    def _parse_json(value: Any) -> Any:
        if isinstance(value, (dict, list)):
            return value
        if not isinstance(value, str) or not value.strip():
            return None
        try:
            return json.loads(value)
        except Exception:
            return None


def build_json_body(template: Any, target: AttackTarget, injected_value: Any) -> Any:
    body = copy.deepcopy(template) if template is not None else {}
    if not isinstance(body, dict):
        body = {}

    path = target.parent_path or target.parameter
    _set_json_path(body, path, injected_value)
    return body


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


def target_from_legacy(candidate: tuple) -> AttackTarget:
    if len(candidate) == 5:
        url, param, method, value, form_inputs = candidate
    else:
        url, param, method, value = candidate
        form_inputs = None
    return AttackTarget(
        url=url,
        parameter=param,
        method=method,
        value=value,
        form_inputs=form_inputs,
    )


def query_or_form_targets(targets: list[AttackTarget]) -> list[tuple]:
    return [
        target.legacy_tuple()
        for target in targets
        if target.location in {ParameterLocation.query, ParameterLocation.form, ParameterLocation.path}
    ]
