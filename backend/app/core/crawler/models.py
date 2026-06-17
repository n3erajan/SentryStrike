from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RouteSource(str, Enum):
    html = "html"
    sitemap = "sitemap"
    robots = "robots"
    javascript = "javascript"
    browser = "browser"
    brute_force = "brute_force"
    api = "api"


class ParameterLocation(str, Enum):
    query = "query"
    path = "path"
    form = "form"
    json_body = "json_body"
    header = "header"
    cookie = "cookie"
    graphql_variable = "graphql_variable"


@dataclass
class RouteCandidate:
    url: str
    source: RouteSource
    priority: int = 50
    depth: int = 0
    evidence: str = ""
    is_spa_fallback: bool = False
    is_dead: bool = False


@dataclass
class ApiEndpoint:
    url: str
    method: str = "GET"
    source: RouteSource = RouteSource.javascript
    content_type: str | None = None
    operation: str | None = None
    request_body: Any = None
    headers: dict[str, str] = field(default_factory=dict)
    evidence: str = ""


@dataclass
class ParameterCandidate:
    name: str
    location: ParameterLocation
    url: str
    method: str = "GET"
    baseline_value: Any = "1"
    content_type: str | None = None
    parent_path: str | None = None
    source: str = "observed"
    security_relevance: set[str] = field(default_factory=set)
    user_controlled: bool = True
    context: dict[str, Any] = field(default_factory=dict)

    def legacy_tuple(self, form_inputs=None) -> tuple:
        return (self.url, self.name, self.method, str(self.baseline_value), form_inputs)


@dataclass
class RequestObservation:
    url: str
    method: str
    resource_type: str = "xhr"
    request_headers: dict[str, str] = field(default_factory=dict)
    post_data: Any = None
    response_status: int | None = None
    response_headers: dict[str, str] = field(default_factory=dict)
    response_content_type: str | None = None
    response_snippet: str | None = None
    redirect_chain: list[str] = field(default_factory=list)
    initiator: str = "browser"


@dataclass
class CrawlState:
    routes: list[RouteCandidate] = field(default_factory=list)
    api_endpoints: list[ApiEndpoint] = field(default_factory=list)
    parameters: list[ParameterCandidate] = field(default_factory=list)
    requests: list[RequestObservation] = field(default_factory=list)
    assets: set[str] = field(default_factory=set)
    technologies: set[str] = field(default_factory=set)
    browser_available: bool | None = None
    browser_error: str | None = None

    def add_route(self, candidate: RouteCandidate) -> None:
        if candidate.url not in {route.url for route in self.routes}:
            self.routes.append(candidate)

    def add_api_endpoint(self, endpoint: ApiEndpoint) -> None:
        key = (endpoint.url, endpoint.method.upper(), endpoint.operation or "")
        existing = {(ep.url, ep.method.upper(), ep.operation or "") for ep in self.api_endpoints}
        if key not in existing:
            self.api_endpoints.append(endpoint)

    def add_parameter(self, parameter: ParameterCandidate) -> None:
        key = (
            parameter.url,
            parameter.method.upper(),
            parameter.location,
            parameter.name,
            parameter.parent_path or "",
        )
        existing = {
            (p.url, p.method.upper(), p.location, p.name, p.parent_path or "")
            for p in self.parameters
        }
        if key not in existing:
            self.parameters.append(parameter)
