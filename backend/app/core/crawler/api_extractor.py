from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlparse

from app.core.crawler.models import ApiEndpoint, ParameterCandidate, ParameterLocation, RouteSource
from app.core.crawler.url_parser import normalize_url


class ApiExtractor:
    """Extract API and frontend route candidates from JavaScript and observed requests."""

    ENDPOINT_RE = re.compile(
        r"""(?P<quote>["'`])(?P<path>/(?:api|graphql|gql|rest|v[0-9]+|rpc|trpc|auth|oauth|session|login|users?|accounts?|products?|orders?)[^"'`\s<>{}]*) (?P=quote)""",
        re.I | re.X,
    )
    RELATIVE_API_PATH_RE = re.compile(
        r"""(?P<quote>["'`])(?P<path>(?:api|graphql|gql|rest|v[0-9]+|rpc|trpc|auth|oauth|session)/(?:[^"'`\s<>{}]+))(?P=quote)""",
        re.I,
    )
    FETCH_RE = re.compile(
        r"""(?:fetch|axios\.(?:get|post|put|patch|delete)|\.(?:get|post|put|patch|delete))\s*\(\s*["'`](?P<path>[^"'`]+)["'`]""",
        re.I,
    )
    ROUTE_ARRAY_RE = re.compile(r"""path\s*:\s*["'`](?P<path>/[^"'`]+)["'`]""", re.I)
    REACT_ROUTER_RE = re.compile(r"""<Route[^>]+path\s*=\s*["'`](?P<path>/[^"'`]+)["'`]""", re.I)
    ANGULAR_ROUTE_RE = re.compile(r"""\{\s*path\s*:\s*["'`](?P<path>[^"'`]*)["'`]""", re.I)
    GRAPHQL_OP_RE = re.compile(r"""\b(query|mutation|subscription)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)""")
    GRAPHQL_VAR_RE = re.compile(r"""\$(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*:""")

    @classmethod
    def extract_from_javascript(cls, base_url: str, script_text: str) -> tuple[list[str], list[ApiEndpoint]]:
        routes: list[str] = []
        endpoints: list[ApiEndpoint] = []
        seen_routes: set[str] = set()
        seen_endpoints: set[tuple[str, str, str]] = set()

        def add_route(path: str) -> None:
            if not path or path.startswith(("http://", "https://", "//")):
                absolute = normalize_url(base_url, path)
            else:
                absolute = normalize_url(base_url, path if path.startswith("/") else f"/{path}")
            if absolute not in seen_routes:
                seen_routes.add(absolute)
                routes.append(absolute)

        def add_endpoint(path: str, method: str = "GET", operation: str | None = None, evidence: str = "") -> None:
            absolute = normalize_url(base_url, path)
            key = (absolute, method.upper(), operation or "")
            if key not in seen_endpoints:
                seen_endpoints.add(key)
                endpoints.append(
                    ApiEndpoint(
                        url=absolute,
                        method=method.upper(),
                        source=RouteSource.javascript,
                        operation=operation,
                        evidence=evidence or path,
                    )
                )

        for match in cls.ENDPOINT_RE.finditer(script_text):
            path = match.group("path")
            add_endpoint(path, "POST" if cls._looks_state_changing(path) else "GET")

        for match in cls.RELATIVE_API_PATH_RE.finditer(script_text):
            path = match.group("path")
            add_endpoint(f"/{path}", "POST" if cls._looks_state_changing(path) else "GET")

        for match in cls.FETCH_RE.finditer(script_text):
            path = match.group("path")
            if cls._looks_api_path(path):
                add_endpoint(path, cls._infer_method_near(script_text, match.start()), evidence="fetch/xhr")

        for regex in (cls.ROUTE_ARRAY_RE, cls.REACT_ROUTER_RE, cls.ANGULAR_ROUTE_RE):
            for match in regex.finditer(script_text):
                route_path = match.group("path")
                if route_path and not cls._looks_api_path(route_path):
                    add_route(route_path if route_path.startswith("/") else f"/{route_path}")

        graphql_paths = set(re.findall(r"""["'`](/(?:graphql|gql)[^"'`]*)["'`]""", script_text, flags=re.I))
        operations = cls.GRAPHQL_OP_RE.findall(script_text)
        operation_names = [name for _, name in operations] or [None]
        for path in graphql_paths:
            for operation in operation_names:
                add_endpoint(path, "POST", operation=operation, evidence="graphql")

        return routes, endpoints

    @classmethod
    def parameters_from_endpoint(cls, endpoint: ApiEndpoint) -> list[ParameterCandidate]:
        params: list[ParameterCandidate] = []
        parsed = urlparse(endpoint.url)

        for segment in parsed.path.split("/"):
            if segment.startswith(":") and len(segment) > 1:
                params.append(
                    ParameterCandidate(
                        name=segment[1:],
                        location=ParameterLocation.path,
                        url=endpoint.url,
                        method=endpoint.method,
                        source="api_path",
                        security_relevance=cls.classify_parameter(segment[1:]),
                    )
                )
            elif re.fullmatch(r"\{[A-Za-z_][A-Za-z0-9_]*\}", segment):
                name = segment.strip("{}")
                params.append(
                    ParameterCandidate(
                        name=name,
                        location=ParameterLocation.path,
                        url=endpoint.url,
                        method=endpoint.method,
                        source="api_path",
                        security_relevance=cls.classify_parameter(name),
                    )
                )

        body = endpoint.request_body
        if isinstance(body, str):
            try:
                body = json.loads(body)
            except Exception:
                body = None
        if isinstance(body, dict):
            cls._walk_json_params(body, endpoint.url, endpoint.method, params)

        if endpoint.operation:
            for variable in cls.GRAPHQL_VAR_RE.finditer(str(endpoint.request_body or "")):
                name = variable.group("name")
                params.append(
                    ParameterCandidate(
                        name=name,
                        location=ParameterLocation.graphql_variable,
                        url=endpoint.url,
                        method=endpoint.method,
                        source="graphql",
                        security_relevance=cls.classify_parameter(name),
                    )
                )
        return params

    @classmethod
    def classify_parameter(cls, name: str) -> set[str]:
        lowered = name.lower()
        relevance: set[str] = set()
        if any(token in lowered for token in ("id", "uuid", "user", "account", "tenant", "org")):
            relevance.add("access_control")
        if any(token in lowered for token in ("url", "uri", "redirect", "return", "next", "callback")):
            relevance.add("redirect_ssrf")
        if any(token in lowered for token in ("file", "path", "template", "page", "view", "doc")):
            relevance.add("file_inclusion")
        if any(token in lowered for token in ("q", "query", "search", "name", "title", "comment", "message")):
            relevance.add("injection_xss")
        if any(token in lowered for token in ("token", "csrf", "jwt", "auth", "session")):
            relevance.add("auth_state")
        return relevance

    @classmethod
    def _walk_json_params(
        cls,
        value: Any,
        url: str,
        method: str,
        out: list[ParameterCandidate],
        parent_path: str = "",
    ) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                path = f"{parent_path}.{key}" if parent_path else key
                out.append(
                    ParameterCandidate(
                        name=key,
                        location=ParameterLocation.json_body,
                        url=url,
                        method=method,
                        baseline_value=child if not isinstance(child, (dict, list)) else "1",
                        parent_path=path,
                        source="json_body",
                        security_relevance=cls.classify_parameter(key),
                    )
                )
                cls._walk_json_params(child, url, method, out, path)
        elif isinstance(value, list):
            for index, child in enumerate(value[:3]):
                cls._walk_json_params(child, url, method, out, f"{parent_path}[{index}]")

    @staticmethod
    def _looks_api_path(path: str) -> bool:
        lowered = path.lower()
        return any(token in lowered for token in ("/api", "/graphql", "/gql", "/rest", "/oauth", "/session", "/auth", "/rpc", "/trpc"))

    @staticmethod
    def _looks_state_changing(path: str) -> bool:
        lowered = path.lower()
        return any(token in lowered for token in ("create", "update", "delete", "login", "logout", "submit", "mutation"))

    @staticmethod
    def _infer_method_near(script_text: str, start: int) -> str:
        window = script_text[start : start + 300].lower()
        method_match = re.search(r"""method\s*:\s*["'`](get|post|put|patch|delete)["'`]""", window)
        if method_match:
            return method_match.group(1).upper()
        prefix = script_text[max(0, start - 40) : start].lower()
        for method in ("post", "put", "patch", "delete", "get"):
            if f".{method}" in prefix:
                return method.upper()
        return "GET"
