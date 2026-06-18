from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlparse

from app.core.crawler.models import ApiEndpoint, ParameterCandidate, ParameterLocation, RouteSource
from app.core.crawler.url_parser import normalize_url


class ApiExtractor:
    """Extract API and frontend route candidates from JavaScript and observed requests."""

    ENDPOINT_RE = re.compile(
        r"""(?P<quote>["'`])(?P<path>/(?:api|graphql|gql|rest|v[0-9]+|rpc|trpc|auth|oauth|session|login|users?|accounts?|products?|orders?)[^"'`\s<>]*) (?P=quote)""",
        re.I | re.X,
    )
    RELATIVE_API_PATH_RE = re.compile(
        r"""(?P<quote>["'`])(?P<path>(?:api|graphql|gql|rest|v[0-9]+|rpc|trpc|auth|oauth|session)/(?:[^"'`\s<>]+))(?P=quote)""",
        re.I,
    )
    FETCH_RE = re.compile(
        r"""(?:fetch|axios\.(?:get|post|put|patch|delete)|\.(?:get|post|put|patch|delete))\s*\(\s*["'`](?P<path>[^"'`]+)["'`]""",
        re.I,
    )
    JS_TEMPLATE_RE = re.compile(r"\$\{\s*(?P<expr>[^}]+?)\s*\}")
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
        endpoint_by_key: dict[tuple[str, str, str], ApiEndpoint] = {}

        def add_route(path: str) -> None:
            if not path or path.startswith(("http://", "https://", "//")):
                absolute = normalize_url(base_url, path)
            else:
                absolute = normalize_url(base_url, path if path.startswith("/") else f"/{path}")
            if absolute not in seen_routes:
                seen_routes.add(absolute)
                routes.append(absolute)

        def add_endpoint(
            path: str,
            method: str = "GET",
            operation: str | None = None,
            evidence: str = "",
            request_body: Any = None,
            content_type: str | None = None,
        ) -> None:
            normalized_path = cls.normalize_template_url(path)
            absolute = normalize_url(base_url, normalized_path)
            key = (absolute, method.upper(), operation or "")
            existing = endpoint_by_key.get(key)
            if existing is not None:
                if request_body is not None and existing.request_body is None:
                    existing.request_body = request_body
                if content_type and not existing.content_type:
                    existing.content_type = content_type
                if evidence and existing.evidence != "fetch/xhr":
                    existing.evidence = evidence
                return

            if evidence == "fetch/xhr":
                for existing_key, existing_endpoint in list(endpoint_by_key.items()):
                    if (
                        existing_endpoint.url == absolute
                        and (existing_endpoint.operation or "") == (operation or "")
                        and existing_endpoint.evidence not in {"fetch/xhr", "graphql"}
                        and existing_endpoint.request_body is None
                    ):
                        endpoints.remove(existing_endpoint)
                        seen_endpoints.discard(existing_key)
                        endpoint_by_key.pop(existing_key, None)

            if key not in seen_endpoints:
                seen_endpoints.add(key)
                endpoint = ApiEndpoint(
                    url=absolute,
                    method=method.upper(),
                    source=RouteSource.javascript,
                    content_type=content_type,
                    operation=operation,
                    request_body=request_body,
                    evidence=evidence or path,
                )
                endpoint_by_key[key] = endpoint
                endpoints.append(endpoint)

        for match in cls.ENDPOINT_RE.finditer(script_text):
            path = match.group("path")
            add_endpoint(path, "POST" if cls._looks_state_changing(path) else "GET")

        for match in cls.RELATIVE_API_PATH_RE.finditer(script_text):
            path = match.group("path")
            add_endpoint(f"/{path}", "POST" if cls._looks_state_changing(path) else "GET")

        for match in cls.FETCH_RE.finditer(script_text):
            path = match.group("path")
            if cls._looks_api_path(path):
                body, content_type = cls._infer_request_schema_near(script_text, match.start())
                add_endpoint(
                    path,
                    cls._infer_method_near(script_text, match.start()),
                    evidence="fetch/xhr",
                    request_body=body,
                    content_type=content_type,
                )

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
                add_endpoint(path, "POST", operation=operation, evidence="graphql", request_body=script_text)

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

        for name, value in parse_qsl(parsed.query, keep_blank_values=True):
            if not name:
                continue
            baseline = value
            if re.fullmatch(r"\{[A-Za-z_][A-Za-z0-9_]*\}", value):
                baseline = "1"
            params.append(
                ParameterCandidate(
                    name=name,
                    location=ParameterLocation.query,
                    url=endpoint.url,
                    method=endpoint.method,
                    baseline_value=baseline or "1",
                    source="api_query",
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
    def normalize_template_url(cls, path: str) -> str:
        placeholder_index = 0

        def replacement(match: re.Match[str]) -> str:
            nonlocal placeholder_index
            placeholder_index += 1
            name = cls._placeholder_name(match.group("expr")) or f"param_{placeholder_index}"
            return "{" + name + "}"

        path = cls.JS_TEMPLATE_RE.sub(replacement, path)
        path = re.sub(r"\+\s*([A-Za-z_$][\w$]*)", lambda m: "{" + cls._placeholder_name(m.group(1)) + "}", path)
        path = re.sub(r"([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\+", "", path)
        if not path.startswith("/") and "/" in path:
            prefix, suffix = path.split("/", 1)
            if cls._looks_like_base_expression(prefix):
                path = "/" + suffix
        return path

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
    def _placeholder_name(expr: str) -> str:
        expr = expr.strip()
        if "." in expr:
            expr = expr.rsplit(".", 1)[-1]
        match = re.search(r"[A-Za-z_$][A-Za-z0-9_$]*", expr)
        if not match:
            return ""
        name = match.group(0).strip("$")
        if len(name) <= 1:
            return "param_1"
        return re.sub(r"[^A-Za-z0-9_]", "_", name)

    @staticmethod
    def _looks_like_base_expression(value: str) -> bool:
        lowered = value.strip("{}").lower()
        return lowered in {"baseurl", "apiurl", "host", "server", "hostserver"} or any(
            token in lowered for token in ("base", "api", "host", "server", "origin")
        )

    @classmethod
    def _infer_request_schema_near(cls, script_text: str, start: int) -> tuple[Any, str | None]:
        window = script_text[max(0, start - 800) : start + 1200]

        append_names = re.findall(r"\.append\s*\(\s*[\"'](?P<name>[A-Za-z_][A-Za-z0-9_-]*)[\"']", window)
        if "FormData" in window and append_names:
            return {name: cls._baseline_for_name(name) for name in append_names}, "multipart/form-data"

        search_params = re.findall(r"\.(?:set|append)\s*\(\s*[\"'](?P<name>[A-Za-z_][A-Za-z0-9_-]*)[\"']", window)
        if "URLSearchParams" in window and search_params:
            return {name: cls._baseline_for_name(name) for name in search_params}, "application/x-www-form-urlencoded"

        json_match = re.search(r"JSON\.stringify\s*\(\s*(?P<object>\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\})", window, re.S)
        if json_match:
            return cls._object_literal_template(json_match.group("object")), "application/json"

        object_match = re.search(r",\s*(?P<object>\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\})\s*\)?", window, re.S)
        if object_match and any(token in object_match.group("object").lower() for token in ("email", "password", "id", "query", "url", "name", "body")):
            return cls._object_literal_template(object_match.group("object")), "application/json"

        return None, None

    @classmethod
    def _object_literal_template(cls, literal: str) -> dict[str, Any]:
        template: dict[str, Any] = {}
        for match in re.finditer(r"(?:[\"'](?P<quoted>[^\"']+)[\"']|(?P<bare>[A-Za-z_$][A-Za-z0-9_$]*))\s*:", literal):
            key = match.group("quoted") or match.group("bare")
            if key:
                template[key] = cls._baseline_for_name(key)
        return template

    @staticmethod
    def _baseline_for_name(name: str) -> Any:
        lowered = name.lower()
        if lowered in {"id", "userid", "user_id", "accountid", "account_id", "orderid", "order_id", "quantity", "qty"}:
            return 1
        if lowered.endswith("id") or lowered.endswith("_id") or lowered.endswith("-id"):
            return 1
        if "email" in lowered:
            return "scanner@example.com"
        if "password" in lowered:
            return "Password123!"
        if "url" in lowered or "uri" in lowered:
            return "https://example.com/"
        if lowered in {"q", "query", "search", "term"}:
            return "test"
        if "file" in lowered:
            return "sample.txt"
        return "test"

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
