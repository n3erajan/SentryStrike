from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import parse_qs, parse_qsl, urlparse, urlunparse

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
    URL_STRING_RE = re.compile(r"""(?P<quote>["'`])(?P<path>/[^"'`\s<>]+)(?P=quote)""")
    # Client-side navigation sinks: location.assign("/x") / location.replace("/x")
    # / (window.)location.href = "/x" / window.location = "/x". Captures the quoted
    # absolute-path literal, tolerating a leading base concat (hostServer+"/x").
    # These are real server pages the app navigates to — safe to fetch (and parse
    # their forms) even when single-segment, unlike arbitrary quoted strings.
    NAV_SINK_RE = re.compile(
        r"""(?:location\s*\.\s*(?:assign|replace)\s*\(|"""
        r"""location(?:\s*\.\s*href)?\s*=)"""
        r"""[^"'`]{0,40}?["'`](?P<path>/[^"'`\s<>]*)["'`]""",
        re.I,
    )
    FETCH_RE = re.compile(
        r"""(?:(?P<axios>axios)\.(?P<axios_method>get|post|put|patch|delete)|fetch|\.(?P<chain_method>get|post|put|patch|delete))\s*\(\s*["'`](?P<path>[^"'`]+)["'`]""",
        re.I,
    )
    JQUERY_AJAX_RE = re.compile(r"""\$\.(?:ajax|get|post)\s*\(\s*(?P<args>\{.*?\}|["'`][^"'`]+["'`])""", re.I | re.S)
    ANGULAR_HTTP_RE = re.compile(
        r"""(?:http|HttpClient)\s*\.\s*(?P<method>get|post|put|patch|delete)\s*\(\s*["'`](?P<path>[^"'`]+)["'`]""",
        re.I,
    )
    # A verb call whose URL is a base-variable concat/template rather than a bare
    # string literal: ``.post(this.host + "/x", body)`` or ``.put(`${base}/x/${id}`)``.
    # The literal path tail is captured; the base var is resolved separately (see
    # ``_resolve_base_vars``) so ``/api``-style prefixes are recovered. Matching
    # both the fetch/axios and Angular ``HttpClient`` chains generically.
    BASE_CONCAT_VERB_RE = re.compile(
        r"""\.\s*(?P<method>get|post|put|patch|delete)\s*\(\s*"""
        r"""(?:`\$\{\s*(?P<tvar>[A-Za-z_$][\w$.]*)\s*\}(?P<ttail>[^`]*)`"""
        r"""|(?P<cvar>[A-Za-z_$][\w$.]*)\s*\+\s*["'](?P<ctail>[^"']*)["'])""",
        re.I,
    )
    # Assignment of a base-URL-ish variable to a string literal, optionally
    # prefixed by another base expression (``host = this.hostServer + "/api"``).
    # Only names that themselves look like a base/host/api var are considered.
    BASE_VAR_ASSIGN_RE = re.compile(
        r"""(?:(?:const|let|var)\s+|this\.)?(?P<name>[A-Za-z_$][\w$]*)\s*[:=]\s*"""
        r"""(?:(?P<base>[A-Za-z_$][\w$.]*)\s*\+\s*)?"""
        r"""["'`](?P<lit>[^"'`]*)["'`]""",
        re.I,
    )
    JS_TEMPLATE_RE = re.compile(r"\$\{\s*(?P<expr>[^}]+?)\s*\}")
    ROUTE_ARRAY_RE = re.compile(r"""path\s*:\s*["'`](?P<path>/[^"'`]+)["'`]""", re.I)
    REACT_ROUTER_RE = re.compile(r"""<Route[^>]+path\s*=\s*["'`](?P<path>/[^"'`]+)["'`]""", re.I)
    ANGULAR_ROUTE_RE = re.compile(r"""\{\s*path\s*:\s*["'`](?P<path>[^"'`]*)["'`]""", re.I)
    GRAPHQL_OP_RE = re.compile(r"""\b(query|mutation|subscription)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)""")
    GRAPHQL_VAR_RE = re.compile(r"""\$(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*:""")
    ROOT_RELATIVE_API_RE = re.compile(r"^(?:api|graphql|gql|rest|v[0-9]+|rpc|trpc|oauth|session)(?:/|$)", re.I)

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
            normalized_path = cls._canonical_api_path(normalized_path)
            absolute = normalize_url(base_url, normalized_path)
            key = (absolute, method.upper(), operation or "")
            existing = endpoint_by_key.get(key)
            if existing is not None:
                if request_body is not None and (
                    existing.request_body is None
                    or existing.evidence in {"", path}
                    or evidence in {"fetch/xhr", "angular-http", "jquery-ajax"}
                ):
                    existing.request_body = request_body
                if content_type and (
                    not existing.content_type
                    or existing.evidence in {"", path}
                    or evidence in {"fetch/xhr", "angular-http", "jquery-ajax"}
                ):
                    existing.content_type = content_type
                if evidence and existing.evidence != "fetch/xhr":
                    existing.evidence = evidence
                if method and existing.method.upper() == "GET" and method.upper() != "GET":
                    endpoints.remove(existing)
                    seen_endpoints.discard(key)
                    endpoint_by_key.pop(key, None)
                    key = (absolute, method.upper(), operation or "")
                    existing = None
                else:
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

        for match in cls.URL_STRING_RE.finditer(script_text):
            path = match.group("path")
            if not cls._looks_rest_string_path(path):
                continue
            add_endpoint(path, "POST" if cls._looks_state_changing(path) else "GET", evidence="js-url-string")
            parent = cls._rest_parent_path(path)
            if parent:
                add_endpoint(parent, "GET", evidence="rest-parent")

        for match in cls.NAV_SINK_RE.finditer(script_text):
            path = match.group("path")
            # Same-origin absolute page paths the app navigates to. add_route
            # resolves against base_url; the spider enforces same_domain, so an
            # off-origin absolute URL matched here is dropped downstream. Guard
            # protocol-relative (//host) explicitly since that is cross-origin.
            if path and path.startswith("/") and not path.startswith("//"):
                add_route(path)

        for match in cls.FETCH_RE.finditer(script_text):
            path = match.group("path")
            if cls._looks_api_path(path):
                body, content_type = cls._infer_request_schema_near(script_text, match.start())
                add_endpoint(
                    path,
                    (match.group("axios_method") or match.group("chain_method") or cls._infer_method_near(script_text, match.start())).upper(),
                    evidence="fetch/xhr",
                    request_body=body,
                    content_type=content_type,
                )

        for match in cls.ANGULAR_HTTP_RE.finditer(script_text):
            path = match.group("path")
            if cls._looks_api_path(path):
                body, content_type = cls._infer_request_schema_near(script_text, match.start())
                add_endpoint(
                    path,
                    match.group("method").upper(),
                    evidence="angular-http",
                    request_body=body,
                    content_type=content_type,
                )

        # Base-variable concat/template calls (body-coverage #3). A minified/dev
        # build often writes ``http.post(this.api + "/Feedbacks", body)`` or
        # ``http.put(`${base}/user/${id}`)`` where the literal tail alone carries
        # no /api|/rest token and so is dropped by the string-literal passes above.
        # Resolve the base var to its literal path prefix (only when unambiguous)
        # and reconstruct the full path so the endpoint is recovered. Bodies are
        # NOT invented here — a bare-variable body stays None (see plan #3).
        # A base var (``host``/``baseUrl``/…) is frequently REUSED across many
        # minified service classes, each binding it to a different resource path
        # (``host=this.hostServer+"/rest/products"`` in one, ``+"/api/Feedbacks"``
        # in another). The global resolver treats such a name as ambiguous and
        # drops it, losing every ``this.host + "/x"`` endpoint. So resolve each
        # concat call scope-locally too: the nearest preceding assignment of the
        # same name (the call's own class field in minified output) wins when the
        # name is globally ambiguous.
        base_vars = cls._resolve_base_vars(script_text)
        local_assignments = list(cls._iter_base_var_assignments(script_text))
        for match in cls.BASE_CONCAT_VERB_RE.finditer(script_text):
            var = match.group("tvar") or match.group("cvar") or ""
            tail = match.group("ttail")
            if tail is None:
                tail = match.group("ctail") or ""
            short = var.rsplit(".", 1)[-1]
            prefix = (
                base_vars.get(var)
                or base_vars.get(short)
                or cls._nearest_base_prefix(local_assignments, short, match.start())
            )
            if prefix is None:
                continue
            joined = prefix + (tail if tail.startswith("/") else f"/{tail}" if tail else "")
            # A template tail may still carry ``${id}`` interpolations — normalise
            # them to ``{name}`` path placeholders (a bare concat tail is unchanged).
            joined = cls.normalize_template_url(joined)
            if not cls._looks_api_path(joined):
                continue
            body, content_type = cls._infer_request_schema_near(script_text, match.start())
            add_endpoint(
                joined,
                match.group("method").upper(),
                evidence="base-concat",
                request_body=body,
                content_type=content_type,
            )

        for match in re.finditer(r"""\$\.ajax\s*\(\s*\{(?P<args>.*?)\}\s*\)""", script_text, re.I | re.S):
            args = match.group("args")
            path_match = re.search(r"""url\s*:\s*["'`](?P<path>[^"'`]+)["'`]""", args, re.I)
            if not path_match:
                continue
            path = path_match.group("path")
            if cls._looks_api_path(path):
                body, content_type = cls._infer_request_schema_near(script_text, match.start())
                data_match = re.search(r"""data\s*:\s*(?P<object>\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\})""", args, re.S | re.I)
                if data_match:
                    body, content_type = cls._object_literal_template(data_match.group("object")), "application/json"
                add_endpoint(
                    path,
                    cls._infer_method_from_ajax_args(args) or cls._infer_method_near(script_text, match.start()),
                    evidence="jquery-ajax",
                    request_body=body,
                    content_type=content_type,
                )

        for match in re.finditer(r"""\$\.post\s*\(\s*["'`](?P<path>[^"'`]+)["'`]""", script_text, re.I):
            path = match.group("path")
            if cls._looks_api_path(path):
                body, content_type = cls._infer_request_schema_near(script_text, match.start())
                add_endpoint(path, "POST", evidence="jquery-ajax", request_body=body, content_type=content_type)

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
    def extract_from_openapi(cls, base_url: str, document: Any) -> list[ApiEndpoint]:
        spec = cls._load_openapi_document(document)
        if not isinstance(spec, dict) or not isinstance(spec.get("paths"), dict):
            return []

        endpoints: list[ApiEndpoint] = []
        server_base = cls._openapi_server_base(base_url, spec)
        for path, path_item in spec.get("paths", {}).items():
            if not isinstance(path_item, dict):
                continue
            path_parameters = path_item.get("parameters", []) if isinstance(path_item.get("parameters"), list) else []
            for method, operation in path_item.items():
                method_upper = str(method).upper()
                if method_upper not in {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}:
                    continue
                if not isinstance(operation, dict):
                    continue
                parameters = path_parameters + (
                    operation.get("parameters", []) if isinstance(operation.get("parameters"), list) else []
                )
                url = cls._openapi_url_with_query(server_base, path, parameters)
                content_type, request_body = cls._openapi_request_body(operation)
                endpoints.append(
                    ApiEndpoint(
                        url=url,
                        method=method_upper,
                        source=RouteSource.api,
                        content_type=content_type,
                        operation=operation.get("operationId"),
                        request_body=request_body,
                        evidence="openapi",
                    )
                )
        return endpoints

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
        content_type = (endpoint.content_type or "").lower()
        if body is None and "application/x-www-form-urlencoded" in content_type:
            raw_body = endpoint.request_body
            if isinstance(raw_body, bytes):
                raw_body = raw_body.decode("utf-8", "ignore")
            if isinstance(raw_body, str):
                body = {
                    name: values[0] if values else ""
                    for name, values in parse_qs(raw_body, keep_blank_values=True).items()
                    if name
                }
        if body is None and "multipart/form-data" in content_type:
            multipart_fields = getattr(endpoint, "multipart_fields", []) or []
            if multipart_fields:
                body = {
                    field.get("name"): cls._baseline_for_name(field.get("name", ""))
                    for field in multipart_fields
                    if field.get("name")
                }
        if isinstance(body, dict) and (
            "application/x-www-form-urlencoded" in content_type
            or "multipart/form-data" in content_type
        ):
            for key, value in body.items():
                params.append(
                    ParameterCandidate(
                        name=key,
                        location=ParameterLocation.form,
                        url=endpoint.url,
                        method=endpoint.method,
                        baseline_value=value if not isinstance(value, (dict, list)) else "1",
                        content_type=endpoint.content_type,
                        source="api_form_body",
                        security_relevance=cls.classify_parameter(key),
                    )
                )
        elif isinstance(body, (dict, list)):
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
    def _canonical_api_path(cls, path: str) -> str:
        path = str(path or "")
        if path.startswith(("http://", "https://", "//", "/")):
            return path
        if cls.ROOT_RELATIVE_API_RE.match(path):
            return f"/{path}"
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
        if ApiExtractor.ROOT_RELATIVE_API_RE.match(lowered):
            return True
        return any(
            token in lowered
            for token in (
                "/api",
                "/graphql",
                "/gql",
                "/rest",
                "/oauth",
                "/session",
                "/auth",
                "/rpc",
                "/trpc",
                "/login",
                "/logout",
                "/user",
                "/users",
                "/account",
                "/accounts",
                "/product",
                "/products",
                "/order",
                "/orders",
            )
        )

    _STATIC_PATH_EXTENSIONS = {
        ".css", ".js", ".mjs", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
        ".webp", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webm",
        ".pdf", ".txt", ".html", ".htm",
    }
    _REST_PARENT_PARAM_RE = re.compile(
        r"/(?:\{[A-Za-z_][A-Za-z0-9_]*\}|:[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[0-9a-fA-F]{16,}|[0-9a-fA-F-]{32,})$"
    )

    @classmethod
    def _looks_rest_string_path(cls, path: str) -> bool:
        """True for server-testable URL string literals found in JS bundles.

        This is deliberately structural: keep same-origin absolute paths that
        look like REST/API surfaces, and skip assets, templates, and UI routes.
        It catches endpoints such as ``/profile/image/url`` without hardcoding
        app-specific paths.
        """
        if not path.startswith("/") or path.startswith("//"):
            return False
        if any(token in path for token in ("${", "*", " ")):
            return False
        parsed = urlparse(path)
        lowered_path = parsed.path.lower()
        if not lowered_path or lowered_path == "/":
            return False
        if lowered_path.endswith(tuple(cls._STATIC_PATH_EXTENSIONS)):
            return False
        segments = [segment for segment in lowered_path.split("/") if segment]
        if not segments:
            return False
        if cls._looks_api_path(path):
            return True
        if any(re.fullmatch(r"v[0-9]+", segment) for segment in segments):
            return True
        if len(segments) >= 3 and all(cls._is_restish_segment(segment) for segment in segments):
            return True
        return False

    @staticmethod
    def _is_restish_segment(segment: str) -> bool:
        if not segment:
            return False
        if segment.startswith((".", "#")):
            return False
        if re.fullmatch(r"[a-z0-9][a-z0-9_-]*", segment):
            return True
        if re.fullmatch(r"\{[A-Za-z_][A-Za-z0-9_]*\}|:[A-Za-z_][A-Za-z0-9_]*", segment):
            return True
        return False

    @classmethod
    def _rest_parent_path(cls, path: str) -> str | None:
        parsed = urlparse(path)
        parent = cls._REST_PARENT_PARAM_RE.sub("", parsed.path.rstrip("/"))
        if parent and parent != parsed.path.rstrip("/") and parent != "/":
            return urlunparse(parsed._replace(path=parent, params="", query="", fragment=""))
        return None

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
    def _resolve_base_vars(cls, script_text: str) -> dict[str, str]:
        """Map base-URL-ish variable names to their resolved literal *path* prefix.

        Recovers the common ``const API = "/api"`` / ``this.baseUrl = "/rest"``
        pattern so a later ``http.post(API + "/Feedbacks", …)`` call can be emitted
        as ``/api/Feedbacks`` instead of being dropped. A base var may itself be a
        concat of another base var and a literal (``host = this.hostServer +
        "/api"``); those are resolved to just their literal tail's path so the tail
        segment (``/api``) is preserved.

        Framework-agnostic and deliberately conservative: a name is kept ONLY when
        every assignment to it across the whole script agrees on the same literal.
        Minified per-class fields frequently reuse a name (e.g. ``host`` bound to a
        different resource path in each service) — resolving an ambiguous name
        would fabricate wrong endpoints, so ambiguous names are dropped entirely.
        Only path-shaped literals (leading ``/`` or a bare ``api``/``rest``-style
        segment) are kept; absolute ``http(s)://`` origins collapse to their path.
        """
        candidates: dict[str, set[str]] = {}
        for _pos, name, prefix in cls._iter_base_var_assignments(script_text):
            candidates.setdefault(name, set()).add(prefix)
        # Keep only unambiguous names (single agreed literal across the script).
        return {name: next(iter(vals)) for name, vals in candidates.items() if len(vals) == 1}

    # Bounded backward window for scope-local base-var resolution. A minified
    # service class defines its own ``host=``/``baseUrl=`` field immediately
    # before its methods, so the nearest preceding assignment within this many
    # chars is that class's own field — the correct binding even when the same
    # name is reused by other classes (which the global resolver drops as
    # ambiguous). Generous because a class's own field is always the closest
    # preceding one; the bound only guards against grabbing an unrelated prior
    # class's field in the pathological case of a scope that never binds the var.
    _BASE_VAR_SCOPE_WINDOW = 8000

    @classmethod
    def _iter_base_var_assignments(cls, script_text: str):
        """Yield ``(pos, name, path_prefix)`` for every base-URL-ish var assignment.

        Shared by the global unambiguous resolver (:meth:`_resolve_base_vars`)
        and the scope-local nearest-preceding resolver
        (:meth:`_nearest_base_prefix`). ``name`` is the bare identifier;
        ``path_prefix`` is the literal collapsed to a path prefix (leading ``/``,
        no trailing ``/``). Absolute origins collapse to their path portion.
        """
        for match in cls.BASE_VAR_ASSIGN_RE.finditer(script_text):
            name = match.group("name")
            if not name or not cls._looks_like_base_expression(name):
                continue
            literal = match.group("lit")
            if literal is None:
                continue
            if literal.startswith("//"):
                literal = urlparse("https:" + literal).path
            elif literal.startswith(("http://", "https://")):
                literal = urlparse(literal).path
            if not literal:
                continue
            if not literal.startswith("/") and not cls.ROOT_RELATIVE_API_RE.match(literal):
                continue
            prefix = (literal if literal.startswith("/") else f"/{literal}").rstrip("/")
            if prefix:
                yield match.start(), name, prefix

    @classmethod
    def _nearest_base_prefix(
        cls, assignments: list[tuple[int, str, str]], name: str, pos: int
    ) -> str | None:
        """Resolve a base var to its nearest preceding same-name assignment.

        ``assignments`` is the position-sorted ``(pos, name, prefix)`` list from
        :meth:`_iter_base_var_assignments`. Returns the prefix of the closest
        assignment of ``name`` occurring before ``pos`` within
        ``_BASE_VAR_SCOPE_WINDOW`` chars (the call's own class scope in minified
        output), or ``None`` when none is in range.
        """
        best: str | None = None
        for a_pos, a_name, a_prefix in assignments:
            if a_pos >= pos:
                break
            if a_name != name or pos - a_pos > cls._BASE_VAR_SCOPE_WINDOW:
                continue
            best = a_prefix
        return best

    @classmethod
    def _infer_request_schema_near(cls, script_text: str, start: int) -> tuple[Any, str | None]:
        prefix = script_text[max(0, start - 800) : start]
        suffix = script_text[start : start + 1200]
        terminator = suffix.find(";")
        if 0 <= terminator < 600:
            suffix = suffix[: terminator + 1]
        window = prefix + suffix

        body_var_match = re.search(r""",\s*(?P<var>[A-Za-z_$][\w$]*)\s*[\),]""", suffix)
        if body_var_match:
            body_var = body_var_match.group("var")
            var_window = script_text[max(0, start - 1200) : start + 200]
            var_kind_match = re.search(
                rf"""{re.escape(body_var)}\s*=\s*new\s*(?P<kind>FormData|URLSearchParams)\s*\(""",
                var_window,
                re.I,
            )
            var_fields = re.findall(
                rf"""{re.escape(body_var)}\.(?:set|append)\s*\(\s*["'](?P<name>[A-Za-z_][A-Za-z0-9_-]*)["']""",
                var_window,
            )
            if var_kind_match and var_fields:
                kind = var_kind_match.group("kind").lower()
                content_type = "multipart/form-data" if kind == "formdata" else "application/x-www-form-urlencoded"
                return {name: cls._baseline_for_name(name) for name in var_fields}, content_type

        search_params = re.findall(r"\.(?:set|append)\s*\(\s*[\"'](?P<name>[A-Za-z_][A-Za-z0-9_-]*)[\"']", window)
        suffix_lower = suffix.lower()
        if "urlsearchparams" in window.lower() and search_params and (
            "urlsearchparams" in suffix_lower or re.search(r"""\(\s*[A-Za-z_$][\w$]*\s*\)""", suffix)
        ):
            return {name: cls._baseline_for_name(name) for name in search_params}, "application/x-www-form-urlencoded"

        append_names = re.findall(r"\.append\s*\(\s*[\"'](?P<name>[A-Za-z_][A-Za-z0-9_-]*)[\"']", window)
        if "FormData" in window and append_names:
            return {name: cls._baseline_for_name(name) for name in append_names}, "multipart/form-data"

        json_match = re.search(r"JSON\.stringify\s*\(\s*(?P<object>\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\})", window, re.S)
        if json_match:
            return cls._object_literal_template(json_match.group("object")), "application/json"

        body_match = re.search(
            r"""(?:body|data|params)\s*:\s*(?:JSON\.stringify\s*\()?(?P<object>\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\})""",
            window,
            re.S | re.I,
        )
        if body_match:
            content_type = "application/json"
            if "urlsearchparams" in window.lower():
                content_type = "application/x-www-form-urlencoded"
            return cls._object_literal_template(body_match.group("object")), content_type

        object_match = re.search(r",\s*(?P<object>\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\})\s*\)?", window, re.S)
        if object_match and any(token in object_match.group("object").lower() for token in ("email", "password", "id", "query", "url", "name", "body")):
            return cls._object_literal_template(object_match.group("object")), "application/json"

        return None, None

    @staticmethod
    def _infer_method_from_ajax_args(args: str) -> str | None:
        match = re.search(r"""(?:method|type)\s*:\s*["'`](get|post|put|patch|delete)["'`]""", args, re.I)
        return match.group(1).upper() if match else None

    @classmethod
    def _load_openapi_document(cls, document: Any) -> Any:
        if isinstance(document, dict):
            return document
        if not isinstance(document, str) or not document.strip():
            return None
        try:
            return json.loads(document)
        except Exception:
            pass
        try:
            import yaml

            return yaml.safe_load(document)
        except Exception:
            return None

    @staticmethod
    def _openapi_server_base(base_url: str, spec: dict[str, Any]) -> str:
        servers = spec.get("servers")
        if isinstance(servers, list) and servers:
            first = servers[0]
            if isinstance(first, dict) and isinstance(first.get("url"), str):
                return normalize_url(base_url, first["url"])
        return base_url

    @classmethod
    def _openapi_url_with_query(cls, base_url: str, path: str, parameters: list[Any]) -> str:
        query_parts: list[str] = []
        for parameter in parameters:
            if not isinstance(parameter, dict):
                continue
            name = parameter.get("name")
            if parameter.get("in") == "query" and isinstance(name, str):
                query_parts.append(f"{name}={cls._baseline_for_schema(parameter.get('schema', {}), name)}")
        query = "&".join(query_parts)
        absolute = normalize_url(base_url, path)
        return f"{absolute}?{query}" if query else absolute

    @classmethod
    def _openapi_request_body(cls, operation: dict[str, Any]) -> tuple[str | None, Any]:
        request_body = operation.get("requestBody")
        if not isinstance(request_body, dict):
            return None, None
        content = request_body.get("content")
        if not isinstance(content, dict):
            return None, None
        preferred = [
            "application/json",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
        ]
        content_type = next((item for item in preferred if item in content), next(iter(content), None))
        media = content.get(content_type) if content_type else None
        schema = media.get("schema") if isinstance(media, dict) else None
        return content_type, cls._template_from_schema(schema)

    @classmethod
    def _template_from_schema(cls, schema: Any, name_hint: str = "value") -> Any:
        if not isinstance(schema, dict):
            return cls._baseline_for_name(name_hint)
        if "$ref" in schema:
            return cls._baseline_for_name(name_hint)
        schema_type = schema.get("type")
        if schema_type == "object" or isinstance(schema.get("properties"), dict):
            return {
                name: cls._template_from_schema(child, name)
                for name, child in schema.get("properties", {}).items()
            }
        if schema_type == "array":
            return [cls._template_from_schema(schema.get("items", {}), name_hint)]
        return cls._baseline_for_schema(schema, name_hint)

    # Method families that carry a request body when injecting.
    _BODY_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
    _BODY_CONTENT_TYPES = (
        "application/json",
        "application/x-www-form-urlencoded",
        "multipart/form-data",
    )
    # Generic REST verbs that imply a mutating body even without a declared schema.
    _BODY_PATH_HINTS = (
        "login",
        "register",
        "signup",
        "signin",
        "create",
        "update",
        "add",
        "new",
        "save",
        "submit",
        "post",
        "checkout",
        "order",
        "comment",
        "feedback",
        "review",
        "upload",
        "token",
    )

    # Generic API path-token families (matched as whole path tokens, never as a
    # full path) that mark an endpoint as a genuine JSON/RPC API surface rather
    # than an SPA HTML navigation route. No application-specific literal.
    _API_PATH_TOKENS = frozenset(
        {"api", "rest", "graphql", "gql", "rpc", "trpc", "v1", "v2", "v3", "json"}
    )
    _API_CONTENT_TYPES = ("json", "x-www-form-urlencoded", "multipart", "graphql")
    _PATH_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")

    @classmethod
    def is_api_endpoint(cls, endpoint: ApiEndpoint) -> bool:
        """Return True when ``endpoint`` is a genuine API/JSON/form endpoint.

        Task C (RC-C): body-injection synthesis must target real API endpoints,
        never SPA HTML navigation routes (a ``POST /login`` Angular *route* that
        returns the 200 HTML shell exercises no vulnerable code). An endpoint is
        API-like when **any** generic signal holds — all key on structure/token
        families, never a full path:

        * declared/observed content-type is JSON/form/multipart/graphql,
        * it carries a ``body_schema`` / ``multipart_fields`` / ``request_body``,
        * a path token belongs to the generic API family (api/rest/graphql/v1…),
        * it was sourced from XHR/fetch/JS mining rather than an ``<a href>`` link.

        Endpoints whose only evidence is an HTML navigation route (static
        html/sitemap/robots source with no body signal) — or whose observed
        response content-type is ``text/html`` — are **not** API-like. Ambiguous
        endpoints (no content-type, no schema, no api token) default to False so
        placeholder bodies are never sprayed at HTML routes.
        """
        content_type = (endpoint.content_type or "").lower()

        # Strong structural body signals.
        if endpoint.body_schema or endpoint.multipart_fields:
            return True
        if endpoint.request_body not in (None, "", {}, []):
            return True

        # Content-type signals (declared or observed request body type).
        if any(ct in content_type for ct in cls._API_CONTENT_TYPES):
            return True

        # Explicit HTML exclusion: a navigation route that returns/declares HTML
        # is never an API endpoint regardless of other weak signals.
        evidence = (endpoint.evidence or "").lower()
        if "text/html" in content_type or "text/html" in evidence:
            return False

        # Generic API path token family.
        try:
            path = urlparse(endpoint.url).path.lower()
        except Exception:
            path = ""
        tokens = {tok for tok in cls._PATH_TOKEN_SPLIT_RE.split(path) if tok}
        if tokens & cls._API_PATH_TOKENS:
            return True

        # Provenance: mined from XHR/fetch/JS rather than a static <a href> link.
        # Browser-derived endpoints come from real XHR/fetch observations; JS/api
        # sources come from fetch/axios/HttpClient mining. Static html/sitemap/
        # robots sources are navigation routes and do not qualify on their own.
        if endpoint.source in {RouteSource.browser, RouteSource.api}:
            return True
        if endpoint.source == RouteSource.javascript and any(
            tok in evidence for tok in ("xhr", "fetch", "axios", "http", "graphql", "ajax")
        ):
            return True

        return False

    @classmethod
    def synthesize_body_schema(
        cls, endpoint: ApiEndpoint, *, allow_generic_body: bool = False
    ) -> tuple[str | None, Any]:
        """Synthesize a skeleton request body for body-injection detectors.

        Returns ``(content_type, body_template)`` when a body can be inferred, or
        ``(None, None)`` when the endpoint should not carry a synthesized body
        (e.g. GET, or a mutating method with no usable signal). The template is
        built from statically-known signals in priority order:

        1. an already-declared/observed ``request_body`` (dict/list),
        2. ``body_schema`` (a list of leaf field names),
        3. ``multipart_fields`` metadata,
        4. a single generic ``{"data": <placeholder>}`` when the method implies a
           body *and* a body content-type or path hint is present.

        ``allow_generic_body`` widens step 4 to fire for any body-implying method
        even without a content-type/path hint. It is opt-in for callers that have
        *already* confirmed the endpoint is a genuine API surface (via
        :meth:`is_api_endpoint`); without it, a mutating API endpoint carrying no
        static schema at all gets zero body-injection coverage whenever the
        browser observed no request body (RC3). Default stays conservative so
        placeholder bodies are never sprayed at unconfirmed/HTML routes.

        Placeholders are inferred generically from field-name tokens; no
        application-specific names or payloads are used.
        """
        method = (endpoint.method or "GET").upper()
        content_type = (endpoint.content_type or "").lower()
        is_body_ct = any(ct in content_type for ct in cls._BODY_CONTENT_TYPES)
        implies_body = method in cls._BODY_METHODS
        if method == "GET" or (not implies_body and not is_body_ct):
            return None, None

        # Priority 1: declared/observed body.
        body = endpoint.request_body
        if isinstance(body, str):
            try:
                body = json.loads(body)
            except Exception:
                body = None
        if isinstance(body, (dict, list)) and body:
            return endpoint.content_type or "application/json", body

        # Priority 2: a flat list of leaf field names.
        schema = list(getattr(endpoint, "body_schema", None) or [])
        if schema:
            template = {name: cls._baseline_for_name(name) for name in schema if name}
            if template:
                return endpoint.content_type or "application/json", template

        # Priority 3: multipart field metadata.
        multipart = list(getattr(endpoint, "multipart_fields", None) or [])
        if multipart:
            template = {
                field.get("name"): cls._baseline_for_name(field.get("name", ""))
                for field in multipart
                if isinstance(field, dict) and field.get("name")
            }
            if template:
                return endpoint.content_type or "multipart/form-data", template

        # Priority 4: generic single-leaf fallback. By default this fires only
        # with an explicit body hint (declared body content-type or a mutating
        # path verb) so we never spray placeholder bodies at every endpoint.
        # ``allow_generic_body`` opts a caller-confirmed API endpoint in even
        # without such a hint, so a genuine mutating API surface with no static
        # schema still gets one low-confidence body target (RC3).
        if is_body_ct or cls._path_hints_body(endpoint.url) or allow_generic_body:
            return endpoint.content_type or "application/json", {"data": cls._baseline_for_name("data")}
        return None, None

    @classmethod
    def _path_hints_body(cls, url: str) -> bool:
        try:
            path = urlparse(url).path.lower()
        except Exception:
            return False
        return any(hint in path for hint in cls._BODY_PATH_HINTS)

    @classmethod
    def _baseline_for_schema(cls, schema: Any, name_hint: str) -> Any:
        if isinstance(schema, dict):
            if "example" in schema:
                return schema["example"]
            if "default" in schema:
                return schema["default"]
            schema_type = schema.get("type")
            if schema_type in {"integer", "number"}:
                return 1
            if schema_type == "boolean":
                return True
        return cls._baseline_for_name(name_hint)

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
        if "message" in lowered:
            return "Scanner test message"
        if "comment" in lowered:
            return "Scanner test comment"
        if lowered in {"name", "title", "displayname", "display_name"}:
            return "Scanner Test"
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

    @classmethod
    def extract_storage_keys(cls, script_text: str) -> set[str]:
        keys = set()
        # 1. Direct string literals in setItem/getItem/removeItem
        pattern_direct = re.compile(
            r"""(?:localStorage|sessionStorage)\s*\.\s*(?:setItem|getItem|removeItem)\s*\(\s*["'`](?P<key>[a-zA-Z0-9_$_\-]+)["'`]""",
            re.I
        )
        for match in pattern_direct.finditer(script_text):
            keys.add(match.group("key"))

        # 2. Variable references in setItem/getItem/removeItem
        pattern_var = re.compile(
            r"""(?:localStorage|sessionStorage)\s*\.\s*(?:setItem|getItem|removeItem)\s*\(\s*(?P<var>[A-Za-z_$][A-Za-z0-9_$]*)\b""",
            re.I
        )
        for match in pattern_var.finditer(script_text):
            var_name = match.group("var")
            # Search for variable definition, e.g. const USER_KEY = "sentrystrike_user";
            var_def_pattern = re.compile(
                r"""\b(?:const|let|var)\s+""" + re.escape(var_name) + r"""\s*=\s*["'`](?P<val>[a-zA-Z0-9_$_\-]+)["'`]""",
                re.I
            )
            for def_match in var_def_pattern.finditer(script_text):
                keys.add(def_match.group("val"))

        # 3. Generic setItem/getItem with literals
        pattern_generic = re.compile(
            r"""\b(?:setItem|getItem|removeItem)\s*\(\s*["'`](?P<key>[a-zA-Z0-9_$_\-]+)["'`]""",
            re.I
        )
        for match in pattern_generic.finditer(script_text):
            key = match.group("key")
            if any(hint in key.lower() for hint in ("token", "jwt", "auth", "session", "user", "id_token", "access_token")):
                keys.add(key)

        return keys

