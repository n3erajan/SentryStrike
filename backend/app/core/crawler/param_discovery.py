import logging
import re
from urllib.parse import parse_qsl, urlparse, urlunparse

from app.core.crawler.api_extractor import ApiExtractor
from app.core.crawler.models import ApiEndpoint, ParameterCandidate, ParameterLocation

logger = logging.getLogger(__name__)

class ParamDiscovery:
    """
    ParamDiscovery synthesizes injection candidates by inspecting discovered URLs
    and forms. Path-only URL synthesis is intentionally conservative: the
    scanner only guesses names when the route itself provides a strong hint.
    """

    COMMON_PARAMS = [
        "id", "user_id", "name", "page", "file", "path", "cat", "category",
        "item", "search", "q", "query", "sort", "order", "lang", "template",
        "doc", "view", "redirect", "url", "default"
    ]
    
    MAX_CANDIDATES_PER_URL = 8
    MAX_CONTEXTUAL_CANDIDATES_PER_URL = 3
    SKIP_INPUT_TYPES = {"submit", "button", "reset", "image", "file", "checkbox", "radio"}
    DEFAULT_BASELINE_VALUE = "1"

    CONTEXTUAL_PARAM_HINTS = (
        ({"download", "downloads", "file", "files", "attachment", "attachments", "asset", "assets", "document", "documents", "doc", "docs", "export"}, ("file", "path", "doc")),
        ({"include", "includes", "template", "templates", "load", "loader", "view", "render"}, ("page", "template", "view")),
        ({"search", "find", "lookup", "query", "results"}, ("q", "query", "search")),
        ({"redirect", "return", "goto", "continue", "out", "link", "links", "url"}, ("url", "next", "return")),
        ({"user", "users", "account", "accounts", "profile", "profiles", "member", "members", "customer", "customers"}, ("id", "user_id")),
        ({"product", "products", "item", "items", "order", "orders", "invoice", "invoices", "post", "posts", "article", "articles"}, ("id", "item")),
        ({"category", "categories", "cat", "tag", "tags"}, ("category", "cat")),
    )

    @classmethod
    def _baseline_value(cls, param_name: str, observed: str) -> str:
        """Use the observed value; fall back to a sensible default when empty."""
        if observed:
            return observed
        return cls.DEFAULT_BASELINE_VALUE

    @classmethod
    def _path_tokens(cls, path: str) -> set[str]:
        """Extract normalized route words from a URL path."""
        tokens: set[str] = set()
        for segment in path.split("/"):
            if not segment:
                continue

            segment = segment.rsplit(".", 1)[0]
            for token in re.split(r"[^A-Za-z0-9]+", segment):
                token = token.strip().lower()
                if token:
                    tokens.add(token)
        return tokens

    @classmethod
    def _contextual_params_for_path(cls, path: str) -> list[str]:
        """
        Return a small set of guessed params only when the path gives a strong
        semantic hint. Neutral routes like /about.php intentionally return [].
        """
        tokens = cls._path_tokens(path)
        if not tokens:
            return []

        params: list[str] = []
        seen: set[str] = set()
        for route_hints, hinted_params in cls.CONTEXTUAL_PARAM_HINTS:
            if tokens.isdisjoint(route_hints):
                continue
            for param in hinted_params:
                if param in seen:
                    continue
                seen.add(param)
                params.append(param)
                if len(params) >= cls.MAX_CONTEXTUAL_CANDIDATES_PER_URL:
                    return params
        return params

    @classmethod
    def build_candidates(
        cls,
        urls: list[str],
        forms: list[object],
        filter_fn=None,
        synthesis_mode: str = "contextual",
        api_endpoints: list[ApiEndpoint] | None = None,
    ) -> list[tuple]:
        """
        Build injection candidates using observed parameters, forms, and synthesis.
        
        Args:
            urls: List of crawled URLs.
            forms: List of HtmlForm objects.
            filter_fn: Callable taking a parameter name and returning True to include it.
            synthesis_mode: "contextual" guesses a tiny, route-derived set for
                path-only URLs; "broad" uses the legacy common parameter list;
                "off" disables synthesis.
            
        Returns:
            List of 5-tuples: (url, parameter, method, baseline_value, form_inputs)
        """
        inventory = cls.build_parameter_inventory(
            urls,
            forms,
            filter_fn=filter_fn,
            synthesis_mode=synthesis_mode,
            api_endpoints=api_endpoints,
        )
        return [candidate.legacy_tuple(candidate.context.get("form_inputs")) for candidate in inventory]

    @classmethod
    def build_parameter_inventory(
        cls,
        urls: list[str],
        forms: list[object],
        filter_fn=None,
        synthesis_mode: str = "contextual",
        api_endpoints: list[ApiEndpoint] | None = None,
    ) -> list[ParameterCandidate]:
        """Build rich, context-preserving parameter candidates.

        Existing detectors call ``build_candidates`` and receive the legacy
        tuple format. Newer modules should use this method so location, content
        type, JSON path, and security relevance are preserved.
        """
        candidates: list[ParameterCandidate] = []
        seen_keys: set[tuple[str, str, str]] = set()  # (url, param, method) dedup
        paths_with_params: set[str] = set()

        def _add_candidate(
            url: str,
            param: str,
            method: str,
            val: object,
            form_inputs=None,
            location: ParameterLocation = ParameterLocation.query,
            source: str = "observed",
            parent_path: str | None = None,
            content_type: str | None = None,
        ):
            if not param or not param.strip():
                return
            if filter_fn and not filter_fn(param):
                return
            key = (url, param, method)
            baseline = cls._baseline_value(param, val)
            if key in seen_keys:
                # Prefer a non-empty observed value over an earlier empty one.
                for i, existing in enumerate(candidates):
                    if (existing.url, existing.name, existing.method) == key and not existing.baseline_value and baseline:
                        existing.baseline_value = baseline
                        if form_inputs:
                            existing.context["form_inputs"] = form_inputs
                return
            seen_keys.add(key)
            context = {"form_inputs": form_inputs} if form_inputs else {}
            candidates.append(
                ParameterCandidate(
                    name=param,
                    location=location,
                    url=url,
                    method=method,
                    baseline_value=baseline,
                    content_type=content_type,
                    parent_path=parent_path,
                    source=source,
                    security_relevance=ApiExtractor.classify_parameter(param),
                    context=context,
                )
            )

        url_paths = set()

        # 1. Observed params from URL query strings
        for url in urls:
            parsed = urlparse(url)
            base_path_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))
            url_paths.add(base_path_url)

            query_params = parse_qsl(parsed.query, keep_blank_values=True)
            if query_params:
                paths_with_params.add(base_path_url)
            for param_name, param_value in query_params:
                _add_candidate(url, param_name, "GET", param_value, location=ParameterLocation.query, source="query")

        # 2. Form-derived params
        for form in forms:
            form_url = getattr(form, "action", getattr(form, "page_url", ""))
            form_method = getattr(form, "method", "POST").upper()
            form_inputs = list(getattr(form, "inputs", []))

            parsed_form = urlparse(form_url)
            base_form_path = urlunparse((parsed_form.scheme, parsed_form.netloc, parsed_form.path, '', '', ''))
            url_paths.add(base_form_path)

            has_injectable_input = False
            for inp in form_inputs:
                inp_name = getattr(inp, "name", "")
                inp_type = getattr(inp, "input_type", "text").lower()

                if not inp_name or inp_type in cls.SKIP_INPUT_TYPES:
                    continue

                has_injectable_input = True
                inp_value = getattr(inp, "value", "")
                if form_method == "GET":
                    _add_candidate(form_url, inp_name, "GET", inp_value, form_inputs, location=ParameterLocation.form, source="form")
                else:
                    _add_candidate(form_url, inp_name, form_method, inp_value, form_inputs, location=ParameterLocation.form, source="form")

            if has_injectable_input:
                paths_with_params.add(base_form_path)

        # 3. Conservative synthesis only when no params were found for this path.
        for path_url in url_paths:
            if synthesis_mode == "off":
                continue
            if path_url in paths_with_params:
                continue

            parsed_path = urlparse(path_url)
            if synthesis_mode == "broad":
                synthesis_params = cls.COMMON_PARAMS
                max_candidates = cls.MAX_CANDIDATES_PER_URL
            else:
                synthesis_params = cls._contextual_params_for_path(parsed_path.path)
                max_candidates = cls.MAX_CONTEXTUAL_CANDIDATES_PER_URL

            added_count = 0
            for param in synthesis_params:
                if added_count >= max_candidates:
                    break
                if filter_fn and not filter_fn(param):
                    continue

                key = (path_url, param, "GET")
                if key not in seen_keys:
                    seen_keys.add(key)
                    candidates.append(
                        ParameterCandidate(
                            name=param,
                            location=ParameterLocation.query,
                            url=path_url,
                            method="GET",
                            baseline_value=cls.DEFAULT_BASELINE_VALUE,
                            source=f"synthesized_{synthesis_mode}",
                            security_relevance=ApiExtractor.classify_parameter(param),
                        )
                    )
                    added_count += 1

        for endpoint in api_endpoints or []:
            for parameter in ApiExtractor.parameters_from_endpoint(endpoint):
                if filter_fn and not filter_fn(parameter.name):
                    continue
                key = (parameter.url, parameter.name, parameter.method)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                candidates.append(parameter)

        return candidates
