import logging
from urllib.parse import parse_qsl, urlparse, urlunparse

logger = logging.getLogger(__name__)

class ParamDiscovery:
    """
    ParamDiscovery synthesizes injection candidates by inspecting discovered URLs
    and forms, and by probing common parameter names on path-only URLs.
    """

    COMMON_PARAMS = [
        "id", "user_id", "name", "page", "file", "path", "cat", "category",
        "item", "search", "q", "query", "sort", "order", "lang", "template",
        "doc", "view", "redirect", "url", "default"
    ]
    
    MAX_CANDIDATES_PER_URL = 8
    SKIP_INPUT_TYPES = {"submit", "button", "reset", "image", "file", "checkbox", "radio"}
    DEFAULT_BASELINE_VALUE = "1"

    @classmethod
    def _baseline_value(cls, param_name: str, observed: str) -> str:
        """Use the observed value; fall back to a sensible default when empty."""
        if observed:
            return observed
        return cls.DEFAULT_BASELINE_VALUE

    @classmethod
    def build_candidates(cls, urls: list[str], forms: list[object], filter_fn=None) -> list[tuple]:
        """
        Build injection candidates using observed parameters, forms, and synthesis.
        
        Args:
            urls: List of crawled URLs.
            forms: List of HtmlForm objects.
            filter_fn: Callable taking a parameter name and returning True to include it.
            
        Returns:
            List of 5-tuples: (url, parameter, method, baseline_value, form_inputs)
        """
        candidates = []
        seen_keys: set[tuple[str, str, str]] = set()  # (url, param, method) dedup
        paths_with_params: set[str] = set()

        def _add_candidate(url: str, param: str, method: str, val: str, form_inputs=None):
            if filter_fn and not filter_fn(param):
                return
            key = (url, param, method)
            baseline = cls._baseline_value(param, val)
            if key in seen_keys:
                # Prefer a non-empty observed value over an earlier empty one.
                for i, existing in enumerate(candidates):
                    if (existing[0], existing[1], existing[2]) == key and not existing[3] and baseline:
                        candidates[i] = (url, param, method, baseline, form_inputs or existing[4])
                return
            seen_keys.add(key)
            candidates.append((url, param, method, baseline, form_inputs))

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
                _add_candidate(url, param_name, "GET", param_value)

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
                    _add_candidate(form_url, inp_name, "GET", inp_value, form_inputs)
                else:
                    _add_candidate(form_url, inp_name, form_method, inp_value, form_inputs)

            if has_injectable_input:
                paths_with_params.add(base_form_path)

        # 3. Wordlist synthesis only when no params were found for this path
        for path_url in url_paths:
            if path_url in paths_with_params:
                continue
            added_count = 0
            for param in cls.COMMON_PARAMS:
                if added_count >= cls.MAX_CANDIDATES_PER_URL:
                    break
                if filter_fn and not filter_fn(param):
                    continue

                key = (path_url, param, "GET")
                if key not in seen_keys:
                    seen_keys.add(key)
                    candidates.append(
                        (path_url, param, "GET", cls.DEFAULT_BASELINE_VALUE, None)
                    )
                    added_count += 1

        return candidates
