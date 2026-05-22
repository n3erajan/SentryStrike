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
        seen_keys = set()  # (url, param, method) dedup

        def _add_candidate(url: str, param: str, method: str, val: str, form_inputs=None):
            if filter_fn and not filter_fn(param):
                return
            key = (url, param, method)
            if key not in seen_keys:
                seen_keys.add(key)
                candidates.append((url, param, method, val, form_inputs))

        url_paths = set()

        # 1. Observed params
        for url in urls:
            parsed = urlparse(url)
            base_path_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))
            url_paths.add(base_path_url)

            query_params = parse_qsl(parsed.query, keep_blank_values=True)
            for param_name, param_value in query_params:
                _add_candidate(url, param_name, "GET", param_value)

        # 2. Form-derived params
        for form in forms:
            form_url = getattr(form, "action", getattr(form, "page_url", ""))
            form_method = getattr(form, "method", "POST").upper()
            form_inputs = list(getattr(form, "inputs", []))

            # Add the form's URL to paths for potential parameter synthesis later
            parsed_form = urlparse(form_url)
            base_form_path = urlunparse((parsed_form.scheme, parsed_form.netloc, parsed_form.path, '', '', ''))
            url_paths.add(base_form_path)

            for inp in form_inputs:
                inp_name = getattr(inp, "name", "")
                inp_type = getattr(inp, "input_type", "text").lower()

                if not inp_name or inp_type in cls.SKIP_INPUT_TYPES:
                    continue

                inp_value = getattr(inp, "value", "")
                if form_method == "GET":
                    _add_candidate(form_url, inp_name, "GET", inp_value)
                else:
                    _add_candidate(form_url, inp_name, form_method, inp_value, form_inputs)

        # 3. Path-only URL synthesis
        for path_url in url_paths:
            added_count = 0
            for param in cls.COMMON_PARAMS:
                if added_count >= cls.MAX_CANDIDATES_PER_URL:
                    break
                if filter_fn and not filter_fn(param):
                    continue
                
                key = (path_url, param, "GET")
                if key not in seen_keys:
                    seen_keys.add(key)
                    candidates.append((path_url, param, "GET", "1", None))
                    added_count += 1

        return candidates
