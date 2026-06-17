import pytest

from app.core.crawler.models import ApiEndpoint, ParameterLocation
from app.core.crawler.api_extractor import ApiExtractor
from app.core.crawler.param_discovery import ParamDiscovery

def test_param_discovery_path_only_url_uses_contextual_hints():
    urls = ["http://example.com/api/users"]
    
    candidates = ParamDiscovery.build_candidates(urls, [], filter_fn=lambda x: True)
    
    # Should synthesize only route-relevant params like 'id'
    params = [c[1] for c in candidates]
    assert "id" in params
    assert "user_id" in params
    assert "page" not in params


def test_param_discovery_neutral_path_only_url_does_not_guess():
    urls = ["http://example.com/about.php"]

    candidates = ParamDiscovery.build_candidates(urls, [], filter_fn=lambda x: True)

    assert candidates == []


def test_param_discovery_broad_synthesis_mode_keeps_legacy_wordlist():
    urls = ["http://example.com/about.php"]

    candidates = ParamDiscovery.build_candidates(
        urls, [], filter_fn=lambda x: True, synthesis_mode="broad"
    )

    params = [c[1] for c in candidates]
    assert "id" in params
    assert "page" in params
    
def test_param_discovery_href_extraction():
    # Simulated href extraction in spider adds url with params
    urls = ["http://example.com/view?file=test.pdf"]
    
    candidates = ParamDiscovery.build_candidates(urls, [], filter_fn=lambda x: True)
    
    params = [c[1] for c in candidates]
    assert "file" in params
    # URL already has a query param - no wordlist guessing
    assert "user_id" not in params
    assert "search" not in params


def test_param_discovery_preserves_query_value():
    urls = ["http://example.com/sqli?id=1&Submit=Submit"]

    candidates = ParamDiscovery.build_candidates(urls, [], filter_fn=lambda x: True)

    id_candidates = [c for c in candidates if c[1] == "id"]
    assert len(id_candidates) == 1
    assert id_candidates[0][3] == "1"
    assert "user_id" not in [c[1] for c in candidates]


def test_param_discovery_ignores_blank_query_parameter_names():
    urls = ["http://example.com/debug.php?=PHPE9568F34-D428-11d2-A769-00AA001ACF42"]

    candidates = ParamDiscovery.build_candidates(urls, [], filter_fn=lambda x: True)

    assert candidates == []


def test_param_discovery_form_empty_value_defaults():
    class FakeInput:
        def __init__(self, name, type, value=""):
            self.name = name
            self.input_type = type
            self.value = value

    class FakeForm:
        action = "http://example.com/sqli/"
        method = "GET"
        inputs = [FakeInput("id", "text"), FakeInput("Submit", "submit")]

    candidates = ParamDiscovery.build_candidates([], [FakeForm()], filter_fn=lambda x: True)

    id_candidates = [c for c in candidates if c[1] == "id"]
    assert len(id_candidates) == 1
    assert id_candidates[0][3] == "1"
    assert "user_id" not in [c[1] for c in candidates]


def test_parameter_inventory_preserves_json_body_context():
    endpoint = ApiEndpoint(
        url="http://example.com/api/users",
        method="POST",
        request_body={"user": {"id": 7, "name": "alice"}, "redirectUrl": "/home"},
    )

    inventory = ParamDiscovery.build_parameter_inventory([], [], api_endpoints=[endpoint])

    by_name = {candidate.name: candidate for candidate in inventory}
    assert by_name["id"].location == ParameterLocation.json_body
    assert by_name["id"].parent_path == "user.id"
    assert "access_control" in by_name["id"].security_relevance
    assert "redirect_ssrf" in by_name["redirectUrl"].security_relevance


def test_api_extractor_finds_relative_rest_login_literal():
    script = 'this.http.post(this.hostServer+"rest/user/login", {email: e, password: p})'

    _, endpoints = ApiExtractor.extract_from_javascript("http://localhost:3000/", script)

    assert any(endpoint.url == "http://localhost:3000/rest/user/login" for endpoint in endpoints)


def test_api_extractor_normalizes_js_template_path_parameter():
    script = "fetch(`${this.hostServer}/rest/basket/${basketId}`)"

    _, endpoints = ApiExtractor.extract_from_javascript("http://localhost:3000/main.js", script)

    endpoint = next(endpoint for endpoint in endpoints if "/rest/basket/" in endpoint.url)
    assert endpoint.url == "http://localhost:3000/rest/basket/{basketId}"
    params = ApiExtractor.parameters_from_endpoint(endpoint)
    assert len(params) == 1
    assert params[0].name == "basketId"
    assert params[0].location == ParameterLocation.path
    assert "access_control" in params[0].security_relevance


def test_api_extractor_normalizes_js_template_query_parameter():
    script = "fetch(`${this.hostServer}/rest/products/search?q=${term}`)"

    _, endpoints = ApiExtractor.extract_from_javascript("http://localhost:3000/main.js", script)

    endpoint = next(endpoint for endpoint in endpoints if "/rest/products/search" in endpoint.url)
    assert endpoint.url == "http://localhost:3000/rest/products/search?q={term}"
    params = ApiExtractor.parameters_from_endpoint(endpoint)
    assert len(params) == 1
    assert params[0].name == "q"
    assert params[0].location == ParameterLocation.query
    assert "injection_xss" in params[0].security_relevance
