import pytest

from app.core.crawler.param_discovery import ParamDiscovery

def test_param_discovery_path_only_url():
    # URL with no query parameters
    urls = ["http://example.com/api/users"]
    
    candidates = ParamDiscovery.build_candidates(urls, [], filter_fn=lambda x: True)
    
    # Should synthesize common params like 'id'
    params = [c[1] for c in candidates]
    assert "id" in params
    assert "page" in params
    
def test_param_discovery_href_extraction():
    # Simulated href extraction in spider adds url with params
    urls = ["http://example.com/view?file=test.pdf"]
    
    candidates = ParamDiscovery.build_candidates(urls, [], filter_fn=lambda x: True)
    
    params = [c[1] for c in candidates]
    assert "file" in params
    # URL already has a query param — no wordlist guessing
    assert "user_id" not in params
    assert "search" not in params


def test_param_discovery_preserves_query_value():
    urls = ["http://example.com/sqli?id=1&Submit=Submit"]

    candidates = ParamDiscovery.build_candidates(urls, [], filter_fn=lambda x: True)

    id_candidates = [c for c in candidates if c[1] == "id"]
    assert len(id_candidates) == 1
    assert id_candidates[0][3] == "1"
    assert "user_id" not in [c[1] for c in candidates]


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
