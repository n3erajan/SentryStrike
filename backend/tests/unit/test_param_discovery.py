import pytest

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
