import pytest

from app.core.crawler.param_discovery import ParamDiscovery

def test_param_discovery_path_only_url():
    # URL with no query parameters
    urls = ["http://example.com/api/users"]
    
    candidates = ParamDiscovery.build_candidates(urls, [], filter_fn=lambda x: True)
    
    # Should synthesize common params like 'id'
    params = [c.parameter for c in candidates]
    assert "id" in params
    assert "page" in params
    
def test_param_discovery_href_extraction():
    # Simulated href extraction in spider adds url with params
    urls = ["http://example.com/view?file=test.pdf"]
    
    candidates = ParamDiscovery.build_candidates(urls, [], filter_fn=lambda x: True)
    
    params = [c.parameter for c in candidates]
    assert "file" in params
