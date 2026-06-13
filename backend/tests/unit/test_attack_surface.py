from app.core.crawler.models import ApiEndpoint, ParameterLocation, RequestObservation
from app.core.detectors.attack_surface import AttackSurface, build_json_body


def test_attack_surface_preserves_json_template_from_api_endpoint():
    endpoint = ApiEndpoint(
        url="http://example.com/api/search",
        method="POST",
        request_body={"query": "alice", "filters": {"user_id": 7}},
        headers={"Content-Type": "application/json"},
    )

    targets = AttackSurface.build(
        ["http://example.com/api/search?query=alice"],
        [],
        api_endpoints=[endpoint],
        filter_fn=lambda name: name in {"query", "user_id"},
    )

    json_targets = [target for target in targets if target.location == ParameterLocation.json_body]
    assert {target.parent_path for target in json_targets} >= {"query", "filters.user_id"}

    user_id_target = next(target for target in json_targets if target.parent_path == "filters.user_id")
    body = build_json_body(user_id_target.json_template, user_id_target, "9 OR 1=1")
    assert body["filters"]["user_id"] == "9 OR 1=1"
    assert body["query"] == "alice"


def test_attack_surface_extracts_browser_observed_json_request():
    request = RequestObservation(
        url="http://example.com/api/products",
        method="POST",
        request_headers={"content-type": "application/json"},
        post_data='{"name":"juice","url":"http://example.org"}',
    )

    targets = AttackSurface.build([], [], requests=[request], filter_fn=lambda name: name == "url")

    assert len(targets) == 1
    target = targets[0]
    assert target.location == ParameterLocation.json_body
    assert target.source == "browser_request"
    assert build_json_body(target.json_template, target, "http://127.0.0.1/")["url"] == "http://127.0.0.1/"
