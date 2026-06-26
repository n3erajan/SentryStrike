from __future__ import annotations

from app.core.crawler.api_extractor import ApiExtractor
from app.core.crawler.models import ApiEndpoint, ParameterLocation, RequestObservation
from app.core.detectors.attack_surface import AttackSurface, build_json_body


# --- synthesize_body_schema unit cases -------------------------------------------------


def test_synthesize_from_body_schema_field_names():
    endpoint = ApiEndpoint(url="http://x/rest/user/login", method="POST", body_schema=["email", "password"])
    content_type, template = ApiExtractor.synthesize_body_schema(endpoint)
    assert content_type == "application/json"
    assert set(template) == {"email", "password"}
    # placeholders inferred generically from field-name tokens
    assert "@" in str(template["email"])


def test_synthesize_skips_get():
    endpoint = ApiEndpoint(url="http://x/rest/products", method="GET", body_schema=["q"])
    assert ApiExtractor.synthesize_body_schema(endpoint) == (None, None)


def test_synthesize_prefers_declared_request_body():
    endpoint = ApiEndpoint(
        url="http://x/api/search",
        method="POST",
        request_body={"query": "alice", "filters": {"user_id": 7}},
    )
    content_type, template = ApiExtractor.synthesize_body_schema(endpoint)
    assert template == {"query": "alice", "filters": {"user_id": 7}}


def test_synthesize_from_multipart_fields():
    endpoint = ApiEndpoint(
        url="http://x/file-upload",
        method="POST",
        content_type="multipart/form-data",
        multipart_fields=[{"name": "avatarFile"}, {"name": "userId"}],
    )
    content_type, template = ApiExtractor.synthesize_body_schema(endpoint)
    assert "multipart/form-data" in content_type
    assert set(template) == {"avatarFile", "userId"}


def test_synthesize_generic_fallback_requires_hint():
    # POST with no schema and no body content-type and no path hint => no spraying.
    bare = ApiEndpoint(url="http://x/rest/basket", method="POST")
    assert ApiExtractor.synthesize_body_schema(bare) == (None, None)
    # POST whose path hints a mutating body => single generic leaf.
    hinted = ApiEndpoint(url="http://x/rest/user/login", method="POST")
    content_type, template = ApiExtractor.synthesize_body_schema(hinted)
    assert template == {"data": template["data"]}
    # POST declaring a JSON content-type => single generic leaf.
    ct_hinted = ApiEndpoint(url="http://x/rest/basket", method="POST", content_type="application/json")
    _, ct_template = ApiExtractor.synthesize_body_schema(ct_hinted)
    assert list(ct_template) == ["data"]


# --- AttackSurface.build synthesis pass ------------------------------------------------


def test_build_synthesizes_json_body_targets_from_schema():
    endpoint = ApiEndpoint(url="http://x/rest/user/login", method="POST", body_schema=["email", "password"])
    targets = AttackSurface.build([], [], api_endpoints=[endpoint])

    json_targets = [t for t in targets if t.location == ParameterLocation.json_body]
    assert {t.parameter for t in json_targets} == {"email", "password"}
    for target in json_targets:
        assert target.replayable is False
        assert target.source_confidence == "static_synth"
        # the synthesized template is injectable
        body = build_json_body(target.json_template, target, "' OR 1=1--")
        assert body[target.parameter] == "' OR 1=1--"


def test_build_synthesis_respects_filter_fn():
    endpoint = ApiEndpoint(url="http://x/rest/user/login", method="POST", body_schema=["email", "password"])
    targets = AttackSurface.build([], [], api_endpoints=[endpoint], filter_fn=lambda name: name == "email")
    assert {t.parameter for t in targets} == {"email"}


def test_build_synthesis_dedups_against_observed_request():
    endpoint = ApiEndpoint(url="http://x/rest/user/login", method="POST", body_schema=["email", "password"])
    observed = RequestObservation(
        url="http://x/rest/user/login",
        method="POST",
        request_headers={"content-type": "application/json"},
        request_content_type="application/json",
        post_data='{"email":"a@b.test","password":"pw"}',
        body_kind="json",
        replayable=True,
    )
    targets = AttackSurface.build([], [], api_endpoints=[endpoint], requests=[observed])
    # Observed body wins; nothing is marked static_synth for this endpoint.
    assert all(t.source_confidence != "static_synth" for t in targets)
    assert any(t.replayable for t in targets)


def test_build_synthesis_skips_get_endpoints():
    endpoint = ApiEndpoint(url="http://x/rest/products", method="GET", body_schema=["q"])
    targets = AttackSurface.build([], [], api_endpoints=[endpoint])
    assert all(t.source_confidence != "static_synth" for t in targets)


def test_build_synthesis_caps_leaves_per_endpoint():
    fields = [f"field_{i}" for i in range(40)]
    endpoint = ApiEndpoint(url="http://x/rest/thing/save", method="POST", body_schema=fields)
    targets = AttackSurface.build([], [], api_endpoints=[endpoint])
    synth = [t for t in targets if t.source_confidence == "static_synth"]
    assert len(synth) <= AttackSurface._SYNTH_LEAF_CAP


def test_build_synthesizes_form_targets_for_form_content_type():
    endpoint = ApiEndpoint(
        url="http://x/session/create",
        method="POST",
        content_type="application/x-www-form-urlencoded",
        body_schema=["email", "password"],
    )
    targets = AttackSurface.build([], [], api_endpoints=[endpoint], filter_fn=lambda name: name == "email")
    target = targets[0]
    assert target.location == ParameterLocation.form
    assert target.replayable is False
    prepared = target.build_request("' OR 1=1--")
    assert prepared.data["email"] == "' OR 1=1--"
