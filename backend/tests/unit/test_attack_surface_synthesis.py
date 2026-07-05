from __future__ import annotations

from app.core.crawler.api_extractor import ApiExtractor
from app.core.crawler.models import ApiEndpoint, ParameterLocation, RequestObservation, RouteSource
from app.core.detectors.attack_surface import AttackSurface, build_json_body


# --- Task C: is_api_endpoint predicate (generic) ---------------------------------------


def test_is_api_endpoint_true_on_body_schema():
    ep = ApiEndpoint(url="http://x/rest/user/login", method="POST", body_schema=["email", "password"])
    assert ApiExtractor.is_api_endpoint(ep) is True


def test_is_api_endpoint_true_on_json_content_type():
    ep = ApiEndpoint(url="http://x/submit", method="POST", content_type="application/json")
    assert ApiExtractor.is_api_endpoint(ep) is True


def test_is_api_endpoint_true_on_api_path_token():
    for url in ("http://x/api/basket", "http://x/rest/products", "http://x/graphql", "http://x/v1/orders"):
        assert ApiExtractor.is_api_endpoint(ApiEndpoint(url=url, method="POST")) is True


def test_is_api_endpoint_true_on_xhr_provenance():
    ep = ApiEndpoint(url="http://x/basket", method="POST", source=RouteSource.browser, evidence="xhr:200")
    assert ApiExtractor.is_api_endpoint(ep) is True
    js = ApiEndpoint(url="http://x/basket", method="POST", source=RouteSource.javascript, evidence="fetch/xhr")
    assert ApiExtractor.is_api_endpoint(js) is True


def test_is_api_endpoint_false_on_html_navigation_route():
    # An SPA route (e.g. the Angular /login route) mined as a bare endpoint with
    # no body, no api token, and no XHR provenance is NOT an API endpoint.
    ep = ApiEndpoint(url="http://x/login", method="POST", source=RouteSource.html, evidence="")
    assert ApiExtractor.is_api_endpoint(ep) is False


def test_is_api_endpoint_false_on_text_html_content_type():
    ep = ApiEndpoint(url="http://x/rest/user/login", method="POST", content_type="text/html")
    assert ApiExtractor.is_api_endpoint(ep) is False


def test_is_api_endpoint_false_on_ambiguous_endpoint():
    # No content-type, no schema, no api token, static source -> default to not API.
    ep = ApiEndpoint(url="http://x/dashboard", method="POST", source=RouteSource.html)
    assert ApiExtractor.is_api_endpoint(ep) is False


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
    # RC3: an opt-in caller (already gated on is_api_endpoint) gets one generic
    # low-confidence leaf for the same bare mutating endpoint.
    _, opt_in = ApiExtractor.synthesize_body_schema(bare, allow_generic_body=True)
    assert list(opt_in) == ["data"]
    # allow_generic_body must never override the GET guard.
    get_ep = ApiEndpoint(url="http://x/rest/basket", method="GET")
    assert ApiExtractor.synthesize_body_schema(get_ep, allow_generic_body=True) == (None, None)
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


# --- Task C: synthesis targets real API endpoints only ---------------------------------


def test_build_synthesis_excludes_html_navigation_route():
    """A JS-mined API endpoint gets body targets; a sibling HTML route does not."""
    api = ApiEndpoint(
        url="http://x/rest/user/login",
        method="POST",
        source=RouteSource.javascript,
        evidence="fetch/xhr",
        body_schema=["email", "password"],
    )
    html_route = ApiEndpoint(
        url="http://x/login",
        method="POST",
        source=RouteSource.html,
        evidence="",
    )
    targets = AttackSurface.build([], [], api_endpoints=[api, html_route])

    synth = [t for t in targets if t.source_confidence == "static_synth"]
    # Body targets exist for the real API endpoint...
    assert {t.parameter for t in synth} == {"email", "password"}
    # ...and none point at the HTML route.
    assert all("/login" not in t.url or "/rest/" in t.url for t in synth)
    assert all(t.url == "http://x/rest/user/login" for t in synth)


def test_build_synthesis_includes_api_signal_endpoint():
    ep = ApiEndpoint(
        url="http://x/api/orders",
        method="POST",
        source=RouteSource.browser,
        evidence="xhr:200",
        content_type="application/json",
        body_schema=["item", "qty"],
    )
    targets = AttackSurface.build([], [], api_endpoints=[ep])
    synth = [t for t in targets if t.source_confidence == "static_synth"]
    assert {t.parameter for t in synth} == {"item", "qty"}


def test_build_synthesis_prefers_observed_body_over_synth_for_api():
    ep = ApiEndpoint(
        url="http://x/rest/user/login",
        method="POST",
        source=RouteSource.javascript,
        evidence="fetch/xhr",
        body_schema=["email", "password"],
    )
    observed = RequestObservation(
        url="http://x/rest/user/login",
        method="POST",
        request_headers={"content-type": "application/json"},
        request_content_type="application/json",
        post_data='{"email":"a@b.test","password":"pw"}',
        body_kind="json",
        replayable=True,
    )
    targets = AttackSurface.build([], [], api_endpoints=[ep], requests=[observed])
    # Observed body wins; nothing static_synth for this endpoint.
    assert all(t.source_confidence != "static_synth" for t in targets)
    assert any(t.replayable for t in targets)
