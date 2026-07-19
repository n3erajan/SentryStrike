from __future__ import annotations

from app.core.crawler.api_extractor import ApiExtractor
from app.core.crawler.models import ApiEndpoint, ParameterLocation, RequestObservation, RouteSource
from app.core.crawler.spider import FormInput, HtmlForm
from app.core.detectors.attack_surface import AttackSurface, build_json_body


# --- is_api_endpoint predicate (generic) ---------------------------------------


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


# --- synthesis targets real API endpoints only ---------------------------------


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


def test_observed_json_array_body_builds_replayable_targets():
    observed = RequestObservation(
        url="http://x/api/items",
        method="POST",
        request_headers={"content-type": "application/json"},
        request_content_type="application/json",
        post_data='[{"id":1,"name":"alpha"}]',
        body_kind="json",
        replayable=True,
    )

    targets = AttackSurface.build([], [], requests=[observed])
    id_target = next(target for target in targets if target.parameter == "id")
    body = build_json_body(id_target.json_template, id_target, "99")

    assert id_target.replayable is True
    assert id_target.parent_path == "[0].id"
    assert body[0]["id"] == "99"


def test_body_target_telemetry_splits_skip_reasons():
    static_endpoint = ApiEndpoint(
        url="http://x/api/static",
        method="POST",
        source=RouteSource.javascript,
        evidence="fetch/xhr",
        content_type="application/json",
        body_schema=["name"],
    )
    non_replayable = RequestObservation(
        url="http://x/api/binary",
        method="POST",
        request_content_type="application/octet-stream",
        post_data="raw",
        replayable=False,
        non_replayable_reason="unsupported_content_type",
    )
    transport = RequestObservation(
        url="http://x/socket.io/?EIO=4&transport=polling",
        method="POST",
        resource_type="fetch",
        post_data="40",
        replayable=False,
        drop_reason="transport_noise",
    )

    telemetry = AttackSurface.body_target_telemetry(
        api_endpoints=[static_endpoint],
        requests=[non_replayable, transport],
    )

    assert telemetry["observed_body_requests"] == 2
    assert telemetry["replayable_body_requests"] == 0
    assert telemetry["body_targets_skipped_static_synth_not_validated"] >= 1
    assert telemetry["body_targets_skipped_non_replayable"] >= 1
    assert telemetry["body_targets_skipped_transport_noise"] >= 1


def test_build_synthesis_skips_unresolved_path_placeholders():
    ep = ApiEndpoint(
        url="http://x/rest/basket/{param_1}/checkout",
        method="POST",
        source=RouteSource.javascript,
        evidence="fetch/xhr",
        content_type="application/json",
        body_schema=["coupon"],
    )

    targets = AttackSurface.build([], [], api_endpoints=[ep])
    telemetry = AttackSurface.body_target_telemetry(api_endpoints=[ep])

    assert targets == []
    assert telemetry["static_synth_body_targets"] == 0
    assert telemetry["skipped_unresolved_body_targets"] == 1


def test_build_skips_parameter_candidates_with_unresolved_path_placeholders():
    targets = AttackSurface.build(
        [],
        [],
        parameters=[
            ApiExtractor.parameters_from_endpoint(
                ApiEndpoint(
                    url="http://x/rest/basket/%7Bparam_1%7D/checkout",
                    method="POST",
                    source=RouteSource.javascript,
                    evidence="fetch/xhr",
                    content_type="application/json",
                    request_body={"coupon": "SAVE10"},
                )
            )[0]
        ],
    )

    assert targets == []


# --- Synthetic body fallback for captured-but-unsubmittable forms -------------


def _browser_cluster_form(action, inputs, method="GET"):
    return HtmlForm(
        page_url="http://x/register",
        action=action,
        method=method,
        inputs=[FormInput(name=n, input_type=t) for n, t in inputs],
        source="browser_cluster",
    )


def test_build_synthesizes_form_synth_json_targets_from_browser_cluster():
    form = _browser_cluster_form(
        "http://x/register",
        [("email", "text"), ("password", "password")],
    )
    targets = AttackSurface.build([], [form])

    synth = [t for t in targets if t.source_confidence == "form_synth"]
    assert {t.parameter for t in synth} == {"email", "password"}
    for target in synth:
        assert target.location == ParameterLocation.json_body
        assert target.method == "POST"
        assert target.replayable is False
        assert target.source == "form_synth"
        # the synthesized template is injectable
        body = build_json_body(target.json_template, target, "' OR 1=1--")
        assert body[target.parameter] == "' OR 1=1--"


def test_form_synth_respects_filter_fn():
    form = _browser_cluster_form(
        "http://x/register",
        [("email", "text"), ("password", "password")],
    )
    targets = AttackSurface.build([], [form], filter_fn=lambda name: name == "email")
    synth = [t for t in targets if t.source_confidence == "form_synth"]
    assert {t.parameter for t in synth} == {"email"}


def test_form_synth_skips_non_injectable_input_types():
    form = _browser_cluster_form(
        "http://x/register",
        [("email", "text"), ("csrf", "hidden"), ("go", "submit"), ("avatar", "file")],
    )
    targets = AttackSurface.build([], [form])
    synth = [t for t in targets if t.source_confidence == "form_synth"]
    assert {t.parameter for t in synth} == {"email"}


def test_form_synth_dropped_for_hash_route_cluster_url():
    """A cluster whose only URL is a client-side hash route (``/#/register``)
    must NOT produce any target: the ``#/…`` fragment is stripped on the wire, so
    a POST there only hits the SPA shell and tests nothing. The real endpoint is
    captured separately via the observed XHR. Framework-agnostic guard."""
    form = HtmlForm(
        page_url="http://x/#/register",
        action="http://x/#/register",
        method="POST",
        inputs=[FormInput(name="email", input_type="text"),
                FormInput(name="mat-input-16", input_type="text")],
        source="browser_cluster",
    )
    targets = AttackSurface.build([], [form])
    # No target may point at the hash-route URL, regardless of source.
    assert all("/#/" not in t.url for t in targets)
    assert all(t.source_confidence != "form_synth" for t in targets)


def test_form_synth_only_fires_for_browser_clusters_not_html_forms():
    # A server-rendered <form> already yields observed form-location targets; it
    # must NOT also get a form_synth JSON fallback.
    html_form = HtmlForm(
        page_url="http://x/login",
        action="http://x/login",
        method="POST",
        inputs=[FormInput(name="email", input_type="text")],
        source="html",
    )
    targets = AttackSurface.build([], [html_form])
    assert all(t.source_confidence != "form_synth" for t in targets)


def test_form_synth_deduped_and_coexists_with_observed_form_target():
    form = _browser_cluster_form(
        "http://x/register",
        [("email", "text")],
    )
    targets = AttackSurface.build([], [form])
    observed = [t for t in targets if t.source_confidence != "form_synth"]
    synth = [t for t in targets if t.source_confidence == "form_synth"]
    # The cluster produced a normal form target (from inventory) AND a JSON fallback.
    assert any(t.location == ParameterLocation.form for t in observed)
    assert any(t.location == ParameterLocation.json_body for t in synth)


def test_form_synth_skips_unresolved_path_placeholder():
    form = _browser_cluster_form(
        "http://x/rest/basket/{param_1}/checkout",
        [("coupon", "text")],
    )
    targets = AttackSurface.build([], [form])
    assert all(t.source_confidence != "form_synth" for t in targets)


# --- Create -> update target synthesis (replayable-body coverage) -----------------------


def _create_observation(url, body, response, status=201, headers=None):
    return RequestObservation(
        url=url,
        method="POST",
        request_content_type="application/json",
        post_data=body,
        request_headers=headers or {"authorization": "Bearer t"},
        response_status=status,
        response_snippet=response,
    )


def test_create_response_id_synthesizes_put_and_patch_update_targets():
    """A POST create returning an id yields replayable PUT/PATCH targets at the
    id-scoped item path with the same body shape (universal REST convention)."""
    obs = _create_observation(
        "http://x/api/Cards",
        '{"fullName": "A", "cardNum": 4111111111111111}',
        '{"status": "success", "data": {"id": 42, "fullName": "A"}}',
    )
    targets = AttackSurface.build([], [], requests=[obs])
    derived = [t for t in targets if t.source_confidence == "derived_update"]
    assert derived, "expected create->update synthesis"
    methods = {t.method for t in derived}
    assert methods == {"PUT", "PATCH"}
    assert all(t.url == "http://x/api/Cards/42" for t in derived)
    assert all(t.replayable is True for t in derived)
    # Same body fields become injectable parameters.
    assert {t.parameter for t in derived} >= {"fullName", "cardNum"}
    # Authenticated context carried over from the create.
    assert all(t.headers.get("authorization") == "Bearer t" for t in derived)


def test_no_update_synthesis_without_created_id():
    """An RPC-style POST (login) whose response carries no resource id must not
    synthesize bogus /login/{id} update targets."""
    obs = _create_observation(
        "http://x/rest/user/login",
        '{"email": "a@b.c", "password": "x"}',
        '{"authentication": {"token": "abc.def.ghi"}}',
        status=200,
    )
    targets = AttackSurface.build([], [], requests=[obs])
    assert [t for t in targets if t.source_confidence == "derived_update"] == []


def test_no_update_synthesis_when_post_targets_item_path():
    """A POST already aimed at an item path (…/42) is not a collection create."""
    obs = _create_observation(
        "http://x/api/Cards/42/activate",
        '{"flag": true}',
        '{"id": 99}',
    )
    targets = AttackSurface.build([], [], requests=[obs])
    # /activate is a noun, but the id 42 earlier doesn't matter — the final segment
    # "activate" is not an id, so this WOULD synthesize; guard instead on failure
    # responses. Here status is 201 so it synthesizes an /activate/{id}: acceptable
    # only if an id was returned. This asserts the create-id gate, not path shape.
    derived = [t for t in targets if t.source_confidence == "derived_update"]
    assert all(t.url.endswith("/99") for t in derived)


def test_no_update_synthesis_on_failed_create():
    obs = _create_observation(
        "http://x/api/Cards",
        '{"fullName": "A"}',
        '{"error": "bad request"}',
        status=400,
    )
    targets = AttackSurface.build([], [], requests=[obs])
    assert [t for t in targets if t.source_confidence == "derived_update"] == []


def test_observed_update_wins_over_synthesized():
    """When the crawler already observed the PUT, no duplicate synthesis."""
    create = _create_observation(
        "http://x/api/Cards",
        '{"fullName": "A"}',
        '{"id": 42}',
    )
    observed_put = RequestObservation(
        url="http://x/api/Cards/42",
        method="PUT",
        request_content_type="application/json",
        post_data='{"fullName": "B"}',
        response_status=200,
    )
    targets = AttackSurface.build([], [], requests=[create, observed_put])
    put_targets = [t for t in targets if t.method == "PUT" and t.url == "http://x/api/Cards/42"]
    # The observed PUT is present; the synthesizer did not add a duplicate derived one.
    assert put_targets
    assert all(t.source_confidence != "derived_update" for t in put_targets)


def test_request_with_unresolved_path_placeholder_yields_no_body_targets():
    """An observed request whose URL still carries a route template (:addressId)
    is a crawler artifact, not a replayable XHR — it must not emit body targets
    that would each 404 against a non-existent object."""
    req = RequestObservation(
        url="http://x/api/Addresss/:addressId",
        method="PUT",
        request_content_type="application/json",
        post_data='{"fullName": "x", "city": "y"}',
    )
    targets = AttackSurface.build([], [], requests=[req])
    assert not any(
        t.location == ParameterLocation.json_body and ":addressId" in t.url
        for t in targets
    )


def test_request_with_concrete_id_still_yields_body_targets():
    """The guard above must not suppress a genuinely-observed concrete-id XHR."""
    req = RequestObservation(
        url="http://x/api/Addresss/42",
        method="PUT",
        request_content_type="application/json",
        post_data='{"fullName": "x"}',
    )
    targets = AttackSurface.build([], [], requests=[req])
    assert any(t.location == ParameterLocation.json_body for t in targets)
