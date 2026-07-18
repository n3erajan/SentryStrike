from app.core.crawler.models import ApiEndpoint, ParameterCandidate, ParameterLocation, RequestObservation
from app.core.crawler.spider import FormInput, HtmlForm
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
        request_content_type="application/json",
        post_data='{"name":"juice","url":"http://example.org"}',
        body_kind="json",
        body_schema=["name", "url"],
        replayable=True,
    )

    targets = AttackSurface.build([], [], requests=[request], filter_fn=lambda name: name == "url")

    assert len(targets) == 1
    target = targets[0]
    assert target.location == ParameterLocation.json_body
    assert target.source == "browser_request"
    assert target.replayable is True
    assert target.body_schema == ["name", "url"]
    assert build_json_body(target.json_template, target, "http://127.0.0.1/")["url"] == "http://127.0.0.1/"


def test_hash_route_translates_to_server_path_candidate():
    assert (
        AttackSurface._translate_hash_route_to_server_url("http://example.com/#/ftp/legal.md")
        == "http://example.com/ftp/legal.md"
    )

    targets = AttackSurface.build(
        ["http://example.com/#/ftp/legal.md?file=legal.md"],
        [],
        filter_fn=lambda name: name == "file",
    )

    assert any(target.url == "http://example.com/ftp/legal.md?file=legal.md" for target in targets)
    assert not any("#/ftp" in target.url for target in targets)


def test_hash_route_form_submission_is_not_resurrected_as_shell_target():
    """A browser-cluster form whose action is a client-side hash route must not
    become a translated server-path POST target: that path only reaches the SPA
    shell, and the real endpoint is captured separately as the form's XHR.

    Regression: SPA form clusters on ``/#/address/create`` (fields such as the
    framework-generated ``mat-input-18``) were being translated to bare
    ``/address/create`` and hammered by every injection detector — hundreds of
    shell-only POSTs per scan.
    """
    form = HtmlForm(
        page_url="http://example.com/#/address/create",
        action="http://example.com/#/address/create",
        method="POST",
        inputs=[FormInput(name="mat-input-18", input_type="text")],
        source="browser_cluster",
    )

    targets = AttackSurface.build([], [form])

    # No target points at the translated client-route path…
    assert not any(t.url == "http://example.com/address/create" for t in targets)
    # …and none carries the hash route verbatim either.
    assert not any("#/address/create" in t.url for t in targets)
    # The junk field never becomes a form-location injection target.
    assert not any(
        t.location == ParameterLocation.form and t.parameter == "mat-input-18"
        for t in targets
    )


def test_attack_surface_filter_can_read_whole_candidate():
    endpoint = ApiEndpoint(
        url="http://example.com/api/profile",
        method="POST",
        request_body={"city": "Berlin", "url": "https://example.test/"},
        headers={"Content-Type": "application/json"},
    )

    targets = AttackSurface.build(
        [],
        [],
        api_endpoints=[endpoint],
        filter_fn=lambda candidate: candidate.name == "city" and candidate.baseline_value == "Berlin",
    )

    assert [target.parameter for target in targets] == ["city"]


def test_attack_surface_extracts_browser_observed_form_encoded_request():
    request = RequestObservation(
        url="http://example.com/login",
        method="POST",
        request_headers={"content-type": "application/x-www-form-urlencoded"},
        request_content_type="application/x-www-form-urlencoded",
        post_data="email=alice%40example.test&password=Secret123%21&csrf=abc",
        body_kind="form",
        body_schema=["csrf", "email", "password"],
        replayable=True,
    )

    targets = AttackSurface.build([], [], requests=[request], filter_fn=lambda name: name == "email")

    assert len(targets) == 1
    target = targets[0]
    assert target.location == ParameterLocation.form
    assert target.source == "browser_form_request"
    assert target.replayable is True
    assert target.body_schema == ["csrf", "email", "password"]
    prepared = target.build_request("' OR 1=1--")
    assert prepared.url == "http://example.com/login"
    assert prepared.data == {
        "email": "' OR 1=1--",
        "password": "Secret123!",
        "csrf": "abc",
    }


def test_api_endpoint_form_content_type_yields_form_target():
    endpoint = ApiEndpoint(
        url="http://example.com/session",
        method="POST",
        content_type="application/x-www-form-urlencoded",
        request_body={"email": "alice@example.test", "password": "Secret123!"},
    )

    targets = AttackSurface.build([], [], api_endpoints=[endpoint], filter_fn=lambda name: name == "email")

    assert len(targets) == 1
    target = targets[0]
    assert target.location == ParameterLocation.form
    assert target.value == "alice@example.test"
    prepared = target.build_request("' OR 1=1--")
    assert prepared.data == {
        "email": "' OR 1=1--",
        "password": "Secret123!",
    }


def test_attack_target_builds_multipart_request_from_api_endpoint():
    endpoint = ApiEndpoint(
        url="http://example.com/upload",
        method="POST",
        content_type="multipart/form-data",
        request_body={"avatarFile": "old.png", "userId": 7},
        headers={"Content-Type": "multipart/form-data; boundary=old", "Authorization": "Bearer token"},
    )

    targets = AttackSurface.build([], [], api_endpoints=[endpoint], filter_fn=lambda name: name == "avatarFile")

    target = targets[0]
    prepared = target.build_request(("avatar.txt", b"canary", "text/plain"))
    assert prepared.url == "http://example.com/upload"
    assert prepared.data == {"userId": "7"}
    assert prepared.files == {"avatarFile": ("avatar.txt", b"canary", "text/plain")}
    assert prepared.headers == {"Authorization": "Bearer token"}


def test_attack_surface_extracts_browser_observed_multipart_request():
    request = RequestObservation(
        url="http://example.com/upload",
        method="POST",
        request_headers={"content-type": "multipart/form-data; boundary=abc"},
        request_content_type="multipart/form-data; boundary=abc",
        post_data='--abc\r\nContent-Disposition: form-data; name="avatar"; filename="old.png"\r\n\r\nx'
        '\r\n--abc\r\nContent-Disposition: form-data; name="userId"\r\n\r\n1\r\n--abc--',
        body_kind="multipart",
        body_schema=["avatar", "userId"],
        multipart_fields=[
            {"name": "avatar", "type": "file", "filename": "old.png"},
            {"name": "userId", "type": "text", "filename": None},
        ],
        replayable=True,
    )

    targets = AttackSurface.build([], [], requests=[request], filter_fn=lambda name: name == "avatar")

    assert len(targets) == 1
    prepared = targets[0].build_request(("avatar.txt", b"canary", "text/plain"))
    assert prepared.data == {"userId": "sentry_test_val"}
    assert prepared.files == {"avatar": ("avatar.txt", b"canary", "text/plain")}


def test_attack_target_builds_query_request():
    target = AttackSurface.build(["http://example.com/search?q=test"], [], filter_fn=lambda name: name == "q")[0]

    request = target.build_request("payload")

    assert request.method == "GET"
    assert request.url == "http://example.com/search?q=payload"
    assert request.params is None
    assert request.data is None


def test_attack_surface_enriches_query_target_from_exact_observed_request():
    url = "http://example.com/search?q=test"
    candidate = ParameterCandidate(
        name="q",
        location=ParameterLocation.query,
        url=url,
        method="GET",
        baseline_value="test",
        source="browser_request",
    )
    observed = RequestObservation(
        url=url,
        method="GET",
        request_headers={
            "host": "example.com",
            "content-length": "99",
            "cookie": "stale=header",
            "accept": "application/json",
            "user-agent": "Mozilla/5.0 HeadlessChrome/140",
        },
        request_cookies={"session": "abc"},
    )

    target = AttackSurface.build(
        [],
        [],
        parameters=[candidate],
        requests=[observed],
    )[0]
    prepared = target.build_request("payload")

    assert prepared.headers == {
        "accept": "application/json",
        "user-agent": "Mozilla/5.0 HeadlessChrome/140",
        "Cookie": "session=abc",
    }
    assert prepared.cookies == {"session": "abc"}


def test_static_form_does_not_inherit_later_browser_cookie_mutation():
    form = HtmlForm(
        page_url="http://example.com/tools",
        action="http://example.com/tools",
        method="POST",
        inputs=[
            FormInput(name="value", input_type="text", value="1"),
            FormInput(name="submit", input_type="submit", value="submit"),
        ],
    )
    observed = RequestObservation(
        url="http://example.com/tools",
        method="POST",
        post_data="value=1&submit=submit",
        request_headers={"content-type": "application/x-www-form-urlencoded"},
        request_cookies={"mode": "mutated"},
        body_kind="form",
        replayable=True,
    )

    target = next(
        item
        for item in AttackSurface.build([], [form], requests=[observed])
        if item.parameter == "value"
    )

    assert target.source == "form"
    assert target.cookies == {}
    assert target.build_request("probe").data == {"value": "probe", "submit": "submit"}


def test_attack_target_builds_path_template_request():
    endpoint = ApiEndpoint(url="http://example.com/api/users/{userId}", method="GET")
    target = AttackSurface.build([], [], api_endpoints=[endpoint], filter_fn=lambda name: name == "userId")[0]

    request = target.build_request("42")

    assert request.url == "http://example.com/api/users/42"
    assert request.method == "GET"


def test_attack_target_builds_form_request_with_sibling_values():
    class Input:
        def __init__(self, name, input_type="text", value=""):
            self.name = name
            self.input_type = input_type
            self.value = value

    class Form:
        action = "http://example.com/comment"
        method = "POST"
        inputs = [Input("comment"), Input("csrf", "hidden", "abc"), Input("Submit", "submit", "Save")]

    target = AttackSurface.build([], [Form()], filter_fn=lambda name: name == "comment")[0]

    request = target.build_request("<x>")

    assert request.url == "http://example.com/comment"
    assert request.data == {"comment": "<x>", "csrf": "abc", "Submit": "Save"}


def test_attack_target_preserves_multipart_form_encoding():
    form = HtmlForm(
        page_url="http://example.com/upload",
        action="http://example.com/upload",
        method="POST",
        inputs=[
            FormInput("MAX_FILE_SIZE", "hidden", "100000"),
            FormInput("uploaded", "file", ""),
            FormInput("Upload", "submit", "Upload"),
        ],
        content_type="multipart/form-data",
    )

    target = next(
        item for item in AttackSurface.build([], [form])
        if item.parameter == "MAX_FILE_SIZE"
    )
    request = target.build_request("100000' AND SLEEP(3)--")

    assert target.content_type == "multipart/form-data"
    assert request.data["MAX_FILE_SIZE"] == "100000' AND SLEEP(3)--"
    assert "uploaded" in request.files
    assert not request.headers or "Content-Type" not in request.headers


def test_attack_target_builds_json_request():
    endpoint = ApiEndpoint(
        url="http://example.com/api/search",
        method="POST",
        request_body={"query": "alice", "filters": {"user_id": 7}},
        headers={"Authorization": "Bearer token"},
    )
    targets = AttackSurface.build([], [], api_endpoints=[endpoint], filter_fn=lambda name: name == "user_id")
    target = next(target for target in targets if target.parent_path == "filters.user_id")

    request = target.build_request("9")

    assert request.url == "http://example.com/api/search"
    assert request.method == "POST"
    assert request.json_body == {"query": "alice", "filters": {"user_id": "9"}}
    assert request.headers == {"Authorization": "Bearer token", "Content-Type": "application/json"}


def test_attack_target_builds_header_and_cookie_requests():
    header_target = AttackSurface.build(
        [],
        [],
        parameters=[],
        api_endpoints=[],
        requests=[],
    )
    from app.core.detectors.attack_surface import AttackTarget

    header = AttackTarget(
        url="http://example.com/",
        parameter="X-Test",
        location=ParameterLocation.header,
    ).build_request("canary")
    cookie = AttackTarget(
        url="http://example.com/",
        parameter="session",
        location=ParameterLocation.cookie,
    ).build_request("canary")

    assert header.headers == {"X-Test": "canary"}
    assert cookie.cookies == {"session": "canary"}
    assert cookie.headers == {"Cookie": "session=canary"}
    assert header_target == []


def test_attack_target_replaces_stale_cookie_header_with_observed_cookie_context():
    from app.core.detectors.attack_surface import AttackTarget

    request = AttackTarget(
        url="http://example.com/app/search",
        parameter="q",
        value="test",
        location=ParameterLocation.query,
        headers={"cookie": "security=high; session=old"},
        cookies={"session": "fresh", "security": "low"},
    ).build_request("payload")

    assert request.headers == {"Cookie": "session=fresh; security=low"}
    assert request.cookies == {"session": "fresh", "security": "low"}
