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
    assert header_target == []
