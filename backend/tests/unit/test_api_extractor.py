from app.core.crawler.api_extractor import ApiExtractor


def test_openapi_json_extracts_request_body_and_query_parameters():
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/api/users/{userId}": {
                "post": {
                    "operationId": "updateUser",
                    "parameters": [
                        {"name": "verbose", "in": "query", "schema": {"type": "boolean"}},
                    ],
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "email": {"type": "string", "example": "a@example.test"},
                                        "profile": {
                                            "type": "object",
                                            "properties": {"name": {"type": "string"}},
                                        },
                                    },
                                }
                            }
                        }
                    },
                }
            }
        },
    }

    endpoints = ApiExtractor.extract_from_openapi("https://example.test", spec)

    assert len(endpoints) == 1
    endpoint = endpoints[0]
    assert endpoint.url == "https://example.test/api/users/{userId}?verbose=True"
    assert endpoint.method == "POST"
    assert endpoint.content_type == "application/json"
    assert endpoint.request_body == {"email": "a@example.test", "profile": {"name": "Scanner Test"}}

    parameters = ApiExtractor.parameters_from_endpoint(endpoint)
    assert {parameter.name for parameter in parameters} >= {"userId", "verbose", "email", "name"}


def test_javascript_extraction_infers_formdata_and_urlsearchparams():
    script = """
        const upload = new FormData();
        upload.append('avatar', file);
        upload.append('userId', user.id);
        fetch('/api/upload', { method: 'POST', body: upload });

        const params = new URLSearchParams();
        params.append('email', email);
        params.set('password', password);
        axios.post('/api/session', params);
    """

    _, endpoints = ApiExtractor.extract_from_javascript("https://example.test/app.js", script)

    upload = next(endpoint for endpoint in endpoints if endpoint.url.endswith("/api/upload"))
    session = next(endpoint for endpoint in endpoints if endpoint.url.endswith("/api/session"))
    assert upload.content_type == "multipart/form-data"
    assert upload.request_body == {"avatar": "test", "userId": 1}
    assert session.content_type == "application/x-www-form-urlencoded"
    assert session.request_body == {"email": "scanner@example.com", "password": "Password123!"}


def test_javascript_extraction_infers_axios_and_jquery_json_bodies():
    script = """
        axios.patch('/api/profile', { email: email, displayName: name });
        $.ajax({ url: '/api/contact', type: 'POST', data: { message: msg, callbackUrl: nextUrl } });
    """

    _, endpoints = ApiExtractor.extract_from_javascript("https://example.test/app.js", script)

    profile = next(endpoint for endpoint in endpoints if endpoint.url.endswith("/api/profile"))
    contact = next(endpoint for endpoint in endpoints if endpoint.url.endswith("/api/contact") and endpoint.method == "POST")
    assert profile.method == "PATCH"
    assert profile.content_type == "application/json"
    assert profile.request_body == {"email": "scanner@example.com", "displayName": "Scanner Test"}
    assert contact.method == "POST"
    assert contact.request_body == {"message": "Scanner test message", "callbackUrl": "https://example.com/"}


def test_relative_api_paths_resolve_from_origin_root_not_frontend_route():
    script = """
        fetch('api/orders', { method: 'POST', body: JSON.stringify({ orderId: id }) });
        axios.get('rest/user/profile');
    """

    _, endpoints = ApiExtractor.extract_from_javascript("https://example.test/shop/cart", script)
    urls = {endpoint.url for endpoint in endpoints}

    assert "https://example.test/api/orders" in urls
    assert "https://example.test/rest/user/profile" in urls
    assert all("/shop/cart/api/" not in url and "/shop/cart/rest/" not in url for url in urls)


def test_base_variable_concat_calls_are_resolved_to_full_path():
    """body-coverage #3: a call whose URL is ``base + "/tail"`` or a template
    ``\\`${base}/tail\\``` — where the literal tail alone carries no /api|/rest
    token — is recovered by resolving the base var to its literal path prefix."""
    script = """
        class Feedback {
          constructor() { this.host = "/api"; }
          save(b) { return this.http.post(this.host + "/Feedbacks", b); }
          update(id, b) { return this.http.put(`${this.host}/Users/${id}`, b); }
        }
    """
    _, endpoints = ApiExtractor.extract_from_javascript("https://example.test/", script)
    by = {(e.method, e.url) for e in endpoints}
    assert ("POST", "https://example.test/api/Feedbacks") in by
    assert ("PUT", "https://example.test/api/Users/{id}") in by
    # These came from the base-concat pass.
    assert any(e.evidence == "base-concat" for e in endpoints)


def test_template_base_call_recovers_rest_path():
    """A ``\\`${base}/rest/user/reset-password\\``` template resolves to the full
    /rest path even when the base var is only an origin/empty prefix."""
    script = """
        const base = "https://api.example.test";
        fetch(`${base}/rest/user/reset-password`, { method: 'POST' });
    """
    _, endpoints = ApiExtractor.extract_from_javascript("https://example.test/", script)
    urls = {e.url for e in endpoints}
    assert any(u.endswith("/rest/user/reset-password") for u in urls)


def test_javascript_url_string_literals_mine_restish_endpoints():
    script = """
        const imageUrl = "/profile/image/url";
        const orderApi = "/b2b/v2/orders";
        const icon = "/assets/logo.svg";
    """

    _, endpoints = ApiExtractor.extract_from_javascript("https://example.test/app.js", script)
    urls = {endpoint.url for endpoint in endpoints}

    assert "https://example.test/profile/image/url" in urls
    assert "https://example.test/b2b/v2/orders" in urls
    assert "https://example.test/assets/logo.svg" not in urls


def test_javascript_url_string_derives_rest_parent_endpoint():
    script = 'const userUrl = "/api/users/{userId}"; const byId = "/rest/orders/123";'

    _, endpoints = ApiExtractor.extract_from_javascript("https://example.test/app.js", script)
    urls = {endpoint.url for endpoint in endpoints}

    assert "https://example.test/api/users/{userId}" in urls
    assert "https://example.test/api/users" in urls
    assert "https://example.test/rest/orders/123" in urls
    assert "https://example.test/rest/orders" in urls


def test_ambiguous_base_variable_is_not_resolved():
    """A base name bound to different literals in different scopes (the minified
    per-class field pattern) MUST NOT resolve — resolving it would fabricate
    wrong endpoints. Ambiguous names are dropped entirely."""
    script = """
        class A { h = "/api/BasketItems"; f(b){ return this.http.post(this.h + "/x", b); } }
        class B { h = "/api/Cards"; g(b){ return this.http.post(this.h + "/y", b); } }
    """
    assert ApiExtractor._resolve_base_vars(script) == {}
    _, endpoints = ApiExtractor.extract_from_javascript("https://example.test/", script)
    # No fabricated /api/BasketItems/x or /api/Cards/y from the concat pass.
    assert not any(e.evidence == "base-concat" for e in endpoints)
    assert not any(u.endswith(("/x", "/y")) for u in {e.url for e in endpoints})



def test_mines_location_navigation_page_paths():
    from app.core.crawler.api_extractor import ApiExtractor
    js = 'goToProfilePage(){window.location.replace(J.hostServer+"/profile")}'
    routes, _endpoints = ApiExtractor.extract_from_javascript("http://t.example/main.js", js)
    assert "http://t.example/profile" in routes


def test_mines_various_navigation_forms():
    from app.core.crawler.api_extractor import ApiExtractor
    js = (
        'location.assign("/account/settings");'
        'window.location.href="/dashboard";'
        'location.replace(base+"/billing");'
    )
    routes, _ = ApiExtractor.extract_from_javascript("http://t.example/x.js", js)
    for expected in ("http://t.example/account/settings",
                     "http://t.example/dashboard",
                     "http://t.example/billing"):
        assert expected in routes, expected


def test_navigation_mining_rejects_offorigin_and_non_nav_strings():
    from app.core.crawler.api_extractor import ApiExtractor
    # A bare single-segment quoted string WITHOUT a navigation call must NOT be
    # mined as a route (the general filter is unchanged).
    js = 'const label="/profile"; const x = someObj["/profile"];'
    routes, _ = ApiExtractor.extract_from_javascript("http://t.example/x.js", js)
    assert "http://t.example/profile" not in routes
    # Off-origin absolute URL navigation is not a same-origin path.
    js2 = 'location.replace("https://evil.example.com/profile")'
    routes2, _ = ApiExtractor.extract_from_javascript("http://t.example/x.js", js2)
    assert not any("evil.example.com" in r for r in routes2)
