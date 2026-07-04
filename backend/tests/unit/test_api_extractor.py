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
