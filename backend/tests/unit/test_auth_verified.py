import pytest
import base64
import json
import time
from types import SimpleNamespace
from unittest.mock import patch

from app.config import get_settings
from app.core.crawler.models import ApiEndpoint, RequestObservation
from app.core.detectors.auth_detector import AuthenticationFailuresDetector
from app.core.detectors.base_detector import Finding
from app.models.vulnerability import OwaspCategory, SeverityLevel
from app.core.verification.response_analyzer import ResponseData
from app.core.verification.verification_framework import HttpVerifier

def test_auth_bruteforce_verified():
    detector = AuthenticationFailuresDetector()
    
    # Test that the _finding method sets verified=True
    finding = detector._finding(
        vuln_type="Lack of Brute-Force Protection on Login Form",
        url="http://example.com/login",
        severity="High",
        evidence="Sent 5 rapid attempts",
        verified=True
    )
    
    assert finding.verified is True


def test_sensitive_query_params_do_not_flag_non_secret_csrf_values():
    detector = AuthenticationFailuresDetector()

    leaked = detector._sensitive_query_params(
        [("id", "1"), ("user_token", "abc123"), ("step", "confirm")],
        "http://example.test/csrf/",
    )

    assert leaked == set()


def test_burst_stability_accepts_identical_fast_responses():
    detector = AuthenticationFailuresDetector()
    responses = [
        SimpleNamespace(status_code=200, body="Invalid login", response_time_ms=50.0)
        for _ in range(10)
    ]
    burst_results = [{"size": 10, "responses": responses, "mean_ms": 50.0, "stdev_ms": 0.0}]

    assert detector._burst_responses_stable(burst_results) is True
    assert detector._rate_limit_signals_present(responses) is False


def test_rate_limit_signal_suppresses_burst_finding():
    detector = AuthenticationFailuresDetector()
    responses = [
        SimpleNamespace(status_code=200, body="Invalid login", response_time_ms=50.0),
        SimpleNamespace(status_code=429, body="Too many requests", response_time_ms=55.0),
    ]

    assert detector._rate_limit_signals_present(responses) is True


@pytest.mark.asyncio
async def test_verified_mode_suppresses_passive_url_only_auth_hints():
    settings = get_settings()
    original_mode = settings.scan_mode
    settings.scan_mode = "verified"

    try:
        detector = AuthenticationFailuresDetector()
        findings = await detector.detect(
            urls=[
                "http://example.test/login",
                "http://example.test/forgot-password",
                "http://example.test/change-password",
            ],
            forms=[],
        )
    finally:
        settings.scan_mode = original_mode

    vuln_types = {finding.vuln_type for finding in findings}
    assert "Authentication Endpoint Served Over Plaintext HTTP" not in vuln_types
    assert "Password Reset Endpoint Without Token Parameter" not in vuln_types


@pytest.mark.asyncio
async def test_heuristic_mode_keeps_passive_url_only_auth_hints():
    settings = get_settings()
    original_mode = settings.scan_mode
    settings.scan_mode = "heuristic"

    try:
        detector = AuthenticationFailuresDetector()
        findings = await detector.detect(
            urls=[
                "http://example.test/login",
                "http://example.test/forgot-password",
            ],
            forms=[],
        )
    finally:
        settings.scan_mode = original_mode

    vuln_types = {finding.vuln_type for finding in findings}
    assert "Authentication Endpoint Served Over Plaintext HTTP" in vuln_types
    assert "Password Reset Endpoint Without Token Parameter" in vuln_types


@pytest.mark.asyncio
async def test_verified_mode_suppresses_url_only_admin_path_findings():
    settings = get_settings()
    original_mode = settings.scan_mode
    settings.scan_mode = "verified"

    try:
        detector = AuthenticationFailuresDetector()
        findings = await detector.detect(
            urls=[
                "http://example.test/administration",
                "http://example.test/.env",
            ],
            forms=[],
        )
    finally:
        settings.scan_mode = original_mode

    vuln_types = {finding.vuln_type for finding in findings}
    assert "Admin / Privileged Endpoint Discovered" not in vuln_types
    assert "Well-Known Admin / Sensitive Path Discovered" not in vuln_types
    assert "Authentication Endpoint Served Over Plaintext HTTP" not in vuln_types


@pytest.mark.asyncio
async def test_heuristic_mode_suppresses_spa_admin_route_name_hints():
    settings = get_settings()
    original_mode = settings.scan_mode
    settings.scan_mode = "heuristic"

    try:
        detector = AuthenticationFailuresDetector()
        findings = await detector.detect(
            urls=[
                "http://example.test/administration",
                "http://example.test/.env",
            ],
            forms=[],
            is_spa=True,
        )
    finally:
        settings.scan_mode = original_mode

    vuln_types = {finding.vuln_type for finding in findings}
    assert "Admin / Privileged Endpoint Discovered" not in vuln_types
    assert "Well-Known Admin / Sensitive Path Discovered" not in vuln_types


def _jwt(header: dict, payload: dict) -> str:
    def enc(value: dict) -> str:
        raw = json.dumps(value, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    return f"{enc(header)}.{enc(payload)}.signature"


@pytest.mark.asyncio
async def test_api_login_rate_limit_probe_uses_replayable_json_request():
    detector = AuthenticationFailuresDetector()
    request = RequestObservation(
        url="https://example.test/api/auth/login",
        method="POST",
        request_headers={"content-type": "application/json"},
        post_data='{"email":"alice@example.test","password":"correct"}',
    )
    seen_bodies: list[dict] = []

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        # Scope to the rate-limit probe (the default-credentials probe also runs
        # on login flows under its own test_phase and is asserted elsewhere).
        if kwargs.get("test_phase") == "api_login_rate_limit":
            seen_bodies.append(kwargs.get("json_body"))
        return ResponseData(
            200,
            {"content-type": "application/json"},
            '{"error":"invalid credentials"}',
            10.0,
            request_snippet=f"{method} {url}",
            response_snippet="HTTP/1.1 200 OK",
        )

    with patch.object(HttpVerifier, "send_request", send_request):
        findings = await detector.detect(urls=[], forms=[], requests=[request])

    assert len(seen_bodies) == 6
    assert all(body["email"].startswith("sentry_invalid_") for body in seen_bodies)
    assert any(f.vuln_type == "API Login Lacks Safe-Probe Rate-Limit Signal" for f in findings)


@pytest.mark.asyncio
async def test_api_login_rate_limit_probe_suppressed_when_rate_limit_signal_seen():
    detector = AuthenticationFailuresDetector()
    endpoint = ApiEndpoint(
        url="https://example.test/api/login",
        method="POST",
        request_body={"username": "alice", "password": "correct"},
    )
    calls = 0

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        nonlocal calls
        # Count only rate-limit-probe requests (the default-credentials probe runs
        # on login flows under its own test_phase; its behaviour is asserted elsewhere).
        if kwargs.get("test_phase") != "api_login_rate_limit":
            return ResponseData(200, {"content-type": "text/plain"}, "Invalid credentials", 5.0)
        calls += 1
        status = 429 if calls == 3 else 200
        body = "Too many requests" if status == 429 else "Invalid credentials"
        return ResponseData(status, {"content-type": "text/plain"}, body, 5.0)

    with patch.object(HttpVerifier, "send_request", send_request):
        findings = await detector.detect(urls=[], forms=[], api_endpoints=[endpoint])

    assert calls == 3
    assert not any(f.vuln_type == "API Login Lacks Safe-Probe Rate-Limit Signal" for f in findings)


@pytest.mark.asyncio
async def test_password_change_api_requires_current_password_check_when_replay_accepts_body():
    detector = AuthenticationFailuresDetector()
    request = RequestObservation(
        url="https://example.test/api/account/change-password",
        method="POST",
        request_headers={"content-type": "application/json"},
        post_data='{"newPassword":"new-pass","confirmPassword":"new-pass"}',
    )

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        return ResponseData(
            200,
            {"content-type": "application/json"},
            '{"success":true,"message":"password changed"}',
            5.0,
            request_snippet=f"{method} {url}",
            response_snippet="HTTP/1.1 200 OK",
        )

    with patch.object(HttpVerifier, "send_request", send_request):
        findings = await detector.detect(
            urls=[],
            forms=[],
            requests=[request],
            auth_headers={"Authorization": "Bearer low-user-token"},
        )

    assert any(f.vuln_type == "Password Change API Missing Current Password Requirement" for f in findings)


@pytest.mark.asyncio
async def test_password_reset_api_without_token_is_only_reported_when_replay_succeeds():
    detector = AuthenticationFailuresDetector()
    endpoint = ApiEndpoint(
        url="https://example.test/api/password/reset",
        method="POST",
        request_body={"email": "alice@example.test", "new_password": "new-pass"},
    )

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        return ResponseData(400, {"content-type": "application/json"}, '{"error":"token required"}', 5.0)

    with patch.object(HttpVerifier, "send_request", send_request):
        findings = await detector.detect(urls=[], forms=[], api_endpoints=[endpoint])

    assert not any(f.vuln_type == "Password Reset API May Not Enforce Reset Token" for f in findings)


@pytest.mark.asyncio
async def test_mfa_api_missing_code_parameter_reported_when_replay_succeeds():
    detector = AuthenticationFailuresDetector()
    endpoint = ApiEndpoint(
        url="https://example.test/api/mfa/verify",
        method="POST",
        request_body={"email": "alice@example.test"},
    )

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        return ResponseData(200, {"content-type": "application/json"}, '{"ok":true,"verified":true}', 5.0)

    with patch.object(HttpVerifier, "send_request", send_request):
        findings = await detector.detect(urls=[], forms=[], api_endpoints=[endpoint])

    assert any(f.vuln_type == "MFA API Flow Missing Verification Code Parameter" for f in findings)


@pytest.mark.asyncio
async def test_jwt_metadata_and_sensitive_claims_are_reported():
    token = _jwt(
        {"alg": "none", "typ": "JWT"},
        {"sub": "user-1", "password_hash": "abc123", "iat": int(time.time())},
    )
    detector = AuthenticationFailuresDetector()

    findings = await detector.detect(
        urls=[],
        forms=[],
        auth_headers={"Authorization": f"Bearer {token}"},
        root_url="https://example.test/",
    )

    vuln_types = {finding.vuln_type for finding in findings}
    assert "JWT Uses alg=none" in vuln_types
    assert "JWT Missing Expiration Claim" in vuln_types
    assert "JWT Contains Sensitive Claims" in vuln_types


@pytest.mark.asyncio
async def test_observed_session_cookie_attributes_are_checked():
    detector = AuthenticationFailuresDetector()
    request = RequestObservation(
        url="https://example.test/api/auth/login",
        method="POST",
        response_headers={"set-cookie": "sessionid=abc123; Path=/"},
    )

    findings = await detector.detect(urls=[], forms=[], requests=[request])

    assert any(f.vuln_type == "Insecure Session Cookie Attributes" for f in findings)


@pytest.mark.asyncio
async def test_bearer_token_reuse_after_logout_is_reported_when_replay_still_succeeds():
    detector = AuthenticationFailuresDetector()
    protected = RequestObservation(url="https://example.test/api/profile", method="GET")
    logout = RequestObservation(url="https://example.test/api/auth/logout", method="POST")
    phases: list[str] = []

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        phases.append(kwargs.get("test_phase", ""))
        return ResponseData(
            200,
            {"content-type": "application/json"},
            '{"user":"alice"}',
            5.0,
            request_snippet=f"{method} {url}",
            response_snippet="HTTP/1.1 200 OK",
        )

    with patch.object(HttpVerifier, "send_request", send_request):
        findings = await detector.detect(
            urls=[],
            forms=[],
            requests=[protected, logout],
            auth_headers={"Authorization": "Bearer still-valid-token"},
        )

    assert phases == ["token_reuse_baseline", "logout_revoke", "token_reuse_after_logout"]
    assert any(f.vuln_type == "Bearer Token Accepted After Logout" for f in findings)


@pytest.mark.asyncio
async def test_password_change_enforcement_probe_flags_when_current_password_ignored():
    """When a change-password body HAS a current-password field, the probe omits it
    and flags if the server still applies the change (no enforcement)."""
    detector = AuthenticationFailuresDetector()
    request = RequestObservation(
        url="https://example.test/api/account/change-password",
        method="POST",
        request_headers={"content-type": "application/json"},
        post_data='{"currentPassword":"old-pass","newPassword":"new-pass","confirmPassword":"new-pass"}',
    )
    sent_bodies: list[dict] = []

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        sent_bodies.append(kwargs.get("json_body"))
        return ResponseData(
            200, {"content-type": "application/json"},
            '{"success":true,"message":"password changed"}', 5.0,
            request_snippet=f"{method} {url}", response_snippet="HTTP/1.1 200 OK",
        )

    with patch.object(HttpVerifier, "send_request", send_request):
        findings = await detector.detect(
            urls=[], forms=[], requests=[request],
            auth_headers={"Authorization": "Bearer low-user-token"},
        )

    assert any(f.vuln_type == "Password Change API Does Not Enforce Current Password" for f in findings)
    # The current-password field was actually stripped from the replayed body.
    assert sent_bodies and "currentPassword" not in sent_bodies[0]
    assert "newPassword" in sent_bodies[0]


@pytest.mark.asyncio
async def test_password_change_enforcement_probe_no_finding_when_rejected():
    detector = AuthenticationFailuresDetector()
    request = RequestObservation(
        url="https://example.test/api/account/change-password",
        method="POST",
        request_headers={"content-type": "application/json"},
        post_data='{"currentPassword":"old-pass","newPassword":"new-pass"}',
    )

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        return ResponseData(
            400, {"content-type": "application/json"},
            '{"error":"current password required"}', 5.0,
        )

    with patch.object(HttpVerifier, "send_request", send_request):
        findings = await detector.detect(
            urls=[], forms=[], requests=[request],
            auth_headers={"Authorization": "Bearer low-user-token"},
        )

    assert not any(f.vuln_type == "Password Change API Does Not Enforce Current Password" for f in findings)


@pytest.mark.asyncio
async def test_security_question_weak_recovery_is_flagged():
    """A reset flow gated only on a security-answer field (no token/OTP) is flagged
    as weak recovery — a structural finding, no answer is guessed."""
    detector = AuthenticationFailuresDetector()
    endpoint = ApiEndpoint(
        url="https://example.test/api/password/reset",
        method="POST",
        request_body={"email": "a@b.test", "securityAnswer": "blue", "newPassword": "x"},
    )

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        # Reject the token-enforcement probe so only the structural finding remains.
        return ResponseData(400, {"content-type": "application/json"}, '{"error":"invalid"}', 5.0)

    with patch.object(HttpVerifier, "send_request", send_request):
        findings = await detector.detect(urls=[], forms=[], api_endpoints=[endpoint])

    assert any(
        f.vuln_type == "Password Reset Relies on Security Question (Weak Recovery)"
        for f in findings
    )


@pytest.mark.asyncio
async def test_security_question_not_flagged_when_token_present():
    detector = AuthenticationFailuresDetector()
    endpoint = ApiEndpoint(
        url="https://example.test/api/password/reset",
        method="POST",
        request_body={"securityAnswer": "blue", "newPassword": "x", "resetToken": "abc123"},
    )

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        return ResponseData(400, {"content-type": "application/json"}, '{"error":"invalid"}', 5.0)

    with patch.object(HttpVerifier, "send_request", send_request):
        findings = await detector.detect(urls=[], forms=[], api_endpoints=[endpoint])

    assert not any(
        f.vuln_type == "Password Reset Relies on Security Question (Weak Recovery)"
        for f in findings
    )


@pytest.mark.asyncio
async def test_active_jwt_forgery_flagged_when_forged_token_accepted():
    """Forged alg=none token accepted by a bearer-protected endpoint → verified."""
    real = _jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "u", "role": "user", "exp": int(time.time()) + 3600})
    detector = AuthenticationFailuresDetector()
    oracle_request = RequestObservation(
        url="https://example.test/api/profile",
        method="GET",
        request_headers={"authorization": f"Bearer {real}"},
    )

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        phase = kwargs.get("test_phase", "")
        if phase == "jwt_forgery_noauth":
            return ResponseData(401, {}, "Unauthorized", 5.0)
        if phase == "jwt_forgery_baseline":
            return ResponseData(200, {}, '{"user":"u"}', 5.0)
        if phase == "jwt_forgery_attempt":
            return ResponseData(200, {}, '{"user":"u"}', 5.0,
                                request_snippet=f"{method} {url}", response_snippet="HTTP/1.1 200 OK")
        return ResponseData(200, {}, "", 5.0)

    with patch.object(HttpVerifier, "send_request", send_request):
        findings = await detector.detect(
            urls=[], forms=[], requests=[oracle_request],
            auth_headers={"Authorization": f"Bearer {real}"},
            root_url="https://example.test/",
        )

    forgery = [f for f in findings if f.vuln_type == "JWT alg=none Forgery Accepted"]
    assert forgery, [f.vuln_type for f in findings]
    assert forgery[0].verified is True
    assert forgery[0].severity == SeverityLevel.critical


@pytest.mark.asyncio
async def test_active_jwt_forgery_not_flagged_when_forged_token_rejected():
    real = _jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "u", "exp": int(time.time()) + 3600})
    detector = AuthenticationFailuresDetector()
    oracle_request = RequestObservation(
        url="https://example.test/api/profile",
        method="GET",
        request_headers={"authorization": f"Bearer {real}"},
    )

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        phase = kwargs.get("test_phase", "")
        if phase == "jwt_forgery_noauth":
            return ResponseData(401, {}, "Unauthorized", 5.0)
        if phase == "jwt_forgery_baseline":
            return ResponseData(200, {}, '{"user":"u"}', 5.0)
        if phase == "jwt_forgery_attempt":
            return ResponseData(401, {}, "Unauthorized", 5.0)  # forged rejected
        return ResponseData(200, {}, "", 5.0)

    with patch.object(HttpVerifier, "send_request", send_request):
        findings = await detector.detect(
            urls=[], forms=[], requests=[oracle_request],
            auth_headers={"Authorization": f"Bearer {real}"},
            root_url="https://example.test/",
        )

    assert not any("Forgery Accepted" in f.vuln_type for f in findings)


@pytest.mark.asyncio
async def test_active_jwt_forgery_requires_protected_oracle():
    """No bearer-protected GET oracle observed → forgery test does not run."""
    real = _jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "u", "exp": int(time.time()) + 3600})
    detector = AuthenticationFailuresDetector()
    sent_phases: list[str] = []

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        sent_phases.append(kwargs.get("test_phase", ""))
        return ResponseData(200, {}, "{}", 5.0)

    with patch.object(HttpVerifier, "send_request", send_request):
        await detector.detect(
            urls=[], forms=[],
            auth_headers={"Authorization": f"Bearer {real}"},
            root_url="https://example.test/",
        )

    assert not any(p.startswith("jwt_forgery") for p in sent_phases)


def test_credential_disclosure_ignores_reflected_sql_query_echo() -> None:
    # A SQLi/LFI source finding surfaces a DB error that echoes the app's own
    # query (``... WHERE email = '<payload>' AND password = '<hash>' ...``). The
    # ``password =`` there is a SQL comparison in a reflected statement, not a
    # disclosed credential — it must NOT be re-reported as credential disclosure.
    detector = AuthenticationFailuresDetector()
    source = Finding(
        category=OwaspCategory.a05,
        vuln_type="SQL Injection (Error-Based)",
        severity=SeverityLevel.critical,
        url="https://example.test/rest/user/login",
        method="POST",
        payload="' AND extractvalue(1,concat(0x7e,(SELECT @@version)))--",
        verification_response_snippet=(
            "SQLITE_ERROR: unrecognized token: \"@\" | "
            "SELECT * FROM Users WHERE email = 'a@b' AND password = "
            "'35fddb24066434f0a68b74fa50b9be61' AND deletedAt IS NULL"
        ),
        verified=True,
    )
    findings = detector.findings_from_observed_evidence([source])
    assert not any(
        f.vuln_type == "Credential / Config Disclosure in Response Body" for f in findings
    )


def test_credential_disclosure_still_flags_config_key_leak() -> None:
    # A genuine config/credential key leaked outside any SQL statement is still
    # reported — the guard only strips reflected SQL comparisons.
    detector = AuthenticationFailuresDetector()
    source = Finding(
        category=OwaspCategory.a05,
        vuln_type="Local File Inclusion",
        severity=SeverityLevel.high,
        url="https://example.test/download?file=../.env",
        method="GET",
        payload="../.env",
        verification_response_snippet=(
            "DB_PASSWORD=sup3rs3cr3t\nAPP_KEY=base64:abcdef\nMAIL_HOST=smtp"
        ),
        verified=True,
    )
    findings = detector.findings_from_observed_evidence([source])
    assert any(
        f.vuln_type == "Credential / Config Disclosure in Response Body" for f in findings
    )


# ---------------------------------------------------------------------------
# Default / weak credential probing (JSON API login)
# ---------------------------------------------------------------------------

def test_harvest_login_identities_prefers_app_domain_over_scanner_domain():
    detector = AuthenticationFailuresDetector()
    # The scanner's own account is on an unrelated domain; the app's real user
    # domain is only observable in a response body (product reviews here).
    reviews = RequestObservation(
        url="https://shop.test/rest/products/1/reviews",
        method="GET",
        response_snippet='{"data":[{"author":"admin@shop.test"},{"author":"basil@shop.test"}]}',
    )
    kwargs = {
        "root_url": "https://shop.test",
        "requests": [reviews],
        # simulate scanner's own identity via a JWT email claim on a foreign domain
        "auth_headers": {},
    }
    with patch.object(get_settings(), "authentication_username", "pentester@gmail.com", create=False):
        emails, usernames, domains = detector._harvest_login_identities(kwargs, {})
    assert "shop.test" in domains
    # app domain (2 observed emails) ranks before the scanner's personal domain
    assert domains[0] == "shop.test"
    assert any(e.lower() == "admin@shop.test" for e in emails)


def test_build_credential_candidates_probes_admin_at_app_domain_early():
    detector = AuthenticationFailuresDetector()
    pairs = detector._build_credential_candidates(
        emails=["admin@shop.test"], usernames=[], domains=["shop.test"], email_login=True
    )
    idx = pairs.index(("admin@shop.test", "admin123"))
    assert idx < detector._MAX_CRED_ATTEMPTS  # reached within the live attempt cap


def test_looks_like_auth_success_discriminates_token_from_denial():
    detector = AuthenticationFailuresDetector()
    # 200 + token, baseline was 401 -> accepted
    assert detector._looks_like_auth_success(200, '{"authentication":{"token":"eyAAAAAAAAAA.BBBBBBBBBB.cc"}}', 401)
    # 401 rejection -> not accepted
    assert not detector._looks_like_auth_success(401, '{"error":"Invalid email or password"}', 401)
    # 200 with no token where baseline was also 200 (accept-anything) -> not accepted
    assert not detector._looks_like_auth_success(200, '{"status":"ok"}', 200)


@pytest.mark.asyncio
async def test_api_default_credentials_detected_via_harvested_domain():
    detector = AuthenticationFailuresDetector()
    # App domain harvested from an observed response; only admin@shop.test/admin123 works.
    reviews = RequestObservation(
        url="https://shop.test/rest/products/1/reviews",
        method="GET",
        response_snippet='{"data":[{"author":"admin@shop.test"}]}',
    )
    endpoint = ApiEndpoint(
        url="https://shop.test/rest/user/login",
        method="POST",
        request_body={"email": "seed@x.io", "password": "seed"},
    )

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        body = kwargs.get("json_body") or {}
        if body.get("email") == "admin@shop.test" and body.get("password") == "admin123":
            return ResponseData(200, {"content-type": "application/json"},
                                 '{"authentication":{"token":"eyAAAAAAAAAA.BBBBBBBBBB.cc"}}', 8.0,
                                 request_snippet=f"{method} {url}", response_snippet="200")
        return ResponseData(401, {"content-type": "application/json"},
                            '{"error":"Invalid email or password"}', 8.0,
                            request_snippet=f"{method} {url}", response_snippet="401")

    with patch.object(HttpVerifier, "send_request", send_request):
        with patch.object(get_settings(), "authentication_username", "pentester@gmail.com", create=False):
            findings = await detector.detect(
                urls=[], forms=[], api_endpoints=[endpoint], requests=[reviews], root_url="https://shop.test",
            )
    dc = [f for f in findings if f.vuln_type == "Default Credentials Accepted"]
    assert len(dc) == 1
    assert dc[0].payload == "admin@shop.test:admin123"
    assert dc[0].severity == SeverityLevel.critical
    assert dc[0].verified is True


@pytest.mark.asyncio
async def test_api_default_credentials_no_false_positive_when_all_rejected():
    detector = AuthenticationFailuresDetector()
    reviews = RequestObservation(
        url="https://shop.test/rest/products/1/reviews",
        method="GET",
        response_snippet='{"data":[{"author":"admin@shop.test"}]}',
    )
    endpoint = ApiEndpoint(
        url="https://shop.test/rest/user/login",
        method="POST",
        request_body={"email": "seed@x.io", "password": "seed"},
    )

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        # Every credential is rejected (no weak/default creds on this target).
        return ResponseData(401, {"content-type": "application/json"},
                            '{"error":"Invalid email or password"}', 8.0,
                            request_snippet=f"{method} {url}", response_snippet="401")

    with patch.object(HttpVerifier, "send_request", send_request):
        findings = await detector.detect(
            urls=[], forms=[], api_endpoints=[endpoint], requests=[reviews], root_url="https://shop.test",
        )
    assert not any(f.vuln_type == "Default Credentials Accepted" for f in findings)


# ---------------------------------------------------------------------------
# Framework-agnostic login coverage (SPA shell skip + non-SPA form default creds)
# ---------------------------------------------------------------------------

def _login_form(action: str):
    return SimpleNamespace(
        action=action,
        method="POST",
        page_url=action,
        inputs=[
            SimpleNamespace(name="email", input_type="text", value=""),
            SimpleNamespace(name="password", input_type="password", value=""),
        ],
    )


@pytest.mark.asyncio
async def test_active_auth_skipped_for_spa_shell_hash_route_form():
    # A form whose action is a client-side hash route posts to the SPA shell; the
    # detector must NOT run its volume probe there (it would report a misleading
    # "no brute-force protection" against the app index for every attempt).
    detector = AuthenticationFailuresDetector()
    hits = 0

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        nonlocal hits
        hits += 1
        return ResponseData(200, {"content-type": "text/html"}, "<html>app shell</html>", 5.0,
                            request_snippet="", response_snippet="")

    form = _login_form("https://spa.test/#/login")
    with patch.object(HttpVerifier, "send_request", send_request):
        findings = await detector.detect(urls=[], forms=[form], is_spa=True)

    assert hits == 0  # no live probing against the shell
    assert not any(f.vuln_type == "Lack of Brute-Force Protection on Login Form" for f in findings)


@pytest.mark.asyncio
async def test_non_spa_form_default_credentials_via_harvested_domain():
    # A traditional (non-SPA) HTML form login authenticating by e-mail: the weak
    # admin credential is detected using the app domain harvested from an observed
    # response, exactly as for the JSON API path.
    detector = AuthenticationFailuresDetector()
    reviews = RequestObservation(
        url="https://shop.test/rest/products/1/reviews", method="GET",
        response_snippet='{"data":[{"author":"admin@shop.test"}]}',
    )
    form = _login_form("https://shop.test/login")  # real server action, not a hash route

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        body = data or {}
        if body.get("email") == "admin@shop.test" and body.get("password") == "admin123":
            return ResponseData(302, {"location": "/dashboard"}, "", 5.0,
                                request_snippet="", response_snippet="302")
        return ResponseData(401, {"content-type": "text/html"},
                            "<html>Invalid email or password</html>", 5.0,
                            request_snippet="", response_snippet="401")

    with patch.object(HttpVerifier, "send_request", send_request):
        with patch.object(get_settings(), "authentication_username", "pentester@gmail.com", create=False):
            findings = await detector.detect(urls=[], forms=[form], requests=[reviews], root_url="https://shop.test")

    dc = [f for f in findings if f.vuln_type == "Default Credentials Accepted"]
    assert len(dc) == 1
    assert "admin@shop.test" in dc[0].payload and "admin123" in dc[0].payload
