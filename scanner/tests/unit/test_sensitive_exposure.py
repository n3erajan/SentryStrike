from types import SimpleNamespace

import asyncio

import httpx
import pytest

from app.core.crawler.models import RequestObservation, RouteCandidate, RouteSource
from app.core.detectors.sensitive_paths import SensitivePathsDetector
from shared.models.vulnerability import SeverityLevel


def test_observed_response_finds_source_map_api_docs_stack_trace_and_secret_values():
    detector = SensitivePathsDetector()
    requests = [
        RequestObservation(
            url="https://example.test/static/app.js.map",
            method="GET",
            response_content_type="application/json",
            response_snippet='{"version":3,"sources":["src/app.ts"],"mappings":"AAAA"}',
        ),
        RequestObservation(
            url="https://example.test/openapi.json",
            method="GET",
            response_content_type="application/json",
            response_snippet='{"openapi":"3.0.0","paths":{"/api/users":{"get":{}}}}',
        ),
        RequestObservation(
            url="https://example.test/api/error",
            method="GET",
            response_content_type="text/plain",
            response_snippet="Traceback (most recent call last):\n  File \"app.py\", line 1",
        ),
        RequestObservation(
            url="https://example.test/api/config",
            method="GET",
            response_content_type="application/json",
            response_snippet='{"client_secret":"super-secret-value-12345"}',
        ),
    ]

    findings = detector._observed_response_findings({"requests": requests})
    vuln_types = {finding.vuln_type for finding in findings}

    assert "Exposed Source Map" in vuln_types
    assert "Exposed API Documentation" in vuln_types
    assert "Verbose Stack Trace Exposure" in vuln_types
    assert "Secret-Like Value Exposure" in vuln_types
    api_docs = next(finding for finding in findings if finding.vuln_type == "Exposed API Documentation")
    assert api_docs.severity == SeverityLevel.info
    source_map = next(finding for finding in findings if finding.vuln_type == "Exposed Source Map")
    assert source_map.severity == SeverityLevel.info
    assert all(finding.detection_evidence["proof_type"] == "content_verified_observed_response" for finding in findings)
    # Each finding is derived from a real observed request, so it must carry a
    # reconstructed request snippet (not left empty).
    for finding in findings:
        assert finding.verification_request_snippet, finding.vuln_type
        assert finding.verification_request_snippet.startswith("GET /")


def test_plain_env_without_secret_pattern_is_not_classified_as_sensitive():
    detector = SensitivePathsDetector()

    result = detector._classify_content("/.env", "APP_ENV=production\nDEBUG=false", "text/plain")

    assert result.matched is False


def test_application_data_field_named_scoreboard_is_not_debug_metrics():
    # The Apache mod_status marker is the whole word "Scoreboard:"; an
    # application data field whose name merely contains the substring (e.g.
    # {"key":"scoreBoardChallenge"}) is not a debug/metrics endpoint. Word
    # boundaries keep the marker precise without hardcoding any app's schema.
    detector = SensitivePathsDetector()
    body = '{"status":"success","data":[{"id":75,"key":"scoreBoardChallenge","name":"Score Board"}]}'

    result = detector._classify_content("/api/Challenges/", body, "application/json")

    assert result.matched is False


def test_htaccess_with_directives_is_sensitive_file_exposure():
    # .htaccess exposure moved from the forced-browsing (A01) detector to
    # sensitive_paths (A02) - it is accidental config-file exposure, not a
    # bypassed access control. A body carrying real Apache directives confirms it.
    detector = SensitivePathsDetector()
    body = "RewriteEngine On\nRewriteRule ^(.*)$ index.php [L]\n<Files ~ \"\\.inc$\">\nDeny from all\n</Files>"

    result = detector._classify_content(
        "/.htaccess", body, "text/plain"
    )

    assert result.matched is True
    assert result.vuln_type == "Sensitive File Exposure"
    assert result.severity == SeverityLevel.medium


def test_htaccess_path_without_directives_is_not_flagged():
    # A path that merely contains ".htaccess" but returns ordinary page content
    # (no Apache directives) must not be classified - avoids false positives on
    # soft-404 / app pages.
    detector = SensitivePathsDetector()

    result = detector._classify_content(
        "/.htaccess", "<html><body>Not Found</body></html>", "text/html"
    )

    assert result.matched is False


def test_apache_server_status_scoreboard_is_still_debug_metrics():
    detector = SensitivePathsDetector()
    body = "Apache Server Status for localhost\nScoreboard: _W_W..CC____\n"

    result = detector._classify_content(
        "/server-status", body, "text/html"
    )

    assert result.matched is True
    assert result.vuln_type == "Debug / Metrics Endpoint Exposed"


def test_spa_fallback_context_is_metadata_not_vulnerability():
    detector = SensitivePathsDetector()
    route = RouteCandidate(
        url="https://example.test/admin",
        source=RouteSource.javascript,
        is_spa_fallback=True,
    )

    findings = detector._spa_fallback_context_findings(
        {"root_url": "https://example.test/", "dead_routes": [route]}
    )

    assert findings == []


@pytest.mark.asyncio
async def test_sensitive_path_detector_requires_content_fingerprint_for_env(monkeypatch):
    detector = SensitivePathsDetector()

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def get(self, url):
            if url.endswith("/.env"):
                return httpx.Response(
                    200,
                    text="APP_ENV=production\nDEBUG=false",
                    headers={"content-type": "text/plain"},
                    request=httpx.Request("GET", url),
                )
            return httpx.Response(404, text="not found", request=httpx.Request("GET", url))

    monkeypatch.setattr("app.core.detectors.sensitive_paths.create_scan_client", lambda **kwargs: FakeClient())

    findings = await detector.detect(urls=["https://example.test/"], forms=[], root_url="https://example.test/")

    assert not any(finding.url.endswith("/.env") for finding in findings)


@pytest.mark.asyncio
async def test_sensitive_path_detector_reports_openapi_with_content_proof(monkeypatch):
    detector = SensitivePathsDetector()

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def get(self, url):
            if url.endswith("/openapi.json"):
                return httpx.Response(
                    200,
                    text='{"openapi":"3.0.0","paths":{"/api/users":{"get":{}}}}',
                    headers={"content-type": "application/json"},
                    request=httpx.Request("GET", url),
                )
            return httpx.Response(404, text="not found", request=httpx.Request("GET", url))

    monkeypatch.setattr("app.core.detectors.sensitive_paths.create_scan_client", lambda **kwargs: FakeClient())

    findings = await detector.detect(urls=["https://example.test/"], forms=[], root_url="https://example.test/")

    assert any(finding.vuln_type == "Exposed API Documentation" for finding in findings)
    assert any(
        finding.detection_evidence["proof_type"] == "content_verified_path_probe"
        for finding in findings
    )
    # The path_content_fingerprint snippet must be HTTP-formatted
    # ("GET <path> HTTP/1.1\nHost: …"), not the old bare "GET <absolute-url>".
    api_docs = next(
        (f for f in findings if f.vuln_type == "Exposed API Documentation"), None
    )
    assert api_docs is not None
    assert api_docs.severity == SeverityLevel.info
    assert api_docs.verification_request_snippet is not None
    assert api_docs.verification_request_snippet.startswith("GET /openapi.json HTTP/1.1\nHost:")
    assert "example.test" in api_docs.verification_request_snippet


@pytest.mark.asyncio
async def test_focused_sensitive_path_probe_replays_exact_authenticated_url(monkeypatch):
    detector = SensitivePathsDetector()
    requested_urls: list[str] = []
    client_options: dict[str, object] = {}

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def get(self, url):
            requested_urls.append(url)
            return httpx.Response(
                200,
                text="<html><body>Swagger UI</body></html>",
                headers={"content-type": "text/html"},
                request=httpx.Request("GET", url),
            )

    def fake_client_factory(**kwargs):
        client_options.update(kwargs)
        return FakeClient()

    monkeypatch.setattr(
        "app.core.detectors.sensitive_paths.create_scan_client",
        fake_client_factory,
    )
    target_url = "https://example.test/custom/internal/api-docs/"

    findings = await detector.detect(
        urls=[target_url],
        forms=[],
        root_url="https://example.test/",
        focused_probe_urls=[target_url],
        session_cookies={"session": "cookie-value"},
        auth_headers={"Authorization": "Bearer token-value"},
    )

    # The authenticated probe, then one credential-free re-probe of the SAME
    # URL: the focused URL must be replayed verbatim in both cases, and the
    # second request is what establishes whether a session was needed at all.
    assert requested_urls == [target_url, target_url]
    assert client_options["cookies"] == {"session": "cookie-value"}
    assert client_options["headers"] == {"Authorization": "Bearer token-value"}
    assert [finding.vuln_type for finding in findings] == ["Exposed API Documentation"]


def test_classify_content_detects_apache_autoindex():
    detector = SensitivePathsDetector()
    body = (
        "<html><head><title>Index of /uploads</title></head><body>"
        "<h1>Index of /uploads</h1><pre>"
        '<a href="../">../</a>'
        '<a href="report.pdf">report.pdf</a>'
        '<a href="notes.txt">notes.txt</a>'
        "</pre></body></html>"
    )

    result = detector._classify_content(
        "/uploads/", body, "text/html"
    )

    assert result.matched is True
    assert result.vuln_type == "Directory Listing Exposed"
    assert result.severity == SeverityLevel.medium


def test_classify_content_does_not_flag_regular_html_as_autoindex():
    detector = SensitivePathsDetector()
    body = "<html><body><h1>Welcome</h1><p>Nothing to list here.</p></body></html>"

    result = detector._classify_content("/home", body, "text/html")

    assert result.matched is False


def test_permutation_targets_derive_backup_and_dir_probes_from_crawl():
    detector = SensitivePathsDetector()

    targets = detector._permutation_targets(
        "https://example.test/",
        ["https://example.test/js/config.js", "https://other.test/evil.js"],
        {"assets": ["https://example.test/static/app.js"]},
    )

    # Backup permutation of a crawled file.
    assert "https://example.test/js/config.js.bak" in targets
    assert "https://example.test/static/app.js.old" in targets
    # Trailing-slash directory listing probe.
    assert "https://example.test/js/" in targets
    # Cross-origin URLs are excluded.
    assert not any("other.test" in t for t in targets)


@pytest.mark.asyncio
async def test_sensitive_path_detector_reports_autoindex_via_permutation(monkeypatch):
    detector = SensitivePathsDetector()

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def get(self, url):
            if url == "https://example.test/uploads/":
                return httpx.Response(
                    200,
                    text=(
                        "<html><head><title>Index of /uploads</title></head><body>"
                        "<h1>Index of /uploads</h1><pre>"
                        '<a href="../">../</a>'
                        '<a href="a.txt">a.txt</a>'
                        "</pre></body></html>"
                    ),
                    headers={"content-type": "text/html"},
                    request=httpx.Request("GET", url),
                )
            return httpx.Response(404, text="not found", request=httpx.Request("GET", url))

    monkeypatch.setattr("app.core.detectors.sensitive_paths.create_scan_client", lambda **kwargs: FakeClient())

    findings = await detector.detect(
        urls=["https://example.test/uploads/report.pdf"],
        forms=[],
        root_url="https://example.test/",
    )

    assert any(finding.vuln_type == "Directory Listing Exposed" for finding in findings)
    assert any(finding.url == "https://example.test/uploads/" for finding in findings)


@pytest.mark.asyncio
async def test_sensitive_path_detector_suppresses_spa_shell_200(monkeypatch):
    detector = SensitivePathsDetector()

    spa_shell = (
        "<!doctype html><html><head><title>My SPA</title></head>"
        "<body><div id='root'></div><script src='/main.js'></script></body></html>"
    )

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def get(self, url):
            # SPA catch-all: every path returns the same 200 HTML shell.
            return httpx.Response(
                200,
                text=spa_shell,
                headers={"content-type": "text/html"},
                request=httpx.Request("GET", url),
            )

    monkeypatch.setattr("app.core.detectors.sensitive_paths.create_scan_client", lambda **kwargs: FakeClient())

    findings = await detector.detect(
        urls=["https://example.test/"],
        forms=[],
        root_url="https://example.test/",
        is_spa=True,
        spa_root_html=spa_shell,
    )

    assert findings == []


# --------------------------------------------------------------------------- #
# Dependency-manifest content classification
# --------------------------------------------------------------------------- #

_PKG_JSON = '{"name":"demo","version":"1.0.0","dependencies":{"express":"^4.18.2"}}'
_REQ_TXT = "Django==4.2.1\nFlask>=2.3\n"


@pytest.mark.parametrize(
    "path, body, expected",
    [
        ("/package.json", _PKG_JSON, True),                 # standard manifest
        ("/ftp/package.json", _PKG_JSON, True),             # nested manifest
        ("/requirements.txt", _REQ_TXT, True),
        # Backup/temp/version suffixes on a manifest still classify (universal
        # file-management conventions, not app-specific paths).
        ("/ftp/package.json.bak", _PKG_JSON, True),
        ("/composer.lock.old", '{"packages":[{"name":"x","version":"1.0"}]}', True),
        ("/package.json~", _PKG_JSON, True),
        ("/requirements.txt.1", _REQ_TXT, True),
        # Manifest-named path but body is NOT manifest content -> not flagged.
        ("/package.json", "<html>not a manifest</html>", False),
        # Manifest-looking body at a non-manifest path -> not flagged (no FP on
        # an ordinary API JSON response that happens to mention dependencies).
        ("/rest/products/1/reviews", '{"status":"success","data":[]}', False),
        ("/api/config", '{"dependencies":{"a":"1"}}', False),
    ],
)
def test_dependency_manifest_classification(path, body, expected):
    det = SensitivePathsDetector()
    assert det._looks_like_dependency_manifest(path, body) is expected


def test_dependency_manifest_reachability_is_informational():
    det = SensitivePathsDetector()

    result = det._classify_content(
        "/package.json", _PKG_JSON, "application/json"
    )

    assert result.matched is True
    assert result.vuln_type == "Sensitive File Exposure"
    assert result.severity == SeverityLevel.info


# ---------------------------------------------------------------------------
# Version-control repository escalation
# ---------------------------------------------------------------------------

_GIT_ROOT_LISTING = (
    "<html><head><title>Index of /app/.git</title></head><body>"
    "<h1>Index of /app/.git</h1><pre>"
    '<a href="../">Parent Directory</a>'
    '<a href="branches/">branches/</a>'
    '<a href="config">config</a>'
    '<a href="description">description</a>'
    '<a href="HEAD">HEAD</a>'
    '<a href="hooks/">hooks/</a>'
    '<a href="objects/">objects/</a>'
    '<a href="refs/">refs/</a>'
    "</pre></body></html>"
)


def test_classify_content_escalates_git_autoindex_to_repository_exposure():
    detector = SensitivePathsDetector()

    result = detector._classify_content(
        "/app/.git/", _GIT_ROOT_LISTING, "text/html"
    )

    assert result.matched is True
    assert result.vuln_type == "Version Control Repository Exposed"
    assert result.severity == SeverityLevel.high


def test_git_object_shard_stays_a_plain_listing():
    """A shard directory holds only hashes, so it proves nothing structurally."""
    detector = SensitivePathsDetector()
    body = (
        "<html><head><title>Index of /app/.git/objects/d4</title></head><body>"
        "<h1>Index of /app/.git/objects/d4</h1><pre>"
        '<a href="../">Parent Directory</a>'
        '<a href="1b2c3d4e5f6a7b8c9d0e">1b2c3d4e5f6a7b8c9d0e</a>'
        '<a href="9f8e7d6c5b4a39281706">9f8e7d6c5b4a39281706</a>'
        "</pre></body></html>"
    )

    result = detector._classify_content(
        "/app/.git/objects/d4/", body, "text/html"
    )

    assert result.vuln_type == "Directory Listing Exposed"


def test_directory_named_like_git_without_repository_contents_is_not_escalated():
    """The escalation must rest on observed contents, never on the path alone."""
    detector = SensitivePathsDetector()
    body = (
        "<html><head><title>Index of /docs/.git-tutorial</title></head><body>"
        "<h1>Index of /docs/.git-tutorial</h1><pre>"
        '<a href="../">Parent Directory</a>'
        '<a href="lesson-one.md">lesson-one.md</a>'
        '<a href="lesson-two.md">lesson-two.md</a>'
        '<a href="lesson-three.md">lesson-three.md</a>'
        '<a href="lesson-four.md">lesson-four.md</a>'
        "</pre></body></html>"
    )

    result = detector._classify_content(
        "/docs/.git-tutorial/", body, "text/html"
    )

    assert result.vuln_type == "Directory Listing Exposed"


def test_html_head_element_is_not_mistaken_for_git_head():
    """Markers match listing hrefs, so page markup cannot fake repository proof.

    Uses a genuine `.git` path so the segment test passes and the marker test is
    what actually decides: the only "HEAD" here is the HTML `<head>` element.
    """
    detector = SensitivePathsDetector()
    body = (
        "<html><head><title>Index of /app/.git/refs/heads</title></head><body>"
        "<h1>Index of /app/.git/refs/heads</h1><pre>"
        '<a href="../">Parent Directory</a>'
        '<a href="main">main</a>'
        '<a href="develop">develop</a>'
        '<a href="release-2.1">release-2.1</a>'
        '<a href="hotfix">hotfix</a>'
        "</pre></body></html>"
    )

    assert detector._looks_like_vcs_repository("/app/.git/refs/heads/", body, "text/html") is False


def test_vcs_path_match_requires_an_exact_segment():
    """`.git-tutorial` is an ordinary directory that shares a prefix."""
    detector = SensitivePathsDetector()

    assert detector._has_vcs_path_segment("/app/.git/objects/") is True
    assert detector._has_vcs_path_segment("/app/.svn/") is True
    assert detector._has_vcs_path_segment("/docs/.git-tutorial/") is False
    assert detector._has_vcs_path_segment("/assets/.git-icons/") is False
    assert detector._has_vcs_path_segment("/digital/") is False


# ---------------------------------------------------------------------------
# Listing tree collapse
# ---------------------------------------------------------------------------

def _listing(url: str, vuln_type: str = "Directory Listing Exposed"):
    detector = SensitivePathsDetector()
    return detector._finding(
        vuln_type=vuln_type,
        severity=SeverityLevel.medium,
        url=url,
        evidence="listing",
        detection_method="path_content_fingerprint",
        proof_type="content_verified_path_probe",
    )


def test_collapse_folds_git_tree_into_single_repository_finding():
    """The DVWA shape: one exposed .git tree produced 18 separate findings."""
    detector = SensitivePathsDetector()
    root = "http://target.test/dvwa/.git/"
    descendants = [
        f"{root}{suffix}"
        for suffix in (
            "objects/", "objects/d4/", "objects/a4/", "objects/62/",
            "objects/pack/", "objects/info/", "refs/", "refs/heads/",
            "refs/tags/", "refs/remotes/", "refs/remotes/origin/",
            "logs/", "logs/refs/", "logs/refs/heads/", "logs/refs/remotes/",
            "info/", "hooks/", "branches/",
        )
    ]
    findings = [_listing(root, "Version Control Repository Exposed")] + [
        _listing(url) for url in descendants
    ]

    collapsed = detector._collapse_listing_trees(findings)

    assert len(collapsed) == 1
    survivor = collapsed[0]
    assert survivor.url == root
    assert survivor.vuln_type == "Version Control Repository Exposed"
    assert survivor.detection_evidence["folded_directory_count"] == 18
    assert "18 descendant directories" in survivor.evidence


def test_collapse_keeps_unrelated_trees_separate():
    detector = SensitivePathsDetector()
    findings = [
        _listing("http://target.test/dvwa/.git/", "Version Control Repository Exposed"),
        _listing("http://target.test/dvwa/.git/refs/"),
        _listing("http://target.test/dvwa/config/"),
        _listing("http://target.test/dvwa/dvwa/js/"),
    ]

    collapsed = detector._collapse_listing_trees(findings)

    assert {f.url for f in collapsed} == {
        "http://target.test/dvwa/.git/",
        "http://target.test/dvwa/config/",
        "http://target.test/dvwa/dvwa/js/",
    }


def test_collapse_matches_on_directory_boundaries_only():
    """/config/ must never absorb the sibling /config2/."""
    detector = SensitivePathsDetector()
    findings = [
        _listing("http://target.test/config/"),
        _listing("http://target.test/config2/"),
    ]

    collapsed = detector._collapse_listing_trees(findings)

    assert len(collapsed) == 2


def test_collapse_uses_deepest_reachable_root_when_parent_is_forbidden():
    """Only listings actually produced are candidates; a 403 parent is absent."""
    detector = SensitivePathsDetector()
    findings = [
        _listing("http://target.test/app/.git/objects/"),
        _listing("http://target.test/app/.git/objects/d4/"),
        _listing("http://target.test/app/.git/objects/pack/"),
    ]

    collapsed = detector._collapse_listing_trees(findings)

    assert [f.url for f in collapsed] == ["http://target.test/app/.git/objects/"]


def test_collapse_separates_distinct_origins():
    detector = SensitivePathsDetector()
    findings = [
        _listing("http://a.test/shared/"),
        _listing("http://b.test/shared/nested/"),
    ]

    collapsed = detector._collapse_listing_trees(findings)

    assert len(collapsed) == 2


def test_collapse_leaves_non_listing_findings_untouched():
    detector = SensitivePathsDetector()
    secret = _listing("http://target.test/.env", "Sensitive File Exposure")
    findings = [
        secret,
        _listing("http://target.test/files/"),
        _listing("http://target.test/files/inner/"),
    ]

    collapsed = detector._collapse_listing_trees(findings)

    assert secret in collapsed
    assert len(collapsed) == 2


def test_collapse_promotes_repository_proof_found_in_a_descendant():
    """A partial root listing must not bury proof found deeper in the tree.

    Observed on the DVWA report: the `.git/` root index was truncated before
    enough entries appeared, while `.git/logs/` clearly showed repository
    structure. Folding without promotion reports a browsable folder and loses
    the fact that the source repository is retrievable.
    """
    detector = SensitivePathsDetector()
    root = _listing("http://target.test/app/.git/")
    findings = [
        root,
        _listing("http://target.test/app/.git/logs/", "Version Control Repository Exposed"),
        _listing("http://target.test/app/.git/refs/"),
    ]

    collapsed = detector._collapse_listing_trees(findings)

    assert len(collapsed) == 1
    survivor = collapsed[0]
    # Reported at the tree root, but classified on the strongest evidence found.
    assert survivor.url == "http://target.test/app/.git/"
    assert survivor.vuln_type == "Version Control Repository Exposed"
    assert survivor.severity == SeverityLevel.high
    assert "/app/.git/logs/" in survivor.evidence


def test_collapse_does_not_invent_repository_proof():
    """Promotion fires only on a confirmed descendant, never on path shape."""
    detector = SensitivePathsDetector()
    findings = [
        _listing("http://target.test/app/.git/"),
        _listing("http://target.test/app/.git/refs/"),
    ]

    collapsed = detector._collapse_listing_trees(findings)

    assert len(collapsed) == 1
    assert collapsed[0].vuln_type == "Directory Listing Exposed"
    assert collapsed[0].severity == SeverityLevel.medium


# ---------------------------------------------------------------------------
# Anonymous-reachability probe
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_confirm_anonymous_access_true_when_exposure_survives_without_session():
    detector = SensitivePathsDetector()

    class AnonClient:
        async def get(self, url):
            return httpx.Response(
                200,
                text=_GIT_ROOT_LISTING,
                headers={"content-type": "text/html"},
                request=httpx.Request("GET", url),
            )

    confirmed = await detector._confirm_anonymous_access(
        AnonClient(),
        "http://target.test/app/.git/",
        "/app/.git/",
        "Version Control Repository Exposed",
    )

    assert confirmed is True


@pytest.mark.asyncio
async def test_confirm_anonymous_access_false_when_session_is_actually_required():
    detector = SensitivePathsDetector()

    class RedirectingClient:
        async def get(self, url):
            return httpx.Response(
                302, text="", headers={"location": "/login"}, request=httpx.Request("GET", url)
            )

    confirmed = await detector._confirm_anonymous_access(
        RedirectingClient(),
        "http://target.test/app/.git/",
        "/app/.git/",
        "Version Control Repository Exposed",
    )

    assert confirmed is False


@pytest.mark.asyncio
async def test_confirm_anonymous_access_false_when_probe_errors():
    """A failed probe must not manufacture an anonymous-access claim."""
    detector = SensitivePathsDetector()

    class BrokenClient:
        async def get(self, url):
            raise httpx.ConnectError("connection refused")

    confirmed = await detector._confirm_anonymous_access(
        BrokenClient(),
        "http://target.test/app/.git/",
        "/app/.git/",
        "Version Control Repository Exposed",
    )

    assert confirmed is False


# ---------------------------------------------------------------------------
# Matched-span contract: what the pattern captured must survive to the judge
# ---------------------------------------------------------------------------

# The exact markup DVWA's brute-force page serves. The old value class was
# defined purely by exclusion, so `Password:` followed by `<br><input` cleared
# the "8+ value characters" bar and every login form reported a leaked secret.
_DVWA_LOGIN_FORM = (
    '<div class="vulnerable_code_area"><h2>Login</h2>'
    '<form action="#" method="GET">'
    'Username:<br><input type="text" name="username"><br>'
    'Password:<br><input type="password" AUTOCOMPLETE="off" name="password"><br>'
    '<input type="submit" value="Login" name="Login">'
    "</form></div>"
)


def test_login_form_markup_is_not_a_secret():
    """Regression: the live DVWA brute page produced a Medium FP from this."""
    detector = SensitivePathsDetector()

    result = detector._classify_content(
        "/dvwa/vulnerabilities/brute/", _DVWA_LOGIN_FORM, "text/html"
    )

    assert result.matched is False


def test_real_credential_assignment_still_matches():
    """The markup fix must not blind the detector to genuine secrets."""
    detector = SensitivePathsDetector()
    body = 'db_password = "S3cr3t-Prod-Value-9182"'

    result = detector._classify_content("/config.yml", body, "text/plain")

    assert result.matched is True
    assert result.vuln_type == "Secret-Like Value Exposure"


def test_pattern_match_carries_span_location_and_offset():
    """A regex finding is only adjudicable if the span survives the branch."""
    detector = SensitivePathsDetector()
    body = "<html><body><p>intro</p><pre><code>api_key = AKIAIOSFODNN7EXAMPLE</code></pre></body></html>"

    result = detector._classify_content("/docs/guide", body, "text/html")

    assert result.matched is True
    assert "AKIAIOSFODNN7EXAMPLE" in result.matched_text
    assert result.match_location == "code_block"
    assert body[result.match_offset:].startswith(result.matched_text)


def test_structural_findings_carry_no_span():
    """An autoindex is proven by shape, so there is no captured substring."""
    detector = SensitivePathsDetector()
    body = (
        "<html><head><title>Index of /files</title></head><body>"
        '<h1>Index of /files</h1><a href="../">../</a><a href="a.txt">a.txt</a>'
        "</body></html>"
    )

    result = detector._classify_content("/files/", body, "text/html")

    assert result.matched is True
    assert result.matched_text == ""
    assert result.match_offset == -1


def test_span_reaches_detection_evidence_with_entropy():
    """_finding must publish the span the adjudicator is asked to rule on."""
    detector = SensitivePathsDetector()
    body = 'client_secret = "aG7xQ2mZpL9vRt4WsYb8"'
    result = detector._classify_content("/config.json", body, "application/json")

    finding = detector._finding(
        vuln_type=result.vuln_type,
        severity=result.severity,
        url="http://target.test/config.json",
        evidence=result.evidence,
        detection_method="path_content_fingerprint",
        proof_type="content_verified_path_probe",
        match=result,
    )

    assert "aG7xQ2mZpL9vRt4WsYb8" in finding.detection_evidence["matched"]
    assert finding.detection_evidence["match_location"] == "body_text"
    # A random-looking token must score well above prose or markup.
    assert finding.detection_evidence["entropy"] > 3.0


def test_entropy_separates_random_tokens_from_markup():
    detector = SensitivePathsDetector()

    assert detector._shannon_entropy("aG7xQ2mZpL9vRt4WsYb8") > detector._shannon_entropy(
        "Password:<br><input"
    )
    assert detector._shannon_entropy("") == 0.0


@pytest.mark.asyncio
async def test_authenticated_scan_does_not_deadlock_on_many_matches(monkeypatch):
    """Regression: the anonymous re-probe must not re-acquire the probe semaphore.

    ``probe_url`` runs inside ``async with semaphore``; ``asyncio.Semaphore`` is
    not reentrant, so a re-probe that acquired it again deadlocked the detector
    the moment enough concurrent probes matched at once - every permit held by a
    task waiting for one more. Observed live: the scanner went silent mid-scan
    right after a run of 200s on an exposed .git tree.

    Every path here returns a matching autoindex, so far more than the permit
    count are in the matched branch simultaneously.
    """
    detector = SensitivePathsDetector()
    listing = (
        "<html><head><title>Index of /d</title></head><body>"
        '<h1>Index of /d</h1><a href="../">../</a><a href="a.txt">a.txt</a>'
        "</body></html>"
    )

    class AlwaysListing:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def get(self, url):
            # Yield to the loop so probes genuinely overlap. Without this the
            # tasks run to completion one at a time and never contend for the
            # semaphore, which is exactly what hid the deadlock from a first
            # version of this test.
            await asyncio.sleep(0.01)
            return httpx.Response(
                200,
                text=listing,
                headers={"content-type": "text/html"},
                request=httpx.Request("GET", url),
            )

    monkeypatch.setattr(
        "app.core.detectors.sensitive_paths.create_scan_client",
        lambda **kwargs: AlwaysListing(),
    )

    findings = await asyncio.wait_for(
        detector.detect(
            urls=[f"https://example.test/dir{i}/file{i}.js" for i in range(12)],
            forms=[],
            root_url="https://example.test/",
            # Credentials present, so the re-probe path is exercised.
            session_cookies={"session": "abc"},
        ),
        timeout=15,
    )

    assert findings
