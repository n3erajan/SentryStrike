"""Truth-table tests for the shared name-OR-value parameter selection."""

import pytest

from app.core.detectors.param_selection import (
    command_candidate,
    file_candidate,
    is_opaque_timing_value,
    looks_like_command_value,
    looks_like_file_extension,
    looks_like_path,
    looks_like_url,
    redirect_candidate,
    select,
    ssrf_candidate,
)


@pytest.mark.parametrize(
    "value, expected",
    [
        ("http://example.com/x", True),
        ("https://example.com", True),
        ("//evil.test/path", True),
        ("\\\\evil.test", True),
        ("127.0.0.1", True),
        ("127.0.0.1:8080/admin", True),
        ("localhost", True),
        ("localhost:3000/x", True),
        ("evil.example.com", True),
        ("evil.example.com:8443/a", True),
        ("http%3A%2F%2Fexample.com", True),  # percent-encoded scheme
        ("%2f%2fevil.test", True),  # encoded protocol-relative
        ("1", False),
        ("42", False),
        ("", False),
        ("dashboard", False),
        ("/dashboard", False),  # a path, not a URL/host
        ("config.js", False),  # a filename, not a host
        ("report.pdf", False),
    ],
)
def test_looks_like_url(value, expected):
    assert looks_like_url(value) is expected


@pytest.mark.parametrize(
    "value, expected",
    [
        ("/dashboard", True),
        ("/a/b/c", True),
        ("../../etc/passwd", True),
        ("..\\..\\windows", True),
        ("..%2f..%2fetc", True),
        ("index.php", True),
        ("config.js", True),
        ("/uploads/report.pdf", True),
        ("//evil.test/path", False),  # protocol-relative URL, not a plain path
        ("1", False),
        ("hello", False),
        ("", False),
    ],
)
def test_looks_like_path(value, expected):
    assert looks_like_path(value) is expected


@pytest.mark.parametrize(
    "value, expected",
    [
        ("index.php", True),
        ("app.js", True),
        ("/a/b/config.yaml", True),
        ("backup.tar.gz", True),
        ("file.bak", True),
        ("evil.com", False),  # TLD, not a file extension
        ("example.net", False),
        ("plainword", False),
        ("42", False),
        ("", False),
    ],
)
def test_looks_like_file_extension(value, expected):
    assert looks_like_file_extension(value) is expected


@pytest.mark.parametrize(
    "name, value, expected",
    [
        ("redirect", "1", True),  # name token
        ("returnUrl", "1", True),  # substring
        ("to", "/dashboard", True),  # generic name, path value
        ("to", "https://evil.test", True),  # generic name, url value
        ("next", "", True),  # name token even with empty value
        ("id", "42", False),  # id-like, numeric
        ("q", "search terms", False),
        ("page", "1", False),  # generic, non-url value
    ],
)
def test_redirect_candidate(name, value, expected):
    assert redirect_candidate(name, value) is expected


@pytest.mark.parametrize(
    "name, value, expected",
    [
        ("file", "1", True),  # name token
        ("template", "x", True),
        ("view", "1", True),
        ("download", "../../etc/passwd", True),  # generic name, traversal value
        ("doc", "report.pdf", True),
        ("theme", "config.php", True),  # generic name, file value
        ("id", "42", False),  # id-like, numeric
        ("id", "/rest/basket/1", False),  # id name + absolute path -> not LFI
        ("id", "../../etc/passwd", True),  # traversal still qualifies
        ("q", "hello", False),
    ],
)
def test_file_candidate(name, value, expected):
    assert file_candidate(name, value) is expected


@pytest.mark.parametrize(
    "name, value, expected",
    [
        ("url", "1", True),  # name token
        ("proxy", "x", True),
        ("callbackUrl", "1", True),  # substring "url"
        ("image", "http://127.0.0.1/", True),  # generic name, url value
        ("avatar", "//evil.test", True),
        ("image", "photo.png", True),  # profile-image-by-URL sink, name only
        ("avatar", "cat", True),  # name token even with non-url value
        ("webhook", "x", True),  # webhook fetch sink
        ("endpoint", "x", True),
        ("callback", "x", True),
        ("imageWidth", "800", False),  # not an exact token, no url value
        ("id", "42", False),
        ("name", "alice", False),
    ],
)
def test_ssrf_candidate(name, value, expected):
    assert ssrf_candidate(name, value) is expected


@pytest.mark.parametrize(
    "name, value, expected",
    [
        ("to", "x", True),  # exact generic redirect name
        ("uri", "x", True),
        ("redirect", "1", True),
        ("returnUrl", "1", True),  # substring
        ("goto", "x", True),
        ("id", "42", False),
        ("page", "1", False),
    ],
)
def test_redirect_candidate_name_tokens(name, value, expected):
    assert redirect_candidate(name, value) is expected


def test_no_hardcoded_target_specifics():
    """A generic id param must never be selected purely by value."""
    assert redirect_candidate("id", "42") is False
    assert file_candidate("id", "42") is False
    assert ssrf_candidate("id", "42") is False


# --------------------------------------------------------------------------- #
# Command injection: name OR value OR endpoint-context selection
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "name, value, url, expected",
    [
        ("cmd", "x", "", True),               # name token
        ("host", "1", "", True),              # name token
        ("execCommand", "x", "", True),       # substring
        ("q", "8.8.8.8", "", True),           # generic name, host-shaped value
        ("q", "1; ls -la", "", True),         # generic name, shell-metachar value
        # generic name on a diagnostic endpoint path -> context selection
        ("target", "opaque", "http://t/api/ping", True),
        ("host", "x", "http://t/network/trace", True),
        # generic name, benign value, non-diagnostic endpoint -> not selected here
        ("city", "Berlin", "http://t/api/address", False),
        ("id", "42", "", False),
        ("q", "search terms", "", False),
    ],
)
def test_command_candidate(name, value, url, expected):
    assert command_candidate(name, value, url) is expected


@pytest.mark.parametrize(
    "value, expected",
    [
        ("1; ls", True),
        ("a | b", True),
        ("$(whoami)", True),
        ("8.8.8.8", True),          # host-shaped
        ("http://127.0.0.1", True),
        ("Berlin", False),
        ("hello world", False),
        ("", False),
    ],
)
def test_looks_like_command_value(value, expected):
    assert looks_like_command_value(value) is expected


@pytest.mark.parametrize(
    "value, expected",
    [
        ("Berlin", True),           # substantive opaque string
        ("some message", True),
        ("42", False),              # bare numeric id
        ("7", False),
        ("", False),
        ("x", False),               # too short
        ("true", False),
        ("null", False),
    ],
)
def test_is_opaque_timing_value(value, expected):
    assert is_opaque_timing_value(value) is expected


def test_select_facade_any_signal():
    # Name-only signal.
    assert select("url", "x", name_tokens=frozenset({"url"})) is True
    # Value-only signal via a predicate.
    assert select("q", "http://x", value_predicates=(looks_like_url,)) is True
    # Context-only signal via a predicate.
    ctx = (lambda n, v, u: "ping" in str(u),)
    assert select("q", "x", "http://t/ping", context_predicates=ctx) is True
    # No signal at all.
    assert select("q", "x") is False
    # A raising predicate must not blow up selection.
    boom = (lambda v: (_ for _ in ()).throw(ValueError("boom")),)
    assert select("q", "x", value_predicates=boom) is False

