"""Shared, name-OR-value parameter selection heuristics.

Detectors historically gated injection candidates purely on the parameter
*name* (an allowlist). That misses candidates whose name is generic (``to``,
``q``, ``dest2``) but whose *value* is clearly the class's data — a URL, a
path, or a filename. These pure predicates let open-redirect, LFI, and SSRF
select a parameter when either its **name** matches the class tokens **or**
its **baseline value** looks like the class's data.

Everything here is pure and framework-agnostic: no target-specific paths,
names, or payloads. Values are percent-decoded before matching so that
``%2f``/``%5c``-encoded inputs are handled.
"""

from __future__ import annotations

import re
from urllib.parse import unquote

# --- Name allowlists (the "name half" of name-OR-value) -------------------
#
# These mirror the token sets the detectors used before this module existed;
# each detector references the set that matches its class so there is a single
# source of truth.

REDIRECT_NAME_TOKENS = frozenset(
    {
        "next", "return", "return_to", "return_url", "redirect", "redirect_to",
        "redirect_url", "redirect_uri", "callback", "callback_url", "continue",
        "url", "target", "dest", "destination", "goto", "back",
    }
)
REDIRECT_NAME_SUBSTRINGS = ("redirect", "return", "callback", "next")

FILE_NAME_TOKENS = frozenset(
    {
        "page", "file", "path", "include", "template", "doc", "dir", "load",
        "url", "src", "dest", "view",
    }
)
FILE_NAME_SUBSTRINGS = ("file", "page", "path", "inc")

SSRF_NAME_TOKENS = frozenset(
    {
        "url", "link", "src", "dest", "redirect", "fetch", "load", "uri",
        "path", "domain", "host", "proxy", "site",
    }
)
SSRF_NAME_SUBSTRINGS = ("url", "link", "redirect")

# Common file extensions that mark a value as a filename/path rather than a
# bare hostname. Deliberately excludes TLD-like tokens (``com``/``net``/...) so
# ``evil.com`` is treated as a host, not a file.
_FILE_EXTENSIONS = frozenset(
    {
        "php", "php3", "php4", "php5", "phtml", "asp", "aspx", "jsp", "jspx",
        "cgi", "pl", "py", "rb", "sh", "bash", "js", "mjs", "ts", "jsx",
        "html", "htm", "xhtml", "xml", "json", "yaml", "yml", "css", "txt",
        "md", "csv", "tsv", "ini", "conf", "cfg", "config", "env", "properties",
        "log", "bak", "old", "orig", "swp", "save", "tmp", "temp", "sql", "db",
        "sqlite", "pem", "key", "crt", "cert", "p12", "pfx", "htaccess",
        "htpasswd", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "zip",
        "tar", "gz", "tgz", "rar", "7z", "png", "jpg", "jpeg", "gif", "svg",
        "ico", "bmp", "webp", "war", "jar", "class", "dll", "so", "exe", "bin",
        "dat", "inc", "tpl", "twig", "ejs", "erb", "map",
    }
)

_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.IGNORECASE)
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:[/?#].*)?$")
# A dotted hostname, optionally with port and/or path/query/fragment.
_DOTTED_HOST_RE = re.compile(
    r"^[a-z0-9\-]+(?:\.[a-z0-9\-]+)+(?::\d+)?(?:[/?#].*)?$", re.IGNORECASE
)
_EXT_RE = re.compile(r"\.([a-z0-9]{1,8})$", re.IGNORECASE)
_ID_NAME_RE = re.compile(r"(^|[_\-])(id|uid|uuid|guid|pid|gid|oid)$", re.IGNORECASE)


def _decode(value: object) -> str:
    """Percent-decode (twice, to catch double-encoding) and strip a value."""
    if value is None:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    for _ in range(2):
        decoded = unquote(text)
        if decoded == text:
            break
        text = decoded
    return text.strip()


def _last_segment(value: str) -> str:
    """Path/query-stripped final segment, for extension checks."""
    segment = value.split("?", 1)[0].split("#", 1)[0]
    segment = segment.replace("\\", "/")
    return segment.rstrip("/").rsplit("/", 1)[-1]


def looks_like_file_extension(value: object) -> bool:
    """True when the value's final segment ends in a known file extension."""
    decoded = _decode(value)
    if not decoded:
        return False
    match = _EXT_RE.search(_last_segment(decoded))
    return bool(match) and match.group(1).lower() in _FILE_EXTENSIONS


def looks_like_url(value: object) -> bool:
    """True when the value looks like a URL or a bare host.

    Recognizes explicit schemes (``http://``), protocol-relative (``//host``),
    IPv4 literals, and dotted hostnames. A bare dotted token whose suffix is a
    file extension (``config.js``) is treated as a file, not a host.
    """
    decoded = _decode(value)
    if not decoded:
        return False
    lowered = decoded.lower()
    if _SCHEME_RE.match(lowered):
        return True
    # Protocol-relative (//host or \\host, including mixed \/) forms.
    if re.match(r"^[/\\]{2}", lowered):
        return True
    if _IPV4_RE.match(lowered):
        return True
    if lowered.startswith("localhost") and (
        lowered == "localhost" or lowered[9] in ":/?#"
    ):
        return True
    if _DOTTED_HOST_RE.match(lowered):
        # A pure ``name.ext`` filename (no port/path) is not a host.
        has_locator = any(ch in lowered for ch in ":/?#")
        if has_locator or not looks_like_file_extension(lowered):
            return True
    return False


def looks_like_path(value: object) -> bool:
    """True when the value looks like a filesystem/URL path.

    Covers absolute paths (``/dashboard``), traversal sequences (``../``,
    ``..\\``), and values ending in a file extension.
    """
    decoded = _decode(value)
    if not decoded:
        return False
    # Absolute path, but not a protocol-relative ``//host`` (that's a URL).
    if decoded.startswith("/") and not decoded.startswith("//"):
        return True
    if "../" in decoded or "..\\" in decoded or "..%2f" in decoded.lower():
        return True
    if looks_like_file_extension(decoded):
        return True
    return False


def _name_matches(name: object, tokens: frozenset[str], substrings: tuple[str, ...]) -> bool:
    lowered = str(name or "").lower()
    if not lowered:
        return False
    if lowered in tokens:
        return True
    return any(token in lowered for token in substrings)


def _looks_like_id_name(name: object) -> bool:
    lowered = str(name or "").lower()
    return lowered == "id" or bool(_ID_NAME_RE.search(lowered))


def redirect_candidate(name: object, value: object) -> bool:
    """Select a parameter for open-redirect testing.

    Qualifies when the name matches redirect tokens OR the value looks like a
    URL or a path.
    """
    if _name_matches(name, REDIRECT_NAME_TOKENS, REDIRECT_NAME_SUBSTRINGS):
        return True
    return looks_like_url(value) or looks_like_path(value)


def _has_traversal(value: object) -> bool:
    decoded = _decode(value).lower()
    return "../" in decoded or "..\\" in decoded


def file_candidate(name: object, value: object) -> bool:
    """Select a parameter for LFI/RFI testing.

    Qualifies when the name matches file tokens OR the value looks like a path
    or a file. A file extension or a traversal sequence is always a strong
    signal. A bare absolute-path value (``/rest/basket/1``) is *not* selected
    when the name is clearly an id, so REST path ids are not fuzzed as LFI.
    """
    if _name_matches(name, FILE_NAME_TOKENS, FILE_NAME_SUBSTRINGS):
        return True
    if looks_like_file_extension(value) or _has_traversal(value):
        return True
    if looks_like_path(value):
        return not _looks_like_id_name(name)
    return False


def ssrf_candidate(name: object, value: object) -> bool:
    """Select a parameter for SSRF testing.

    Qualifies when the name matches SSRF tokens OR the value looks like a URL.
    """
    if _name_matches(name, SSRF_NAME_TOKENS, SSRF_NAME_SUBSTRINGS):
        return True
    return looks_like_url(value)
