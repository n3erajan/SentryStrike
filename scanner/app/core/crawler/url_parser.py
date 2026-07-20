import pathlib
import posixpath
import re
from urllib.parse import parse_qs, unquote, urljoin, urlparse, urlunparse

# Canonical set of file extensions that are inert static assets — never an
# HTML page or an injectable HTTP endpoint. This is the SINGLE source of truth
# shared by the crawler (skip enqueueing/testing them) and the detectors (never
# fuzz them or use them as reflection sinks). ``.txt`` is included: robots.txt /
# security.txt etc. are real files but carry no testable surface, and a stored
# payload can never be reflected into a plain-text body.
STATIC_EXTENSIONS = {
    # Stylesheets & scripts
    ".css", ".js", ".map",
    # Images
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".webp", ".bmp", ".tiff",
    # Fonts
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    # Media
    ".mp4", ".mp3", ".ogg", ".webm", ".avi",
    # Documents & data (not web endpoints)
    ".pdf", ".xml", ".json", ".csv", ".xls", ".xlsx", ".txt",
    # Archives
    ".zip", ".tar", ".gz",
}


def is_static_asset(url: str) -> bool:
    """True when ``url``'s path ends in a known inert static-asset extension.

    Framework-agnostic gate used everywhere a URL must be classified as
    "not a testable HTTP page" — the crawler uses it to avoid enqueueing assets,
    and detectors use it to avoid fuzzing them or probing them as XSS sinks.
    """
    try:
        path = urlparse(url).path
    except Exception:
        return False
    return pathlib.PurePosixPath(path).suffix.lower() in STATIC_EXTENSIONS


def normalize_url(base_url: str, candidate: str) -> str:
    absolute = urljoin(base_url, candidate)
    parsed = urlparse(absolute)
    normalized = parsed._replace(fragment="")
    return urlunparse(normalized)


def same_domain(url_a: str, url_b: str) -> bool:
    return urlparse(url_a).netloc == urlparse(url_b).netloc


def application_base_path(root_url: str) -> str:
    """Return the navigable path boundary implied by a submitted target URL."""
    raw_path = unquote(urlparse(root_url).path or "/")
    normalized = posixpath.normpath(raw_path)
    if not normalized.startswith("/"):
        normalized = f"/{normalized}"
    if raw_path.endswith("/"):
        base = normalized
    elif pathlib.PurePosixPath(normalized).suffix:
        base = posixpath.dirname(normalized)
    else:
        base = normalized
    return "/" if base == "/" else f"{base.rstrip('/')}/"


def url_in_application_scope(root_url: str, candidate_url: str) -> bool:
    """Keep page navigation inside a path-hosted app on the same origin."""
    if not same_domain(root_url, candidate_url):
        return False
    base = application_base_path(root_url)
    if base == "/":
        return True
    path = posixpath.normpath(unquote(urlparse(candidate_url).path or "/"))
    return path == base.rstrip("/") or path.startswith(base)


def is_session_termination_url(url: str) -> bool:
    """Identify navigation that can poison the session used by later probes.

    Besides explicit sign-out routes, security configuration pages can overwrite
    authorization-context cookies simply by being submitted. Active detectors must
    not fuzz those pages with the shared scan session because a response-level
    ``Set-Cookie`` then changes the behavior of every later probe.
    """
    parsed = urlparse(url)
    route_text = f"{parsed.path}/{parsed.fragment.partition('?')[0]}"
    for segment in unquote(route_text).lower().split("/"):
        # Strip a trailing file extension (``logout.php``, ``sign-out.aspx``,
        # ``logoff.jsp`` …) BEFORE removing separators. The separator-strip below
        # deletes the dot too, so without this a server-rendered auth page like
        # ``logout.php`` canonicalized to ``logoutphp`` and slipped past the token
        # set — only extensionless SPA routes (``/auth/sign-out``) were caught.
        # That let the crawler enqueue ``logout.php`` and detectors GET it,
        # destroying the shared session so later probes were redirected to login.
        # Extension-agnostic: matches any short alphanumeric suffix, no framework
        # list. Query/fragment are already excluded above, so this only trims a
        # real trailing extension.
        base = re.sub(r"\.[a-z0-9]{1,6}$", "", segment)
        canonical = re.sub(r"[-_.\s]", "", base)
        if canonical in {"logout", "signout", "logoff", "endsession", "security"}:
            return True
    return False


def extract_query_params(url: str) -> list[str]:
    parsed = urlparse(url)
    return list(parse_qs(parsed.query).keys())


def normalize_for_dedupe(url: str) -> str:
    p = urlparse(url.strip())
    host = p.hostname or ""
    port = p.port
    if (p.scheme == "http" and port == 80) or \
       (p.scheme == "https" and port == 443):
        port = None
    netloc = host if port is None else f"{host}:{port}"
    path = p.path.rstrip("/") or "/"
    return urlunparse((p.scheme.lower(), netloc, path,
                       p.params, p.query, ""))
