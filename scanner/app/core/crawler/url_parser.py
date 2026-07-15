import pathlib
from urllib.parse import parse_qs, urljoin, urlparse, urlunparse

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
