from urllib.parse import parse_qs, urljoin, urlparse, urlunparse


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
