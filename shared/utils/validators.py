from urllib.parse import urlparse

import httpx


def validate_url_format(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


async def validate_url_accessibility(url: str, timeout: float = 5.0) -> bool:
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            response = await client.get(url)
            return response.status_code < 500
    except Exception:
        return False


def sanitize_input(value: str) -> str:
    return value.replace("\x00", "").strip()
