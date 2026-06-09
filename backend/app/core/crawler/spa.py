from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass
class SpaFallbackSignal:
    is_fallback: bool
    reason: str = ""
    similarity: float = 0.0


class SpaFallbackDetector:
    """Detect unknown client-side routes that all return the same SPA shell."""

    def __init__(self, root_html: str | None = None, root_url: str | None = None) -> None:
        self.root_url = root_url
        self.root_fingerprint = self.fingerprint(root_html or "") if root_html else ""
        self.root_title = self._title(root_html or "") if root_html else ""
        self.root_tokens = self._tokens_from_fingerprint_source(root_html or "") if root_html else set()

    def configure_root(self, root_url: str, html: str) -> None:
        self.root_url = root_url
        self.root_fingerprint = self.fingerprint(html)
        self.root_title = self._title(html)
        self.root_tokens = self._tokens_from_fingerprint_source(html)

    def detect(self, url: str, status_code: int, content_type: str, html: str) -> SpaFallbackSignal:
        if status_code != 200 or "text/html" not in content_type.lower():
            return SpaFallbackSignal(False)
        if not self.root_fingerprint or not html:
            return SpaFallbackSignal(False)

        parsed = urlparse(url)
        if pathlib_suffix(parsed.path):
            return SpaFallbackSignal(False)

        candidate_fingerprint = self.fingerprint(html)
        if candidate_fingerprint == self.root_fingerprint:
            return SpaFallbackSignal(True, "html shell fingerprint matched root", 1.0)

        similarity = self._similarity(self.root_tokens, self._tokens_from_fingerprint_source(html))
        if similarity >= 0.98 and self.root_title and self.root_title == self._title(html):
            return SpaFallbackSignal(True, "html shell is effectively identical to root", similarity)
        return SpaFallbackSignal(False, similarity=similarity)

    @staticmethod
    def fingerprint(html: str) -> str:
        normalized = re.sub(r">\s+<", "><", html)
        normalized = re.sub(r"\s+", " ", normalized)
        normalized = re.sub(r"<script\b[^>]*>.*?</script>", "<script></script>", normalized, flags=re.I | re.S)
        normalized = re.sub(r"<style\b[^>]*>.*?</style>", "<style></style>", normalized, flags=re.I | re.S)
        normalized = re.sub(r"\b(?:nonce|integrity|crossorigin)=(['\"]).*?\1", "", normalized, flags=re.I)
        return hashlib.sha256(normalized.strip().encode("utf-8", "ignore")).hexdigest()

    @staticmethod
    def _title(html: str) -> str:
        match = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
        return re.sub(r"\s+", " ", match.group(1)).strip().lower() if match else ""

    @staticmethod
    def _tokens_from_fingerprint_source(html: str) -> set[str]:
        return set(re.findall(r"[A-Za-z0-9_/-]{3,}", html.lower()))

    @staticmethod
    def _similarity(a: set[str], b: set[str]) -> float:
        if not a and not b:
            return 1.0
        if not a or not b:
            return 0.0
        return len(a & b) / len(a | b)


def pathlib_suffix(path: str) -> str:
    last = path.rsplit("/", 1)[-1]
    return "." in last and last.rsplit(".", 1)[-1].lower()
