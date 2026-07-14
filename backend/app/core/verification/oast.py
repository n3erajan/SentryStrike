from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlencode
from uuid import uuid4

import httpx


# Genuine scanner-minted interaction ids only: new_callback_url() mints
# f"{purpose}-{uuid4().hex}", where uuid4().hex is exactly 32 lowercase hex
# chars. This anchored pattern is the "genuine uuid" gate — random strings,
# traversal probes, wrong length/case all fail it, so they are never stored.
INTERACTION_ID_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}-[0-9a-f]{32}$")


@dataclass
class OastInteraction:
    interaction_id: str
    raw: object


class OastClient:
    """Minimal callback/OAST helper used only when operator configuration exists."""

    def __init__(
        self,
        callback_base_url: str | None,
        poll_url: str | None = None,
        *,
        timeout_seconds: float = 5.0,
    ) -> None:
        self.callback_base_url = (callback_base_url or "").rstrip("/")
        self.poll_url = poll_url
        self.timeout_seconds = timeout_seconds

    @property
    def enabled(self) -> bool:
        return bool(self.callback_base_url)

    @staticmethod
    def is_valid_interaction_id(value: str) -> bool:
        return bool(isinstance(value, str) and INTERACTION_ID_RE.match(value))

    def new_callback_url(self, purpose: str = "ssrf") -> tuple[str, str]:
        interaction_id = f"{purpose}-{uuid4().hex}"
        return f"{self.callback_base_url}/{interaction_id}", interaction_id

    async def poll(self, interaction_id: str) -> list[OastInteraction]:
        if not self.enabled or not self.poll_url:
            return []

        separator = "&" if "?" in self.poll_url else "?"
        poll_target = f"{self.poll_url}{separator}{urlencode({'id': interaction_id})}"
        async with httpx.AsyncClient(timeout=self.timeout_seconds, follow_redirects=True) as client:
            response = await client.get(poll_target)
        if response.status_code >= 400:
            return []

        try:
            payload = response.json()
        except Exception:
            payload = response.text

        interactions = self._extract_interactions(payload)
        return [
            OastInteraction(interaction_id=interaction_id, raw=item)
            for item in interactions
            if interaction_id in str(item)
        ]

    @staticmethod
    def _extract_interactions(payload: object) -> list[object]:
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            for key in ("interactions", "events", "data", "results"):
                value = payload.get(key)
                if isinstance(value, list):
                    return value
            return [payload]
        if isinstance(payload, str) and payload:
            return [payload]
        return []
