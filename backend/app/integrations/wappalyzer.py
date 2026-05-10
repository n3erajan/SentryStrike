import re

import httpx
from bs4 import BeautifulSoup

from app.config import get_settings
from app.models.vulnerability import TechnologyComponent


class TechnologyDetector:
    def __init__(self) -> None:
        self.settings = get_settings()

    async def detect(self, url: str) -> list[TechnologyComponent]:
        components: list[TechnologyComponent] = []
        async with httpx.AsyncClient(timeout=self.settings.request_timeout_seconds) as client:
            response = await client.get(url)

        headers = response.headers
        server = headers.get("server")
        if server:
            name, version = self._split_name_version(server)
            components.append(TechnologyComponent(name=name, version=version, category="server"))

        powered_by = headers.get("x-powered-by")
        if powered_by:
            name, version = self._split_name_version(powered_by)
            components.append(TechnologyComponent(name=name, version=version, category="framework"))

        soup = BeautifulSoup(response.text, "html.parser")
        for script in soup.find_all("script"):
            src = (script.get("src") or "").lower()
            if "jquery" in src:
                components.append(TechnologyComponent(name="jQuery", version=self._extract_version(src), category="library"))
            if "react" in src:
                components.append(TechnologyComponent(name="React", version=self._extract_version(src), category="library"))

        uniq: dict[str, TechnologyComponent] = {}
        for c in components:
            uniq[f"{c.name}:{c.version}:{c.category}"] = c
        return list(uniq.values())

    def _split_name_version(self, raw: str) -> tuple[str, str | None]:
        match = re.search(r"([A-Za-z\- ]+)[/ ]([0-9][A-Za-z0-9\._-]*)", raw)
        if match:
            return match.group(1).strip(), match.group(2).strip()
        return raw.strip(), None

    def _extract_version(self, text: str) -> str | None:
        match = re.search(r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)", text)
        return match.group(1) if match else None
