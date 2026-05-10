import json
import logging

import httpx

from app.config import get_settings

logger = logging.getLogger(__name__)


class OllamaClient:
    def __init__(self) -> None:
        self.settings = get_settings()

    async def generate_json(self, prompt: str, fallback: dict) -> dict:
        payload = {
            "model": self.settings.ollama_model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
        }

        for attempt in range(1, self.settings.ai_max_retries + 2):
            try:
                logger.debug("ollama request payload: %s", payload)
                async with httpx.AsyncClient(timeout=self.settings.ollama_timeout_seconds) as client:
                    response = await client.post(f"{self.settings.ollama_base_url}/api/generate", json=payload)
                    if response.status_code >= 400:
                        logger.warning("ollama returned status %s: %s", response.status_code, response.text)
                    response.raise_for_status()
                text = response.json().get("response", "")
                return self._extract_json(text)
            except Exception as exc:
                logger.warning("ollama call attempt %s failed: %s", attempt, exc)

        return fallback

    def _extract_json(self, text: str) -> dict:
        text = text.strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            start = text.find("{")
            end = text.rfind("}")
            if start >= 0 and end > start:
                return json.loads(text[start : end + 1])
            raise
