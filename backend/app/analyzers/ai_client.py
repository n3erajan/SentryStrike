import json
import logging

import httpx

from app.config import get_settings

logger = logging.getLogger(__name__)


class AIClient:
    """Single LLM client speaking the OpenAI Chat Completions API.

    One client, one config set — works with any OpenAI-compatible endpoint.
    Point ``AI_BASE_URL`` at the provider's ``/v1`` root and set ``AI_MODEL``
    (and ``AI_API_KEY`` for hosted providers). Local Ollama needs no key: its
    OpenAI-compatible endpoint lives at ``http://localhost:11434/v1``.

    The scanner calls ``generate_json`` (one JSON object) and
    ``generate_json_list`` (a JSON array of a known length). JSON parsing,
    retries, and length validation are shared here; subclasses are not needed.
    """

    provider_name: str = "ai"

    def __init__(self) -> None:
        self.settings = get_settings()
        self._base_url = self.settings.ai_base_url.rstrip("/")
        self._model = self.settings.ai_model
        self._api_key = self.settings.ai_api_key
        self._timeout = self.settings.ai_timeout_seconds
        self._json_mode = self.settings.ai_json_mode

    async def _complete(self, prompt: str) -> str:
        """Return raw model text for *prompt* via Chat Completions."""
        payload: dict = {
            "model": self._model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
            "temperature": 0.2,
        }
        if self._json_mode:
            payload["response_format"] = {"type": "json_object"}
        headers: dict[str, str] = {}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        logger.debug(
            "%s request to %s (model=%s, json_mode=%s, prompt_len=%d)",
            self.provider_name, self._base_url, self._model, self._json_mode, len(prompt),
        )
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            response = await client.post(
                f"{self._base_url}/chat/completions", json=payload, headers=headers
            )
            if response.status_code >= 400:
                logger.warning(
                    "%s provider returned status %s: %s",
                    self.provider_name, response.status_code, response.text,
                )
            response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"]

    async def generate_json(self, prompt: str) -> dict:
        """Generate a single JSON dict from *prompt* with retries."""
        for attempt in range(1, self.settings.ai_max_retries + 2):
            try:
                text = await self._complete(prompt)
                return self._extract_json(text)
            except Exception as exc:
                logger.warning(
                    "%s call attempt %s failed: %s: %s",
                    self.provider_name, attempt, type(exc).__name__, exc,
                )
        raise RuntimeError(f"{self.provider_name} failed to generate JSON after retries")

    async def generate_json_list(self, prompt: str, expected_count: int) -> list[dict]:
        """Send a single prompt expecting a JSON array with *expected_count* items.

        Raises RuntimeError if the response cannot be parsed or has the wrong
        length after retries.
        """
        for attempt in range(1, self.settings.ai_max_retries + 2):
            try:
                text = await self._complete(prompt)
                items = self._extract_json_list(text, expected_count)
                if items is not None:
                    return items
                logger.warning(
                    "%s batch response had wrong structure; retrying (attempt %s)",
                    self.provider_name, attempt,
                )
            except Exception as exc:
                logger.warning(
                    "%s batch call attempt %s failed: %s: %s",
                    self.provider_name, attempt, type(exc).__name__, exc,
                )
        raise RuntimeError(
            f"{self.provider_name} failed to return a list of {expected_count} items after retries"
        )

    # ------------------------------------------------------------------
    # JSON extraction helpers
    # ------------------------------------------------------------------

    def _extract_json_list(self, text: str, expected_count: int) -> list[dict] | None:
        """Try to parse *text* as a JSON array of dicts.

        The AI may return either a raw JSON array ``[{...}, ...]`` or a JSON
        object with a single key whose value is the array (e.g.
        ``{"results": [{...}, ...]}``).  Both forms are accepted.

        Returns ``None`` when the response cannot be coerced into a list of
        the correct length so the caller can retry or fall back.
        """
        text = text.strip()
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            # Try to find the outermost array or object
            start_bracket = text.find("[")
            start_brace = text.find("{")
            if start_bracket >= 0 and (start_brace < 0 or start_bracket < start_brace):
                end = text.rfind("]")
                if end > start_bracket:
                    try:
                        parsed = json.loads(text[start_bracket : end + 1])
                    except json.JSONDecodeError:
                        return None
                else:
                    return None
            elif start_brace >= 0:
                end = text.rfind("}")
                if end > start_brace:
                    try:
                        parsed = json.loads(text[start_brace : end + 1])
                    except json.JSONDecodeError:
                        return None
                else:
                    return None
            else:
                return None

        # If the model returned an object wrapping the array, unwrap it
        if isinstance(parsed, dict):
            # Look for the first list-valued key
            for val in parsed.values():
                if isinstance(val, list):
                    parsed = val
                    break
            else:
                # Single-item batch - wrap
                return [parsed] if expected_count == 1 else None

        if not isinstance(parsed, list):
            return None

        # If length doesn't match, return None to trigger a retry
        if len(parsed) != expected_count:
            logger.warning("batch response had %d items, expected %d", len(parsed), expected_count)
            return None
        return [item if isinstance(item, dict) else {} for item in parsed[:expected_count]]

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
