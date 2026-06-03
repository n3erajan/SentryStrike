import json
import logging

import httpx

from app.config import get_settings

logger = logging.getLogger(__name__)

# Ollama model families that support the `think` parameter.
# For unsupported models the parameter is silently ignored by Ollama, but
# we skip it entirely to keep payloads clean and avoid log noise.
_THINKING_CAPABLE_PREFIXES = ("qwen3", "deepseek-r1", "qwq")


def _model_supports_thinking(model_name: str) -> bool:
    """Return True if *model_name* is known to support Ollama's ``think`` param."""
    name_lower = (model_name or "").lower()
    return any(name_lower.startswith(prefix) for prefix in _THINKING_CAPABLE_PREFIXES)


class OllamaClient:
    def __init__(self) -> None:
        self.settings = get_settings()
        self._thinking_capable = _model_supports_thinking(self.settings.ollama_model)

    def _build_payload(self, prompt: str, *, thinking: bool) -> dict:
        """Construct the Ollama /api/generate payload.

        ``think=True``  → chain-of-thought reasoning (slower, more accurate).
        ``think=False`` → direct answer, no <think> block (faster).

        The ``think`` key is only injected for models that support it so the
        payload stays clean for qwen2.5-coder and other non-thinking models.
        """
        payload: dict = {
            "model": self.settings.ollama_model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
        }
        if self._thinking_capable:
            payload["think"] = thinking
            logger.debug("thinking mode: %s for model %s", thinking, self.settings.ollama_model)
        return payload

    async def generate_json(self, prompt: str, *, thinking: bool = False) -> dict:
        """Generate a single JSON dict from *prompt*.

        Args:
            prompt:   The full prompt string.
            thinking: Whether to enable chain-of-thought reasoning.
                      Pass ``True`` for borderline/ambiguous findings;
                      leave ``False`` (default) for clear-cut, high-confidence ones.
        """
        payload = self._build_payload(prompt, thinking=thinking)

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
                logger.warning("ollama call attempt %s failed: %s: %s", attempt, type(exc).__name__, exc)

        raise RuntimeError("Ollama failed to generate JSON after retries")

    async def generate_json_list(self, prompt: str, expected_count: int, *, thinking: bool = False) -> list[dict]:
        """Send a single prompt expecting a JSON array response with *expected_count* items.

        Args:
            prompt:         The full prompt string.
            expected_count: Number of result objects expected in the array.
            thinking:       Whether to enable chain-of-thought reasoning.

        Raises RuntimeError if the AI response cannot be
        parsed or has the wrong length after retries.
        """
        payload = self._build_payload(prompt, thinking=thinking)

        for attempt in range(1, self.settings.ai_max_retries + 2):
            try:
                logger.debug("ollama batch request payload length: %d chars", len(prompt))
                async with httpx.AsyncClient(timeout=self.settings.ollama_timeout_seconds) as client:
                    response = await client.post(f"{self.settings.ollama_base_url}/api/generate", json=payload)
                    if response.status_code >= 400:
                        logger.warning("ollama returned status %s: %s", response.status_code, response.text)
                    response.raise_for_status()
                text = response.json().get("response", "")
                items = self._extract_json_list(text, expected_count)
                if items is not None:
                    return items
                logger.warning("ollama batch response had wrong structure; retrying (attempt %s)", attempt)
            except Exception as exc:
                logger.warning("ollama batch call attempt %s failed: %s: %s", attempt, type(exc).__name__, exc)

        raise RuntimeError(f"Ollama failed to return a list of {expected_count} items after retries")

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
                # Single-item batch — wrap
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