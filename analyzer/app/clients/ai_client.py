from __future__ import annotations

import json
import logging
from dataclasses import dataclass

import httpx

from app.config import get_settings

logger = logging.getLogger(__name__)


class ProviderError(RuntimeError):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        retryable: bool,
        request_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.retryable = retryable
        self.request_id = request_id


@dataclass(frozen=True)
class ProviderResult:
    data: dict
    request_id: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None


class AIClient:
    """OpenAI-compatible JSON client owned exclusively by the analyzer."""

    def __init__(self) -> None:
        self.settings = get_settings()

    async def list_models(self) -> list[str] | None:
        """Return model ids the provider advertises, or None if it cannot be asked.

        None means "unknown", not "empty": a provider that omits /v1/models, or is
        unreachable right now, must not be reported as missing the model.
        """
        headers = {}
        if self.settings.ai_api_key:
            headers["Authorization"] = f"Bearer {self.settings.ai_api_key}"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    f"{self.settings.ai_base_url.rstrip('/')}/models",
                    headers=headers,
                )
            if response.status_code >= 400:
                return None
            data = response.json().get("data")
            if not isinstance(data, list):
                return None
            return [str(entry["id"]) for entry in data if isinstance(entry, dict) and "id" in entry]
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            return None

    async def check_model_available(self) -> bool | None:
        """Whether the configured model is advertised. None when undetermined."""
        available = await self.list_models()
        if available is None:
            return None
        wanted = self.settings.ai_model
        # Ollama reports an untagged name as "<name>:latest"; treat that as a match
        # so AI_MODEL=llama3 is not reported missing when llama3:latest is installed.
        candidates = {wanted, f"{wanted}:latest"}
        if wanted.endswith(":latest"):
            candidates.add(wanted[: -len(":latest")])
        return any(name in candidates for name in available)

    async def generate_json(self, prompt: str) -> ProviderResult:
        last_error: ProviderError | None = None
        attempts = self.settings.ai_max_retries + 1
        for attempt in range(1, attempts + 1):
            try:
                result = await self._request(prompt)
                logger.debug(
                    "provider call ok (attempt %s/%s) request_id=%s tokens=in:%s/out:%s",
                    attempt,
                    attempts,
                    result.request_id,
                    result.input_tokens,
                    result.output_tokens,
                )
                return result
            except ProviderError as exc:
                last_error = exc
                if not exc.retryable:
                    logger.warning(
                        "provider call failed non-retryably (%s): %s",
                        exc.code,
                        exc,
                        exc_info=exc.__cause__,
                    )
                    raise
                logger.warning(
                    "provider call failed retryably (attempt %s/%s, %s): %s",
                    attempt,
                    attempts,
                    exc.code,
                    exc,
                    exc_info=exc.__cause__,
                )
        if last_error is not None:
            raise last_error
        raise ProviderError("provider_error", "Provider request failed", retryable=True)

    async def _request(self, prompt: str) -> ProviderResult:
        payload: dict = {
            "model": self.settings.ai_model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
            "temperature": 0.1,
        }
        if self.settings.ai_json_mode:
            payload["response_format"] = {"type": "json_object"}
        if self.settings.ai_reasoning_effort:
            payload["reasoning_effort"] = self.settings.ai_reasoning_effort
        headers = {}
        if self.settings.ai_api_key:
            headers["Authorization"] = f"Bearer {self.settings.ai_api_key}"

        try:
            async with httpx.AsyncClient(
                timeout=self.settings.ai_timeout_seconds
            ) as client:
                response = await client.post(
                    f"{self.settings.ai_base_url.rstrip('/')}/chat/completions",
                    json=payload,
                    headers=headers,
                )
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            raise ProviderError(
                "provider_unavailable",
                f"The AI provider at {self.settings.ai_base_url} could not be reached",
                retryable=True,
            ) from exc

        request_id = response.headers.get("x-request-id")
        if response.status_code in {401, 403}:
            raise ProviderError(
                "provider_authentication_failed",
                "The AI provider rejected its credentials",
                retryable=False,
                request_id=request_id,
            )
        if response.status_code == 429 or response.status_code >= 500:
            raise ProviderError(
                "provider_retryable_error",
                f"The AI provider returned HTTP {response.status_code}",
                retryable=True,
                request_id=request_id,
            )
        if response.status_code >= 400:
            raise ProviderError(
                "provider_request_rejected",
                f"The AI provider returned HTTP {response.status_code}",
                retryable=False,
                request_id=request_id,
            )

        try:
            body = response.json()
            content = body["choices"][0]["message"]["content"]
            data = self._extract_object(content)
        except (KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ProviderError(
                "invalid_provider_response",
                "The AI provider returned malformed JSON",
                retryable=True,
                request_id=request_id,
            ) from exc

        usage = body.get("usage") or {}
        return ProviderResult(
            data=data,
            request_id=request_id,
            input_tokens=usage.get("prompt_tokens"),
            output_tokens=usage.get("completion_tokens"),
        )

    @staticmethod
    def _extract_object(content: object) -> dict:
        text = str(content).strip()
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            start = text.find("{")
            end = text.rfind("}")
            if start < 0 or end <= start:
                raise
            parsed = json.loads(text[start : end + 1])
        if not isinstance(parsed, dict):
            raise ValueError("Provider response was not a JSON object")
        return parsed

