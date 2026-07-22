from __future__ import annotations

import json
from dataclasses import dataclass

import httpx

from app.config import get_settings


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

    async def generate_json(self, prompt: str) -> ProviderResult:
        last_error: ProviderError | None = None
        for _ in range(self.settings.ai_max_retries + 1):
            try:
                return await self._request(prompt)
            except ProviderError as exc:
                last_error = exc
                if not exc.retryable:
                    raise
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
                "The AI provider could not be reached",
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

