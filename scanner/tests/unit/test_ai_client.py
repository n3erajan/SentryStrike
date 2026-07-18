import json

import httpx
import pytest

from app.analyzers.ai_client import AIClient
from app.config import get_settings


class _FakeResponse:
    """Minimal stand-in for an httpx.Response used to stub HTTP calls."""

    def __init__(self, status_code: int = 200, payload: dict | None = None) -> None:
        self.status_code = status_code
        self._payload = payload or {}
        self.text = json.dumps(self._payload)

    def json(self) -> dict:
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("error", request=None, response=self)


def _chat_response(text: str) -> _FakeResponse:
    return _FakeResponse(200, {"choices": [{"message": {"content": text}}]})


def _patch_post(monkeypatch, capture: dict, response: _FakeResponse) -> None:
    """Patch ``httpx.AsyncClient.post`` to capture the request and return *response*."""

    async def fake_post(self, url, **kwargs):
        capture["url"] = str(url)
        capture["json"] = kwargs.get("json")
        capture["headers"] = kwargs.get("headers")
        return response

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)


# ---------------------------------------------------------------------------
# Request shape
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_builds_chat_completions_request(monkeypatch):
    monkeypatch.setenv("AI_BASE_URL", "https://api.openai.com/v1")
    monkeypatch.setenv("AI_API_KEY", "sk-secret")
    monkeypatch.setenv("AI_MODEL", "gpt-4o-mini")
    get_settings.cache_clear()
    try:
        capture: dict = {}
        _patch_post(monkeypatch, capture, _chat_response('{"exploitability": "Easy"}'))
        client = AIClient()
        result = await client.generate_json("analyse finding")

        assert result == {"exploitability": "Easy"}
        assert capture["url"] == "https://api.openai.com/v1/chat/completions"
        assert capture["headers"]["Authorization"] == "Bearer sk-secret"
        body = capture["json"]
        assert body["model"] == "gpt-4o-mini"
        assert body["messages"] == [{"role": "user", "content": "analyse finding"}]
        assert body["stream"] is False
        assert body["temperature"] == 0.1
        assert body["response_format"] == {"type": "json_object"}
    finally:
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_no_authorization_header_when_api_key_absent(monkeypatch):
    """Local Ollama / unauthenticated servers need no key — don't send the header."""
    monkeypatch.delenv("AI_API_KEY", raising=False)
    monkeypatch.setenv("AI_BASE_URL", "http://localhost:11434/v1")
    get_settings.cache_clear()
    try:
        capture: dict = {}
        _patch_post(monkeypatch, capture, _chat_response('{"a": 1}'))
        await AIClient().generate_json("x")
        assert "Authorization" not in (capture["headers"] or {})
        assert capture["url"] == "http://localhost:11434/v1/chat/completions"
    finally:
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_trailing_slash_in_base_url_is_stripped(monkeypatch):
    monkeypatch.setenv("AI_BASE_URL", "https://api.groq.com/openai/v1/")
    monkeypatch.setenv("AI_API_KEY", "sk-test")
    monkeypatch.setenv("AI_MODEL", "llama-3.3-70b-versatile")
    get_settings.cache_clear()
    try:
        capture: dict = {}
        _patch_post(monkeypatch, capture, _chat_response('{"a": 1}'))
        await AIClient().generate_json("x")
        assert capture["url"] == "https://api.groq.com/openai/v1/chat/completions"
    finally:
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_json_mode_can_be_disabled(monkeypatch):
    monkeypatch.setenv("AI_API_KEY", "sk-test")
    monkeypatch.setenv("AI_JSON_MODE", "false")
    get_settings.cache_clear()
    try:
        capture: dict = {}
        _patch_post(monkeypatch, capture, _chat_response('{"a": 1}'))
        await AIClient().generate_json("x")
        assert "response_format" not in capture["json"]
    finally:
        get_settings.cache_clear()


# ---------------------------------------------------------------------------
# JSON extraction
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_extracts_json_from_plain_text(monkeypatch):
    """With JSON mode off, models often wrap JSON in prose — extraction must recover it."""
    monkeypatch.setenv("AI_API_KEY", "sk-test")
    monkeypatch.setenv("AI_JSON_MODE", "false")
    get_settings.cache_clear()
    try:
        capture: dict = {}
        _patch_post(
            monkeypatch, capture,
            _chat_response('Here is the analysis:\n{"confidence": 0.9}\nDone.'),
        )
        result = await AIClient().generate_json("x")
        assert result == {"confidence": 0.9}
    finally:
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_generate_json_unwraps_single_element_array(monkeypatch):
    """Some providers wrap a single object in an array [{...}] — must be unwrapped
    so callers get a dict, not a list (which would break result.get(...))."""
    monkeypatch.setenv("AI_API_KEY", "sk-test")
    get_settings.cache_clear()
    try:
        capture: dict = {}
        _patch_post(monkeypatch, capture, _chat_response('[{"confidence": 0.7}]'))
        result = await AIClient().generate_json("x")
        assert result == {"confidence": 0.7}
    finally:
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_generate_json_unwraps_array_embedded_in_prose(monkeypatch):
    """Array-in-prose with JSON mode off must still reduce to a dict."""
    monkeypatch.setenv("AI_API_KEY", "sk-test")
    monkeypatch.setenv("AI_JSON_MODE", "false")
    get_settings.cache_clear()
    try:
        capture: dict = {}
        _patch_post(
            monkeypatch, capture,
            _chat_response('Result:\n[{"exploitability": "Easy"}]\nDone.'),
        )
        result = await AIClient().generate_json("x")
        assert result == {"exploitability": "Easy"}
    finally:
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_reasoning_effort_sent_when_configured(monkeypatch):
    """AI_REASONING_EFFORT is forwarded as a string to disable model thinking."""
    monkeypatch.setenv("AI_API_KEY", "sk-test")
    monkeypatch.setenv("AI_REASONING_EFFORT", "none")
    get_settings.cache_clear()
    try:
        capture: dict = {}
        _patch_post(monkeypatch, capture, _chat_response('{"a": 1}'))
        await AIClient().generate_json("x")
        assert capture["json"]["reasoning_effort"] == "none"
    finally:
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_reasoning_effort_defaults_to_none(monkeypatch):
    """When unset, reasoning_effort defaults to "none" — thinking disabled by default."""
    monkeypatch.setenv("AI_API_KEY", "sk-test")
    monkeypatch.delenv("AI_REASONING_EFFORT", raising=False)
    get_settings.cache_clear()
    try:
        capture: dict = {}
        _patch_post(monkeypatch, capture, _chat_response('{"a": 1}'))
        await AIClient().generate_json("x")
        assert capture["json"]["reasoning_effort"] == "none"
    finally:
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_generate_json_list(monkeypatch):
    monkeypatch.setenv("AI_API_KEY", "sk-test")
    get_settings.cache_clear()
    try:
        items = [
            {"exploitability": "Easy", "business_impact": "a"},
            {"exploitability": "Hard", "business_impact": "b"},
        ]
        capture: dict = {}
        _patch_post(monkeypatch, capture, _chat_response(json.dumps(items)))
        result = await AIClient().generate_json_list("batch prompt", expected_count=2)
        assert result == items
    finally:
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_generate_json_list_unwraps_object_wrapping_array(monkeypatch):
    """Some providers wrap the array in {"results": [...]} — must be unwrapped."""
    monkeypatch.setenv("AI_API_KEY", "sk-test")
    get_settings.cache_clear()
    try:
        wrapped = {"results": [{"a": 1}]}
        capture: dict = {}
        _patch_post(monkeypatch, capture, _chat_response(json.dumps(wrapped)))
        result = await AIClient().generate_json_list("p", expected_count=1)
        assert result == [{"a": 1}]
    finally:
        get_settings.cache_clear()


# ---------------------------------------------------------------------------
# Retries
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_retries_then_succeeds(monkeypatch):
    monkeypatch.setenv("AI_API_KEY", "sk-test")
    monkeypatch.setenv("AI_MAX_RETRIES", "2")
    get_settings.cache_clear()
    try:
        attempts = 0

        async def flaky_post(self, url, **kwargs):
            nonlocal attempts
            attempts += 1
            if attempts < 3:
                raise httpx.ConnectError("transient")
            return _chat_response('{"ok": true}')

        monkeypatch.setattr(httpx.AsyncClient, "post", flaky_post)
        result = await AIClient().generate_json("x")
        assert result == {"ok": True}
        assert attempts == 3
    finally:
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_fails_after_exhausting_retries(monkeypatch):
    monkeypatch.setenv("AI_API_KEY", "sk-test")
    monkeypatch.setenv("AI_MAX_RETRIES", "1")
    get_settings.cache_clear()
    try:
        async def always_fail(self, url, **kwargs):
            raise httpx.ConnectError("down")

        monkeypatch.setattr(httpx.AsyncClient, "post", always_fail)
        with pytest.raises(RuntimeError, match="failed to generate JSON after retries"):
            await AIClient().generate_json("x")
    finally:
        get_settings.cache_clear()
