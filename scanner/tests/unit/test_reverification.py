import httpx
import pytest

from app import reverification
from shared.models.reverification import ReverificationOutcome
from shared.models.vulnerability import AuthContext, VerificationTarget


def test_exact_replay_preserves_captured_json_body() -> None:
    target = VerificationTarget(
        detector_id="access_control",
        url="https://target.example/api/profile",
        method="POST",
        parameter="userId",
        parameter_location="json_body",
        payload="2",
        request_template={
            "replay_exact": True,
            "json_body": {"userId": "2", "include": "summary"},
        },
    )

    url, kwargs = reverification._build_request(target, target.payload)

    assert url == target.url
    assert kwargs == {"json": {"userId": "2", "include": "summary"}}


@pytest.mark.asyncio
async def test_focused_reverification_replays_parameter_and_captures_evidence(
    monkeypatch,
) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=f"result: {request.url.params['q']}")

    def client_factory(**kwargs):
        kwargs.pop("limits", None)
        return httpx.AsyncClient(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(reverification, "create_scan_client", client_factory)
    target = VerificationTarget(
        detector_id="xss_detector",
        url="https://target.example/search",
        method="GET",
        parameter="q",
        parameter_location="query",
        payload="sentry-reflection-proof",
        proof_type="reflection",
        auth_context=AuthContext.unauthenticated,
    )

    outcome, evidence = await reverification.run_focused_reverification(target, [])

    assert outcome == ReverificationOutcome.reproduced
    assert evidence[-1].proof_matched is True
    assert "q=sentry-reflection-proof" in evidence[-1].request_url
    assert evidence[-1].status_code == 200


@pytest.mark.asyncio
async def test_authenticated_target_without_credentials_is_inconclusive() -> None:
    target = VerificationTarget(
        detector_id="idor_detector",
        url="https://target.example/api/items/2",
        auth_context=AuthContext.authenticated,
    )

    outcome, evidence = await reverification.run_focused_reverification(target, [])

    assert outcome == ReverificationOutcome.inconclusive
    assert "requires authentication" in evidence[0].reason
