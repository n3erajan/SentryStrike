import re

import pytest
from unittest.mock import AsyncMock, patch
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from shared.verification.oast import OastClient, INTERACTION_ID_RE


def test_is_valid_interaction_id_accepts_genuine_minted_id():
    # Exactly what new_callback_url mints: purpose + uuid4().hex (32 lowercase hex)
    genuine = "ssrf-" + "a" * 32
    assert OastClient.is_valid_interaction_id(genuine) is True
    assert OastClient.is_valid_interaction_id("ssrf-0123456789abcdef0123456789abcdef") is True


def test_is_valid_interaction_id_rejects_non_genuine():
    for bad in [
        "",
        "notauuid",
        "ssrf-tooShort",
        "ssrf-" + "a" * 31,          # 31 hex — too short
        "ssrf-" + "a" * 33,          # 33 hex — too long
        "ssrf-" + "A" * 32,          # uppercase — uuid4().hex is lowercase
        "ssrf-../../etc/passwd",
        "ssrf-" + "g" * 32,          # non-hex
        "-" + "a" * 32,              # missing purpose
        "ssrf_" + "a" * 32,          # wrong separator
    ]:
        assert OastClient.is_valid_interaction_id(bad) is False, bad


def test_minted_ids_always_pass_validation():
    client = OastClient("https://example.test/oast")
    for purpose in ("ssrf", "xxe", "a"):
        _url, iid = client.new_callback_url(purpose)
        assert INTERACTION_ID_RE.match(iid)
        assert OastClient.is_valid_interaction_id(iid) is True


from app.api.routes import oast as oast_route


def _app_with_oast():
    app = FastAPI()
    app.include_router(oast_route.router)
    return app


@pytest.mark.asyncio
async def test_catcher_records_genuine_id_and_returns_ok():
    genuine = "ssrf-" + "0" * 32
    saved = {}

    class _FakeRecord:
        def __init__(self, **kwargs):
            self._kwargs = kwargs

        async def insert(self):
            saved.update(self._kwargs)
            return self

    with patch("app.api.routes.oast.OastInteractionRecord", _FakeRecord):
        transport = ASGITransport(app=_app_with_oast())
        async with AsyncClient(transport=transport, base_url="http://t") as c:
            resp = await c.get(f"/oast/{genuine}")
    assert resp.status_code == 200
    assert resp.text == "ok"
    assert saved["interaction_id"] == genuine


@pytest.mark.asyncio
async def test_catcher_rejects_non_genuine_id_without_writing():
    inserted = False

    class _FakeRecord:
        def __init__(self, **kwargs):
            pass

        async def insert(self):
            nonlocal inserted
            inserted = True
            return self

    with patch("app.api.routes.oast.OastInteractionRecord", _FakeRecord):
        transport = ASGITransport(app=_app_with_oast())
        async with AsyncClient(transport=transport, base_url="http://t") as c:
            resp = await c.get("/oast/not-a-real-uuid")
    assert resp.status_code == 404
    assert inserted is False


@pytest.mark.asyncio
async def test_poll_returns_interactions_for_genuine_id():
    genuine = "ssrf-" + "f" * 32

    class _Doc:
        interaction_id = genuine
        source_ip = "10.0.0.9"
        path = f"/oast/{genuine}"
        method = "GET"
        received_at = __import__("datetime").datetime(2026, 7, 12)

    find_result = AsyncMock()
    find_result.limit = lambda n: find_result
    find_result.to_list = AsyncMock(return_value=[_Doc()])
    with patch("app.api.routes.oast.OastInteractionRecord.find", return_value=find_result):
        transport = ASGITransport(app=_app_with_oast())
        async with AsyncClient(transport=transport, base_url="http://t") as c:
            resp = await c.get("/oast/poll", params={"id": genuine})
    assert resp.status_code == 200
    body = resp.json()
    assert isinstance(body, list) and body[0]["interaction_id"] == genuine


@pytest.mark.asyncio
async def test_poll_rejects_non_genuine_id_returns_empty():
    transport = ASGITransport(app=_app_with_oast())
    async with AsyncClient(transport=transport, base_url="http://t") as c:
        resp = await c.get("/oast/poll", params={"id": "bogus"})
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_oastclient_poll_parses_route_json_shape():
    """OastClient.poll must consume the exact list-of-dicts shape /oast/poll
    emits (each dict carries the interaction_id), so the collaborator and the
    detector agree end to end."""
    import shared.verification.oast as oast_mod

    genuine = "ssrf-" + "1" * 32
    # Exactly the shape backend/app/api/routes/oast.py::poll returns.
    route_payload = [
        {
            "interaction_id": genuine,
            "source_ip": "172.17.0.1",
            "path": f"/oast/{genuine}",
            "method": "GET",
            "received_at": "2026-07-12T00:00:00",
        }
    ]

    class _Resp:
        status_code = 200

        def json(self):
            return route_payload

    class _CtxClient:
        def __init__(self, *a, **k):
            ...

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url):
            return _Resp()

    client = OastClient("http://t/oast", "http://t/oast/poll")
    with patch.object(oast_mod.httpx, "AsyncClient", _CtxClient):
        interactions = await client.poll(genuine)

    assert len(interactions) == 1
    assert interactions[0].interaction_id == genuine

