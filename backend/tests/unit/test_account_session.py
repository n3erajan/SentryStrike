import pytest

from app.core.crawler import account_session as acct
from app.core.crawler.auth_manager import AuthResult
from app.models.scan import ScanAuthAccount, ScanAuthRole


class _FakeJar:
    def __init__(self, cookies):
        self._cookies = [type("C", (), {"name": k, "value": v}) for k, v in cookies.items()]

    def __iter__(self):
        return iter(self._cookies)


class _FakeCookies:
    def __init__(self, cookies):
        self.jar = _FakeJar(cookies)


class _FakeClient:
    def __init__(self, cookies=None):
        self.cookies = _FakeCookies(cookies or {})

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


def _patch_login(monkeypatch, *, result: AuthResult, client_cookies=None):
    monkeypatch.setattr(acct, "create_scan_client", lambda **_: _FakeClient(client_cookies))

    class _FakeAuthenticator:
        def __init__(self, _settings):
            pass

        async def authenticate(self, client, url, email, password):
            return result

    monkeypatch.setattr(acct, "SmartAuthenticator", _FakeAuthenticator)


async def test_raw_cookie_and_header_without_login():
    account = ScanAuthAccount(
        role=ScanAuthRole.second,
        cookie="session=abc; csrf=def",
        header="Authorization: Bearer xyz",
    )
    session = await acct.resolve_account_session("http://target", account)
    assert session.cookies == {"session": "abc", "csrf": "def"}
    assert session.headers == {"Authorization": "Bearer xyz"}
    assert session.usable


async def test_credential_login_success(monkeypatch):
    _patch_login(
        monkeypatch,
        result=AuthResult(authenticated=True, cookies={"sid": "1"}, bearer_token="tok"),
        client_cookies={"extra": "2"},
    )
    account = ScanAuthAccount(role=ScanAuthRole.admin, username="a@b.c", password="pw")
    session = await acct.resolve_account_session("http://target", account)
    assert session.cookies["sid"] == "1"
    assert session.cookies["extra"] == "2"  # picked up from the client jar
    assert session.headers["Authorization"] == "Bearer tok"
    assert session.usable


async def test_login_failure_falls_back_to_raw_cookie(monkeypatch):
    _patch_login(monkeypatch, result=AuthResult(authenticated=False))
    account = ScanAuthAccount(role=ScanAuthRole.main, username="a@b.c", password="pw", cookie="k=v")
    session = await acct.resolve_account_session("http://target", account)
    assert session.cookies == {"k": "v"}
    assert session.usable


async def test_empty_account_is_unusable(monkeypatch):
    _patch_login(monkeypatch, result=AuthResult(authenticated=False))
    account = ScanAuthAccount(role=ScanAuthRole.second, username="a@b.c", password="pw")
    session = await acct.resolve_account_session("http://target", account)
    assert not session.usable
    assert session.cookies == {}
    assert session.headers == {}
