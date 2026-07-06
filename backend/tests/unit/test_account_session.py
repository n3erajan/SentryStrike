import sys
import types

import pytest

from app.core.crawler import account_session as acct
from app.core.crawler.auth_manager import AuthReplayState, AuthResult, AuthStrategy, SmartAuthenticator
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


# --- P1-2: reuse the main account's winning login path ---------------------------------


def test_substitute_replay_credentials_swaps_by_value():
    payload = {"email": "main@x.test", "password": "MAINPW", "csrf": "keepme"}
    out = SmartAuthenticator._substitute_replay_credentials(
        payload, "main@x.test", "MAINPW", "second@x.test", "SECONDPW"
    )
    assert out == {"email": "second@x.test", "password": "SECONDPW", "csrf": "keepme"}


def test_substitute_replay_credentials_falls_back_to_field_names():
    payload = {"email": "placeholder@example.test", "password": "", "csrf": "keepme"}
    out = SmartAuthenticator._substitute_replay_credentials(
        payload, None, None, "second@x.test", "SECONDPW"
    )
    assert out == {"email": "second@x.test", "password": "SECONDPW", "csrf": "keepme"}


def _patch_replay(monkeypatch, *, replay_result, cascade_result, client_cookies=None):
    """Patch the authenticator to record which login path was taken."""
    monkeypatch.setattr(acct, "create_scan_client", lambda **_: _FakeClient(client_cookies))
    calls: list[str] = []

    class _FakeAuthenticator:
        def __init__(self, _settings):
            pass

        async def authenticate_with_replay(self, client, replay, email, password, **kwargs):
            calls.append("replay")
            return replay_result

        async def authenticate(self, client, url, email, password):
            calls.append("cascade")
            return cascade_result

    monkeypatch.setattr(acct, "SmartAuthenticator", _FakeAuthenticator)
    return calls


async def test_resolve_prefers_replay_and_skips_cascade(monkeypatch):
    calls = _patch_replay(
        monkeypatch,
        replay_result=AuthResult(authenticated=True, cookies={"sid": "second"}),
        cascade_result=AuthResult(authenticated=True, cookies={"sid": "cascade"}),
    )
    account = ScanAuthAccount(role=ScanAuthRole.second, username="s@x.test", password="pw")
    replay = AuthReplayState(login_url="http://t/login", action="http://t/api/login",
                             method="POST", payload={"email": "m@x.test", "password": "mpw"})
    session = await acct.resolve_account_session(
        "http://target", account, preferred_replay=replay,
        primary_credentials=("m@x.test", "mpw"),
    )
    assert calls == ["replay"], "winning recipe must be replayed without the full cascade"
    assert session.cookies["sid"] == "second"


async def test_resolve_forwards_storage_state_from_replay(monkeypatch):
    """Change 3b: the 2nd/admin account's storage_state (captured by the fast
    replay path) is carried on the ResolvedSession, and no browser relaunch
    happens on the non-browser replay fast-path (only ``replay`` runs)."""
    blob = {"cookies": [{"name": "s", "value": "1"}], "origins": []}
    calls = _patch_replay(
        monkeypatch,
        replay_result=AuthResult(
            authenticated=True, cookies={"sid": "second"}, storage_state=blob
        ),
        cascade_result=AuthResult(authenticated=False),
    )
    account = ScanAuthAccount(role=ScanAuthRole.second, username="s@x.test", password="pw")
    replay = AuthReplayState(login_url="http://t/login", action="http://t/api/login",
                             method="POST", payload={"email": "m@x.test", "password": "mpw"})
    session = await acct.resolve_account_session(
        "http://target", account, preferred_replay=replay,
        primary_credentials=("m@x.test", "mpw"),
    )
    assert calls == ["replay"], "fast replay path must not fall through to a browser cascade"
    assert session.storage_state == blob


async def test_resolve_falls_back_to_cascade_when_replay_fails(monkeypatch):
    calls = _patch_replay(
        monkeypatch,
        replay_result=AuthResult(authenticated=False),
        cascade_result=AuthResult(authenticated=True, cookies={"sid": "cascade"}),
    )
    account = ScanAuthAccount(role=ScanAuthRole.admin, username="a@x.test", password="pw")
    replay = AuthReplayState(login_url="http://t/login", action="http://t/api/login",
                             method="POST", payload={"email": "m@x.test", "password": "mpw"})
    session = await acct.resolve_account_session(
        "http://target", account, preferred_replay=replay,
        primary_credentials=("m@x.test", "mpw"),
    )
    assert calls == ["replay", "cascade"], "must fall back to the cascade when replay fails"
    assert session.cookies["sid"] == "cascade"


async def test_browser_spa_login_records_replay_state(monkeypatch):
    class _FakeKeyboard:
        async def press(self, _key):
            return None

    class _FakeElement:
        def __init__(self, attrs=None):
            self.attrs = attrs or {}

        async def is_visible(self):
            return True

        async def is_enabled(self):
            return True

        async def get_attribute(self, name):
            return self.attrs.get(name)

        async def click(self, *_, **__):
            return None

    class _FakeLocator:
        def __init__(self, elements):
            self._elements = elements
            self.first = elements[0] if elements else _FakeElement()

        async def count(self):
            return len(self._elements)

        def nth(self, index):
            return self._elements[index]

    class _FakePage:
        def __init__(self):
            self.url = ""
            self.keyboard = _FakeKeyboard()
            self.fills = []

        async def goto(self, url, **_kwargs):
            self.url = url

        def locator(self, selector):
            if selector == "input[type='password']":
                return _FakeLocator([_FakeElement({"type": "password", "name": "password"})])
            if selector == "input":
                return _FakeLocator([
                    _FakeElement({"type": "email", "name": "email"}),
                    _FakeElement({"type": "password", "name": "password"}),
                ])
            if selector == "button[type='submit']":
                return _FakeLocator([_FakeElement()])
            return _FakeLocator([])

        async def wait_for_selector(self, *_args, **_kwargs):
            return None

        async def wait_for_load_state(self, *_args, **_kwargs):
            return None

        async def wait_for_timeout(self, *_args, **_kwargs):
            return None

        async def fill(self, selector, value):
            self.fills.append((selector, value))

        async def press(self, *_args, **_kwargs):
            return None

        async def evaluate(self, *_args, **_kwargs):
            return "{}"

    class _FakeContext:
        def __init__(self, page):
            self.page = page

        async def new_page(self):
            return self.page

        async def cookies(self):
            return [{"name": "sid", "value": "abc"}]

        async def storage_state(self):
            return {"cookies": [], "origins": []}

        async def close(self):
            return None

    class _FakeBrowser:
        def __init__(self, page):
            self.context = _FakeContext(page)

        async def new_context(self):
            return self.context

        async def close(self):
            return None

    class _FakeChromium:
        def __init__(self, page):
            self.page = page

        async def launch(self, **_kwargs):
            return _FakeBrowser(self.page)

    class _FakePlaywright:
        def __init__(self, page):
            self.chromium = _FakeChromium(page)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_exc):
            return False

    page = _FakePage()
    fake_module = types.SimpleNamespace(async_playwright=lambda: _FakePlaywright(page))
    monkeypatch.setitem(sys.modules, "playwright", types.SimpleNamespace(async_api=fake_module))
    monkeypatch.setitem(sys.modules, "playwright.async_api", fake_module)

    auth = SmartAuthenticator(settings=types.SimpleNamespace())

    async def _verified(_client, _response=None):
        return AuthResult(authenticated=True)

    monkeypatch.setattr(auth, "_verify_auth", _verified)
    client = types.SimpleNamespace(cookies={}, headers={})

    result = await auth._try_browser_spa_login(client, "http://target", "second@example.test", "pw")

    assert result.authenticated
    assert result.strategy == AuthStrategy.browser_spa
    assert result.replay_state is not None
    assert result.replay_state.method == "BROWSER"
    assert result.replay_state.action == "http://target"
    assert result.replay_state.payload == {
        "username_selector": "input[name='email']",
        "password_selector": "input[type='password']",
        "submit_selector": "button[type='submit']",
    }


async def test_authenticate_with_replay_uses_browser_recipe(monkeypatch):
    auth = SmartAuthenticator(settings=types.SimpleNamespace())
    replay = AuthReplayState(
        login_url="http://target/login",
        action="http://target/login",
        method="BROWSER",
        payload={
            "username_selector": "input[name='email']",
            "password_selector": "input[type='password']",
            "submit_selector": "button[type='submit']",
        },
    )
    calls = []
    fills = []

    class _Client:
        def __init__(self):
            self.headers = {}
            self.cookies = {}

        async def get(self, url, **kwargs):
            calls.append(("prefetch", url, kwargs))

    class _ReplayPage:
        async def goto(self, url, **_kwargs):
            calls.append(("browser_goto", url))

        async def fill(self, selector, value):
            fills.append((selector, value))

        async def click(self, selector, **_kwargs):
            calls.append(("click", selector))

        async def press(self, selector, key):
            calls.append(("press", selector, key))

        async def wait_for_load_state(self, *_args, **_kwargs):
            return None

        async def wait_for_timeout(self, *_args, **_kwargs):
            return None

        async def evaluate(self, *_args, **_kwargs):
            return "{}"

    class _ReplayContext:
        async def new_page(self):
            return _ReplayPage()

        async def cookies(self):
            return [{"name": "sid", "value": "second"}]

        async def storage_state(self):
            return {"cookies": [], "origins": []}

        async def close(self):
            return None

    class _ReplayBrowser:
        async def new_context(self):
            return _ReplayContext()

        async def close(self):
            return None

    class _ReplayChromium:
        async def launch(self, **_kwargs):
            return _ReplayBrowser()

    class _ReplayPlaywright:
        chromium = _ReplayChromium()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_exc):
            return False

    fake_module = types.SimpleNamespace(async_playwright=lambda: _ReplayPlaywright())
    monkeypatch.setitem(sys.modules, "playwright", types.SimpleNamespace(async_api=fake_module))
    monkeypatch.setitem(sys.modules, "playwright.async_api", fake_module)

    async def _verified(_client, _response=None):
        return AuthResult(authenticated=True)

    monkeypatch.setattr(auth, "_verify_auth", _verified)

    result = await auth.authenticate_with_replay(
        _Client(),
        replay,
        "second@example.test",
        "second-password",
        prior_username="main@example.test",
        prior_password="main-password",
    )

    assert result.authenticated
    assert result.replay_state is not None
    assert result.replay_state.method == "BROWSER"
    assert fills == [
        ("input[name='email']", "second@example.test"),
        ("input[type='password']", "second-password"),
    ]
    assert calls == [
        ("prefetch", "http://target/login", {"follow_redirects": True}),
        ("browser_goto", "http://target/login"),
        ("click", "button[type='submit']"),
    ]
