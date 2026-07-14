"""Resolve scan-submitted account credentials into live sessions.

Users may submit up to three optional accounts (main / second / admin) when
creating a scan. Rather than relying on hand-pasted cookie strings via env
vars (fragile when a session spans multiple cookies), we log each account in
against the target and capture the resulting cookies/headers. Raw cookie /
header strings are still supported as a fallback.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from app.config import get_settings
from app.core.crawler.auth_manager import AuthReplayState, SmartAuthenticator
from app.models.scan import ScanAuthAccount
from app.utils.scan_http import create_scan_client

logger = logging.getLogger(__name__)


@dataclass
class ResolvedSession:
    """A resolved account session: cookies + headers ready for HTTP replay.

    ``storage_state`` is the full authenticated browser blob (cookies +
    per-origin localStorage/sessionStorage) when the login used a browser path,
    so a downstream browser-based access-control check can seed its context
    directly instead of re-running a full login (which can cascade into another
    Chromium launch).
    """

    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    storage_state: dict | None = None

    @property
    def usable(self) -> bool:
        return bool(self.cookies or self.headers)


def _parse_cookie_string(value: str | None) -> dict[str, str]:
    cookies: dict[str, str] = {}
    if not value:
        return cookies
    for cookie in value.split(";"):
        cookie = cookie.strip()
        if "=" in cookie:
            key, val = cookie.split("=", 1)
            key = key.strip()
            if key:
                cookies[key] = val.strip()
    return cookies


def _parse_header_string(value: str | None) -> dict[str, str]:
    if not value or ":" not in value:
        return {}
    key, val = value.split(":", 1)
    key, val = key.strip(), val.strip()
    return {key: val} if key and val else {}


async def resolve_account_session(
    root_url: str,
    account: ScanAuthAccount,
    *,
    preferred_replay: AuthReplayState | None = None,
    primary_credentials: tuple[str | None, str | None] | None = None,
) -> ResolvedSession:
    """Log ``account`` in against ``root_url`` (or apply its raw cookies/headers).

    When ``preferred_replay`` (the login recipe that authenticated the main
    account) is supplied, it is replayed first with this account's credentials —
    so second/admin logins reuse the *same winning path* instead of restarting
    the whole strategy cascade from Strategy 1. Falls back to the full cascade if
    the replay does not authenticate.

    Never raises: on failure it logs and returns an empty (unusable) session so a
    single bad credential can't abort the scan.
    """
    session = ResolvedSession()

    # 1. Raw cookie / header strings take effect regardless of login outcome.
    session.cookies.update(_parse_cookie_string(account.cookie))
    session.headers.update(_parse_header_string(account.header))

    # 2. Credential login against the target to obtain a fresh, complete session.
    if account.username and account.password:
        settings = get_settings()
        login_target = account.login_url or root_url
        prior_username, prior_password = primary_credentials or (None, None)
        try:
            async with create_scan_client(
                timeout=settings.request_timeout_seconds,
                follow_redirects=True,
                headers={"User-Agent": "SentryStrikeScanner/1.0"},
            ) as client:
                authenticator = SmartAuthenticator(settings)
                result = None
                # Fast path: replay the main account's winning login recipe.
                if preferred_replay is not None:
                    result = await authenticator.authenticate_with_replay(
                        client,
                        preferred_replay,
                        account.username,
                        account.password,
                        prior_username=prior_username,
                        prior_password=prior_password,
                    )
                    if not (result and result.authenticated):
                        logger.info(
                            "recipe replay did not authenticate %s account; "
                            "falling back to full strategy cascade",
                            account.role.value,
                        )
                        result = None
                # Fallback: full multi-strategy cascade.
                if result is None:
                    result = await authenticator.authenticate(
                        client, login_target, account.username, account.password
                    )
                if result.authenticated:
                    session.cookies.update(result.cookies or {})
                    # Snapshot any cookies the client picked up during the flow.
                    for cookie in client.cookies.jar:
                        session.cookies.setdefault(cookie.name, cookie.value)
                    if result.bearer_token:
                        session.headers["Authorization"] = f"Bearer {result.bearer_token}"
                    # Forward the full authenticated browser blob (cookies +
                    # localStorage) when the login captured one, so a browser-based
                    # access-control check can reuse it instead of re-logging-in.
                    session.storage_state = getattr(result, "storage_state", None)
                    logger.info(
                        "resolved session for %s account via login (cookies=%d, bearer=%s)",
                        account.role.value,
                        len(session.cookies),
                        bool(result.bearer_token),
                    )
                else:
                    logger.warning(
                        "login failed for %s account (%s); "
                        "falling back to any raw cookie/header supplied",
                        account.role.value,
                        result.verification_evidence or "no evidence",
                    )
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("session resolution errored for %s account: %s", account.role.value, exc)

    return session


async def provision_secondary_session(root_url: str, allow_override: bool | None = None) -> ResolvedSession:
    """Auto-provision a throwaway second identity for differential IDOR/BOLA.

    Gated by ``allow_secondary_provisioning`` (or ``allow_override`` when set).
    Registers and logs in a random throwaway user against ``root_url`` and returns
    its session. Never raises: when provisioning is disabled or not possible, returns
    an empty (unusable) session so IDOR simply falls back to whatever identities
    already exist.
    """
    session = ResolvedSession()
    settings = get_settings()
    allowed = allow_override if allow_override is not None else getattr(settings, "allow_secondary_provisioning", False)
    if not allowed:
        return session

    try:
        async with create_scan_client(
            timeout=settings.request_timeout_seconds,
            follow_redirects=True,
            headers={"User-Agent": "SentryStrikeScanner/1.0"},
        ) as client:
            result = await SmartAuthenticator(settings).acquire_secondary_identity(client, root_url)
            if result and result.authenticated:
                session.cookies.update(result.cookies or {})
                for cookie in client.cookies.jar:
                    session.cookies.setdefault(cookie.name, cookie.value)
                if result.bearer_token:
                    session.headers["Authorization"] = f"Bearer {result.bearer_token}"
                session.storage_state = getattr(result, "storage_state", None)
                logger.info(
                    "auto-provisioned secondary identity on %s (cookies=%d, bearer=%s)",
                    root_url,
                    len(session.cookies),
                    bool(result.bearer_token),
                )
            else:
                logger.info("secondary identity could not be auto-provisioned on %s", root_url)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("secondary identity provisioning errored on %s: %s", root_url, exc)

    return session


@dataclass
class DisposableAccount:
    """A self-provisioned throwaway account whose credentials the caller knows.

    Unlike the shared secondary IDOR identity, this account is intended to be
    *mutated* (e.g. its password changed) by a single test in isolation, so it
    must never be reused for anything else.
    """

    email: str
    password: str
    session: ResolvedSession


async def provision_disposable_account(
    root_url: str, allow_override: bool | None = None
) -> DisposableAccount | None:
    """Register a fresh throwaway account and return it WITH its credentials.

    Separate from :func:`provision_secondary_session` on purpose: the returned
    account is meant to be destructively mutated by one test (e.g. a password
    change) without corrupting the shared IDOR second identity or the user's real
    scan session. Gated by ``allow_secondary_provisioning``. Never raises; returns
    ``None`` when provisioning is disabled or not possible.
    """
    settings = get_settings()
    allowed = allow_override if allow_override is not None else getattr(settings, "allow_secondary_provisioning", False)
    if not allowed:
        return None

    try:
        async with create_scan_client(
            timeout=settings.request_timeout_seconds,
            follow_redirects=True,
            headers={"User-Agent": "SentryStrikeScanner/1.0"},
        ) as client:
            result = await SmartAuthenticator(settings).acquire_secondary_identity(client, root_url)
            if not (result and result.authenticated and result.account_email and result.account_password):
                return None
            session = ResolvedSession()
            session.cookies.update(result.cookies or {})
            for cookie in client.cookies.jar:
                session.cookies.setdefault(cookie.name, cookie.value)
            if result.bearer_token:
                session.headers["Authorization"] = f"Bearer {result.bearer_token}"
            return DisposableAccount(
                email=result.account_email,
                password=result.account_password,
                session=session,
            )
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("disposable account provisioning errored on %s: %s", root_url, exc)
        return None


async def account_login_succeeds(root_url: str, email: str, password: str) -> bool:
    """True when ``email``/``password`` authenticate against ``root_url``.

    Used as a zero-FP confirmation oracle: after a password-change probe, a
    successful login with the NEW password proves the change actually took effect.
    """
    settings = get_settings()
    try:
        async with create_scan_client(
            timeout=settings.request_timeout_seconds,
            follow_redirects=True,
            headers={"User-Agent": "SentryStrikeScanner/1.0"},
        ) as client:
            result = await SmartAuthenticator(settings).authenticate(client, root_url, email, password)
            return bool(result and result.authenticated)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("disposable account login check errored on %s: %s", root_url, exc)
        return False