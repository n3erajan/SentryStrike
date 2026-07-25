"""Focused finding re-verification via detector/verifier strategies."""

from __future__ import annotations

from copy import deepcopy
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from app.core.crawler.account_session import resolve_account_session
from app.reverification_strategies import (
    ResolvedSessions,
    bootstrap_registry,
    get_strategy,
)
from shared.models.reverification import (
    ReverificationEvidence,
    ReverificationOutcome,
)
from shared.models.scan import ScanAuthAccount, ScanAuthRole
from shared.models.vulnerability import VerificationTarget
from shared.reverification.policy import resolve_family


def _root_url(url: str) -> str:
    parsed = urlsplit(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _with_query_parameter(url: str, name: str, value: str) -> str:
    parsed = urlsplit(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query[name] = value
    return urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, urlencode(query), parsed.fragment)
    )


def _build_request(target: VerificationTarget, payload: str | None) -> tuple[str, dict]:
    """Build an HTTP request from a VerificationTarget (used by unit tests / helpers)."""
    template = deepcopy(target.request_template)
    url = target.url
    kwargs: dict = {}
    headers = template.get("headers")
    if isinstance(headers, dict):
        kwargs["headers"] = headers

    if template.get("replay_exact") is True:
        if "json_body" in template:
            kwargs["json"] = template["json_body"]
        elif "form_body" in template:
            kwargs["data"] = template["form_body"]
        return url, kwargs

    parameter = target.parameter
    location = (target.parameter_location or "").lower()
    if payload is not None and parameter:
        if location in {"json", "json_body", "body_json"}:
            body = template.get("json_body") or template.get("json") or {}
            kwargs["json"] = dict(body) if isinstance(body, dict) else {}
            kwargs["json"][parameter] = payload
        elif location in {"form", "form_body", "body", "data"}:
            body = template.get("form_body") or template.get("data") or {}
            kwargs["data"] = dict(body) if isinstance(body, dict) else {}
            kwargs["data"][parameter] = payload
        elif location in {"path", "path_segment"}:
            marker = "{" + parameter + "}"
            if marker in url:
                url = url.replace(marker, payload)
        else:
            url = _with_query_parameter(url, parameter, payload)
    else:
        if isinstance(template.get("json_body"), dict):
            kwargs["json"] = template["json_body"]
        elif isinstance(template.get("form_body"), dict):
            kwargs["data"] = template["form_body"]
    return url, kwargs


async def _resolve_sessions(
    target: VerificationTarget,
    auth_accounts: list[ScanAuthAccount],
) -> ResolvedSessions:
    root = _root_url(target.url)
    by_role = {account.role: account for account in auth_accounts}

    async def _one(role: ScanAuthRole) -> tuple[dict[str, str], dict[str, str], bool]:
        account = by_role.get(role)
        if account is None:
            return {}, {}, False
        session = await resolve_account_session(root, account)
        if session is None or not session.usable:
            return {}, {}, False
        return dict(session.cookies), dict(session.headers), True

    main_cookies, main_headers, main_usable = await _one(ScanAuthRole.main)
    second_cookies, second_headers, second_usable = await _one(ScanAuthRole.second)
    admin_cookies, admin_headers, admin_usable = await _one(ScanAuthRole.admin)
    return ResolvedSessions(
        main_cookies=main_cookies,
        main_headers=main_headers,
        second_cookies=second_cookies,
        second_headers=second_headers,
        admin_cookies=admin_cookies,
        admin_headers=admin_headers,
        main_usable=main_usable,
        second_usable=second_usable,
        admin_usable=admin_usable,
    )


async def run_focused_reverification(
    target: VerificationTarget,
    auth_accounts: list[ScanAuthAccount],
    *,
    vuln_type: str | None = None,
    category=None,
) -> tuple[ReverificationOutcome, list[ReverificationEvidence]]:
    """Re-verify a finding by reusing the original detector/verifier logic."""
    bootstrap_registry()
    family = resolve_family(
        detector_id=target.detector_id,
        vuln_type=vuln_type,
        category=category,
        proof_type=target.proof_type,
    )
    sessions = await _resolve_sessions(target, auth_accounts)
    strategy = get_strategy(family)
    if strategy is None:
        return (
            ReverificationOutcome.inconclusive,
            [
                ReverificationEvidence(
                    request_url=target.url,
                    request_method=target.method,
                    reason=(
                        f"No detector-backed re-verification strategy is registered "
                        f"for family '{family.value}'."
                    ),
                )
            ],
        )
    return await strategy.run(
        target,
        sessions=sessions,
        auth_accounts=auth_accounts,
        vuln_type=vuln_type or target.vuln_type,
    )
