"""Focused HTTP replay for finding re-verification jobs."""

from __future__ import annotations

from copy import deepcopy
from difflib import SequenceMatcher
from time import perf_counter
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from app.config import get_settings
from app.core.crawler.account_session import resolve_account_session
from app.utils.scan_http import create_scan_client
from shared.models.reverification import (
    ReverificationEvidence,
    ReverificationOutcome,
)
from shared.models.scan import ScanAuthAccount, ScanAuthRole
from shared.models.vulnerability import AuthContext, VerificationTarget


def _root_url(url: str) -> str:
    parsed = urlsplit(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _with_query_parameter(url: str, name: str, value: str) -> str:
    parsed = urlsplit(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query[name] = value
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), parsed.fragment))


def _build_request(target: VerificationTarget, payload: str | None) -> tuple[str, dict]:
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


def _proof_matches(
    target: VerificationTarget,
    *,
    payload: str | None,
    status_code: int,
    response_text: str,
    response_headers: dict,
    elapsed_ms: float,
    control_elapsed_ms: float | None,
) -> tuple[bool, str]:
    proof_type = (target.proof_type or "").lower()
    detector_id = target.detector_id.lower()
    lower = response_text.lower()
    expected = (target.expected_response_snippet or "").strip()

    if "security_header" in detector_id or "header" in proof_type:
        for header in (
            "content-security-policy",
            "strict-transport-security",
            "x-frame-options",
            "x-content-type-options",
        ):
            if header in expected.lower() and header not in response_headers:
                return True, f"Expected missing response header remains absent: {header}."

    if any(word in proof_type for word in ("time", "timing")) and control_elapsed_ms is not None:
        threshold = float(target.request_template.get("timing_threshold_ms", 1500))
        if elapsed_ms - control_elapsed_ms >= threshold:
            return True, "Payload response retained the detector's timing differential."

    error_markers = (
        "sql syntax",
        "sqlstate",
        "stack trace",
        "traceback (most recent call last)",
        "root:x:0:0",
        "uid=",
    )
    expected_markers = [marker for marker in error_markers if marker in expected.lower()]
    if expected_markers and any(marker in lower for marker in expected_markers):
        return True, "The original response proof marker was observed again."

    if payload and payload in response_text and any(
        word in proof_type for word in ("reflection", "xss", "echo")
    ):
        return True, "The verification payload was reflected again."

    if expected and len(response_text) > 0:
        expected_norm = " ".join(expected.lower().split())[:500]
        actual_norm = " ".join(response_text.lower().split())[:2000]
        if len(expected_norm) >= 40 and SequenceMatcher(
            None, expected_norm, actual_norm
        ).ratio() >= 0.72:
            return True, "The response remains materially similar to the original proof."

    access_control = any(
        word in detector_id or word in proof_type
        for word in ("idor", "authorization", "access_control", "forced_browsing")
    )
    if access_control and 200 <= status_code < 400:
        return True, "The focused access-control request is still accepted."

    if target.expected_status_code and target.expected_status_code >= 500 and status_code >= 500:
        return True, "The original server-error behavior was reproduced."
    return False, "The original proof condition was not observed."


async def run_focused_reverification(
    target: VerificationTarget,
    auth_accounts: list[ScanAuthAccount],
) -> tuple[ReverificationOutcome, list[ReverificationEvidence]]:
    """Replay only the finding's captured request and return immutable evidence."""
    account = next(
        (item for item in auth_accounts if item.role == ScanAuthRole.main),
        auth_accounts[0] if auth_accounts else None,
    )
    session = await resolve_account_session(_root_url(target.url), account) if account else None
    requires_auth = target.auth_context in {
        AuthContext.authenticated,
        AuthContext.requires_user_session,
    }
    if requires_auth and (session is None or not session.usable):
        return (
            ReverificationOutcome.inconclusive,
            [
                ReverificationEvidence(
                    request_url=target.url,
                    request_method=target.method,
                    reason="The finding requires authentication, but no usable session was resolved.",
                )
            ],
        )

    headers = dict(session.headers) if session else {}
    cookies = dict(session.cookies) if session else {}
    evidence: list[ReverificationEvidence] = []
    control_elapsed: float | None = None
    attack_result: tuple[int, str, dict, float, str] | None = None
    payloads = []
    if target.control_payload is not None:
        payloads.append(("control", target.control_payload))
    payloads.append(("verification", target.payload))

    try:
        async with create_scan_client(
            timeout=get_settings().request_timeout_seconds,
            follow_redirects=True,
            headers={"User-Agent": "SentryStrikeScanner/1.0", **headers},
            cookies=cookies,
        ) as client:
            for label, payload in payloads:
                url, kwargs = _build_request(target, payload)
                started = perf_counter()
                response = await client.request(target.method.upper(), url, **kwargs)
                elapsed_ms = (perf_counter() - started) * 1000
                snippet = response.text[:2000]
                evidence.append(
                    ReverificationEvidence(
                        request_url=str(response.request.url),
                        request_method=target.method.upper(),
                        status_code=response.status_code,
                        elapsed_ms=round(elapsed_ms, 2),
                        response_snippet=snippet,
                        reason=f"Focused {label} request completed.",
                    )
                )
                if label == "control":
                    control_elapsed = elapsed_ms
                else:
                    attack_result = (
                        response.status_code,
                        response.text,
                        {key.lower(): value for key, value in response.headers.items()},
                        elapsed_ms,
                        url,
                    )
    except Exception as exc:
        evidence.append(
            ReverificationEvidence(
                request_url=target.url,
                request_method=target.method,
                reason=f"Focused request failed: {type(exc).__name__}: {exc}",
            )
        )
        return ReverificationOutcome.inconclusive, evidence

    if attack_result is None:
        return ReverificationOutcome.inconclusive, evidence
    status_code, text, response_headers, elapsed_ms, _ = attack_result
    matched, reason = _proof_matches(
        target,
        payload=target.payload,
        status_code=status_code,
        response_text=text,
        response_headers=response_headers,
        elapsed_ms=elapsed_ms,
        control_elapsed_ms=control_elapsed,
    )
    evidence[-1].proof_matched = matched
    evidence[-1].reason = reason
    return (
        ReverificationOutcome.reproduced if matched else ReverificationOutcome.not_reproduced,
        evidence,
    )
