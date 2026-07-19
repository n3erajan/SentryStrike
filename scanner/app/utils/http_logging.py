"""Structured HTTP request logging for vulnerability scanning."""

from __future__ import annotations

import logging
from contextvars import ContextVar
from dataclasses import dataclass, replace
from typing import Optional
from urllib.parse import parse_qs, urlparse

from app.utils.scan_metrics import record_detector_request

http_logger = logging.getLogger("sentry.http")


@dataclass(frozen=True)
class ScanRequestContext:
    """Carries the scan-state context for structured HTTP log lines.

    ``module`` identifies the detector (e.g. ``"sqli"``, ``"xss"``),
    ``parameter`` names the injection point, and ``test_phase`` labels
    the verification stage (e.g. ``"recon"``, ``"probe"``, ``"verify"``).
    """

    module: str = ""
    parameter: str = ""
    test_phase: str = ""
    payload: str = ""


_default_context = ScanRequestContext()
_scan_context: ContextVar[ScanRequestContext] = ContextVar(
    "scan_request_context",
    default=_default_context,
)


def get_scan_context() -> ScanRequestContext:
    return _scan_context.get()


def set_scan_context(**kwargs: str) -> None:
    current = _scan_context.get()
    updates = {key: value for key, value in kwargs.items() if value}
    if updates:
        _scan_context.set(replace(current, **updates))


def reset_scan_context() -> None:
    _scan_context.set(_default_context)


class scan_context:
    """Temporarily override scan context for a block of requests."""

    def __init__(self, **kwargs: str) -> None:
        self._kwargs = kwargs
        self._previous = _default_context

    def __enter__(self) -> ScanRequestContext:
        self._previous = _scan_context.get()
        _scan_context.set(replace(self._previous, **self._kwargs))
        return _scan_context.get()

    def __exit__(self, exc_type, exc, tb) -> None:
        _scan_context.set(self._previous)


def truncate(value: str, max_len: int = 120) -> str:
    if len(value) <= max_len:
        return value
    return value[:max_len] + "..."


def resolve_request_context(
    *,
    instance_context: Optional[ScanRequestContext] = None,
    module: str = "",
    parameter: str = "",
    test_phase: str = "",
    payload: str = "",
) -> ScanRequestContext:
    ctx_var = get_scan_context()
    instance = instance_context or ScanRequestContext()

    return ScanRequestContext(
        module=module or instance.module or ctx_var.module,
        parameter=parameter or instance.parameter or ctx_var.parameter,
        test_phase=test_phase or instance.test_phase or ctx_var.test_phase,
        payload=payload or instance.payload or ctx_var.payload,
    )


def infer_payload_from_request(
    parameter: str,
    url: str,
    params: Optional[dict],
    data: Optional[dict],
) -> str:
    if not parameter:
        return ""

    if params and parameter in params:
        return str(params[parameter])

    if data and parameter in data:
        return str(data[parameter])

    parsed = urlparse(url)
    if parsed.query:
        query_values = parse_qs(parsed.query, keep_blank_values=True)
        if parameter in query_values:
            values = query_values[parameter]
            if values:
                return str(values[0])

    return ""


def log_http_response(
    method: str,
    url: str,
    status_code: int,
    *,
    module: str = "",
    parameter: str = "",
    test_phase: str = "",
    payload: str = "",
    response_time_ms: float = 0,
) -> None:
    record_detector_request(module)
    parts = [f"HTTP {method} {url}", f"status={status_code}"]

    if response_time_ms > 0:
        parts.append(f"time={response_time_ms:.0f}ms")
    if module:
        parts.append(f"module={module}")
    if parameter:
        parts.append(f"parameter={parameter}")
    if test_phase:
        parts.append(f"phase={test_phase}")
    if payload:
        parts.append(f"payload={truncate(payload)}")

    http_logger.info(" | ".join(parts))


def make_httpx_response_logger(module: str, test_phase: str = "request"):
    """Event hook for raw httpx.AsyncClient instances (crawler, integrations)."""

    async def _log_response(response) -> None:
        request = response.request
        log_http_response(
            request.method,
            str(request.url),
            response.status_code,
            module=module,
            test_phase=test_phase,
        )

    return _log_response
