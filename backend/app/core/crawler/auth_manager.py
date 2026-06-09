from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

import httpx
from bs4 import BeautifulSoup

from app.core.crawler.api_extractor import ApiExtractor
from app.core.crawler.models import ApiEndpoint
from app.core.crawler.url_parser import normalize_url

logger = logging.getLogger(__name__)


@dataclass
class AuthFlowCandidate:
    url: str
    method: str = "POST"
    fields: dict[str, str] = field(default_factory=dict)
    flow_type: str = "form"
    evidence: str = ""


@dataclass
class AuthState:
    cookies: dict[str, str] = field(default_factory=dict)
    bearer_tokens: list[str] = field(default_factory=list)
    csrf_tokens: dict[str, str] = field(default_factory=dict)
    flow: AuthFlowCandidate | None = None


class ModernAuthManager:
    """Authentication discovery helpers for traditional and SPA applications."""

    LOGIN_HINTS = ("login", "signin", "sign-in", "auth", "session", "oauth", "token")
    TOKEN_RE = re.compile(r"""(?P<name>csrf|xsrf|token|jwt|access_token|id_token)["'\s:=]+(?P<value>[A-Za-z0-9._\-+/=]{12,})""", re.I)

    @classmethod
    def discover_flows(cls, page_url: str, html: str, api_endpoints: list[ApiEndpoint] | None = None) -> list[AuthFlowCandidate]:
        flows: list[AuthFlowCandidate] = []
        soup = BeautifulSoup(html, "html.parser")

        for form in soup.find_all("form"):
            text = " ".join([form.get("id", ""), form.get("class", [""])[0] if form.get("class") else "", form.get_text(" ", strip=True)]).lower()
            has_password = bool(form.find("input", attrs={"type": re.compile("^password$", re.I)}))
            if not has_password and not any(hint in text for hint in cls.LOGIN_HINTS):
                continue

            action = normalize_url(page_url, form.get("action", page_url))
            fields: dict[str, str] = {}
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    fields[name] = inp.get("value", "")
            flows.append(
                AuthFlowCandidate(
                    url=action,
                    method=form.get("method", "POST").upper(),
                    fields=fields,
                    flow_type="form",
                    evidence="password/login form",
                )
            )

        for endpoint in api_endpoints or []:
            lowered = endpoint.url.lower()
            if any(hint in lowered for hint in cls.LOGIN_HINTS):
                flows.append(
                    AuthFlowCandidate(
                        url=endpoint.url,
                        method=endpoint.method,
                        flow_type="api",
                        evidence=endpoint.evidence or "auth-like API endpoint",
                    )
                )
        return flows

    @classmethod
    def extract_tokens(cls, html_or_script: str) -> dict[str, str]:
        tokens: dict[str, str] = {}
        for match in cls.TOKEN_RE.finditer(html_or_script):
            tokens[match.group("name").lower()] = match.group("value")
        return tokens

    @staticmethod
    def snapshot_cookies(cookies: httpx.Cookies) -> dict[str, str]:
        return {cookie.name: cookie.value for cookie in cookies.jar}

    @classmethod
    def auth_endpoints_from_javascript(cls, base_url: str, script_text: str) -> list[ApiEndpoint]:
        _, endpoints = ApiExtractor.extract_from_javascript(base_url, script_text)
        return [endpoint for endpoint in endpoints if any(hint in endpoint.url.lower() for hint in cls.LOGIN_HINTS)]
