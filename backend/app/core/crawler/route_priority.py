"""Generic, application-agnostic route surface scoring (Task B).

The browser crawl has a finite time budget. Visiting routes in raw discovery
order spends that budget on low-value pages while high-value ones (auth, forms,
search, API-bearing routes) are never reached before truncation. This module
provides a pure, unit-testable :func:`score_route_surface` that ranks a route by
**generic** structural signals only — token *families* and shape, never a full
path, app name, parameter, or credential. The crawl uses the score to drive a
priority queue so the highest-surface routes are visited first.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

# Generic path-token families that imply state change / data / auth surface.
# These are matched as whole tokens against path segments, never as full paths,
# so they generalise across React/Angular/Vue/Next/Svelte/Nuxt apps. No
# application-specific literal appears here.
_HIGH_VALUE_TOKENS = (
    "login",
    "signin",
    "sign-in",
    "register",
    "signup",
    "sign-up",
    "account",
    "profile",
    "user",
    "users",
    "admin",
    "search",
    "api",
    "rest",
    "graphql",
    "upload",
    "order",
    "orders",
    "cart",
    "basket",
    "checkout",
    "payment",
    "auth",
    "token",
    "session",
    "settings",
    "password",
)

# Slightly lower-value but still data-bearing token families.
_MEDIUM_VALUE_TOKENS = (
    "list",
    "detail",
    "edit",
    "create",
    "new",
    "form",
    "message",
    "comment",
    "review",
    "feedback",
    "contact",
    "product",
    "item",
)

_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")


def _path_tokens(path: str) -> list[str]:
    """Split a URL path into lowercased alphanumeric tokens.

    ``/rest/user/login`` → ``["rest", "user", "login"]``. Fragment-router paths
    like ``/#/search`` collapse cleanly since the split drops separators.
    """
    return [tok for tok in _TOKEN_SPLIT_RE.split(path.lower()) if tok]


def score_route_surface(url: str, evidence: str = "") -> int:
    """Rank a route by generic vulnerability-surface signals (higher = sooner).

    Signals (all generic — token families and structure, no full-path matching):

    * a query string present (carries injectable parameters),
    * path tokens from a high/medium value family (auth, forms, api, …),
    * the route was mined from JS/XHR API inventory rather than a static link,
    * shallower depth is preferred (top-level surface first) as a tie-breaker.

    ``evidence`` is the free-text provenance string carried on route candidates
    (e.g. ``"javascript"``, ``"browser_navigation"``); an API/JS origin is a
    generic signal that the route bears real request surface.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return 0

    score = 0
    path = parsed.path or "/"
    # Account for hash-router routes: SPAs frequently encode the real route in
    # the fragment (``/#/search``), so fold the fragment into the token stream.
    fragment = parsed.fragment or ""

    tokens = set(_path_tokens(path)) | set(_path_tokens(fragment))

    # Query string: strong generic signal of injectable parameter surface.
    if parsed.query:
        score += 30
    # A parameterised fragment (hash-router query) counts too.
    if "?" in fragment or "=" in fragment:
        score += 20

    high_hits = tokens & set(_HIGH_VALUE_TOKENS)
    med_hits = tokens & set(_MEDIUM_VALUE_TOKENS)
    score += 25 * len(high_hits)
    score += 10 * len(med_hits)

    # Provenance: JS/XHR-mined routes are far more likely to bear real API
    # surface than a plain <a href> link.
    ev = (evidence or "").lower()
    if any(tok in ev for tok in ("javascript", "api", "xhr", "fetch", "rest", "graphql")):
        score += 15

    # Depth tie-breaker: shallower routes first. Each extra segment costs a
    # little, but never enough to outrank a real high-value token match.
    depth = len([seg for seg in path.split("/") if seg])
    score -= min(depth, 8)

    return score
