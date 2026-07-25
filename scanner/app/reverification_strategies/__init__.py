"""Focused re-verification strategies that reuse detector/verifier logic."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Awaitable, Callable, Protocol

from shared.models.reverification import ReverificationEvidence, ReverificationOutcome
from shared.models.scan import ScanAuthAccount
from shared.models.vulnerability import VerificationTarget
from shared.reverification.policy import ReverifyFamily


@dataclass
class ResolvedSessions:
    """Auth sessions resolved for a re-verification job."""

    main_cookies: dict[str, str]
    main_headers: dict[str, str]
    second_cookies: dict[str, str]
    second_headers: dict[str, str]
    admin_cookies: dict[str, str]
    admin_headers: dict[str, str]
    main_usable: bool = False
    second_usable: bool = False
    admin_usable: bool = False


class ReverifyStrategy(Protocol):
    family: ReverifyFamily

    async def run(
        self,
        target: VerificationTarget,
        *,
        sessions: ResolvedSessions,
        auth_accounts: list[ScanAuthAccount],
        vuln_type: str | None = None,
    ) -> tuple[ReverificationOutcome, list[ReverificationEvidence]]:
        ...


StrategyFactory = Callable[[], ReverifyStrategy]

_REGISTRY: dict[ReverifyFamily, StrategyFactory] = {}


def register_strategy(family: ReverifyFamily, factory: StrategyFactory) -> None:
    _REGISTRY[family] = factory


def get_strategy(family: ReverifyFamily) -> ReverifyStrategy | None:
    factory = _REGISTRY.get(family)
    return factory() if factory is not None else None


def registered_families() -> frozenset[ReverifyFamily]:
    return frozenset(_REGISTRY)


def _ensure_builtin_strategies() -> None:
    """Import strategy modules so they self-register (idempotent)."""
    # Imported for side effects.
    from app.reverification_strategies import (  # noqa: F401
        access_control,
        authentication,
        injection,
        passive,
    )


def bootstrap_registry() -> None:
    _ensure_builtin_strategies()
