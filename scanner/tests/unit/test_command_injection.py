"""Command-injection candidate selection (value-aware).

Locks in the fix for the audit's "command_injection sent 0 of 378 built
candidates": selection is now name-OR-value-OR-context, with a replayable
blind-timing fallback so JSON-body params with generic names (``city``,
``message``) are no longer silently dropped. Generic — no target-specific names.
"""

from __future__ import annotations

from types import SimpleNamespace

from app.core.crawler.models import ParameterLocation, RequestObservation
from app.core.detectors.attack_surface import AttackTarget
from app.core.detectors.command_injection import CommandInjectionDetector


def _target(name, value, *, url="http://t.example/api/x", replayable=True, location=ParameterLocation.json_body):
    return AttackTarget(url=url, parameter=name, value=value, location=location, replayable=replayable)


det = CommandInjectionDetector()


# --------------------------------------------------------------------------- #
# Selection truth table
# --------------------------------------------------------------------------- #

def test_selects_opaque_replayable_body_param():
    # Generic name, opaque value, no positive signal -> selected via the
    # replayable blind-timing fallback (the exact 'city' gap from the audit).
    assert det._is_command_candidate(_target("city", "Berlin")) is True
    assert det._is_command_candidate(_target("message", "hello world")) is True


def test_selects_positive_signal():
    # Command-token name / shell-or-host value / diagnostic endpoint context.
    assert det._is_command_candidate(_target("cmd", "x")) is True
    assert det._is_command_candidate(_target("q", "8.8.8.8")) is True
    assert det._is_command_candidate(_target("q", "1; ls")) is True
    assert det._is_command_candidate(_target("target", "opaque", url="http://t/api/ping")) is True


def test_rejects_non_replayable_without_signal():
    # A static-synth (non-replayable) target with no positive signal is not fired.
    assert det._is_command_candidate(_target("city", "Berlin", replayable=False)) is False


def test_rejects_trivial_values():
    # Bare id / boolean values make poor blind-timing probes -> not selected.
    assert det._is_command_candidate(_target("id", "42")) is False
    assert det._is_command_candidate(_target("active", "true")) is False


# --------------------------------------------------------------------------- #
# detect(): selected candidates actually reach verification (requests_sent > 0)
# --------------------------------------------------------------------------- #

class _StubVerifier:
    """Records verify() calls; reports not-vulnerable so no findings are emitted."""

    calls: list[tuple] = []

    def __init__(self, *a, **k):
        self.http_verifier = SimpleNamespace(configure_auth=self._noop)
        self.blind_timing_threshold = 0.0

    async def _noop(self, *a, **k):
        return None

    async def verify(self, url, parameter, method, value, **kwargs):
        type(self).calls.append((url, parameter))
        return SimpleNamespace(is_vulnerable=False, findings=[])

    async def close(self):
        return None


async def test_detect_sends_requests_for_replayable_candidates(monkeypatch):
    _StubVerifier.calls = []
    monkeypatch.setattr(
        "app.core.detectors.command_injection.CommandInjectionVerifier", _StubVerifier
    )

    # An observed JSON body whose only field is a generic, opaque param.
    request = RequestObservation(
        url="http://t.example/api/address",
        method="POST",
        request_headers={"content-type": "application/json"},
        request_content_type="application/json",
        post_data='{"city":"Berlin"}',
        body_kind="json",
        body_schema=["city"],
        replayable=True,
    )

    findings = await det.detect([], [], requests=[request])

    # No finding (stub is not-vulnerable) but the candidate WAS sent to verify.
    assert findings == []
    assert any(param == "city" for _, param in _StubVerifier.calls)
