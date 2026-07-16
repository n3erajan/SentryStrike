from datetime import datetime, timezone

import pytest

from app.core.detectors.base_detector import Finding
from app.core.verification.response_analyzer import ResponseAnalyzer
from app.core.verification.verification_framework import TestPollutionFilter
from shared.models.vulnerability import OwaspCategory, SeverityLevel


def test_verify_reflection_rejects_pre_existing_canary() -> None:
    canary = "sentryprobe_abc12345"
    baseline = f"<html>Welcome <!--{canary}--></html>"
    response = baseline

    confirmed, evidence = ResponseAnalyzer.verify_reflection(
        payload=f"<script><!--{canary}--></script>",
        response_body=response,
        baseline_body=baseline,
        canary=canary,
    )

    assert not confirmed
    assert evidence["pre_existing_in_baseline"] is True


def test_verify_reflection_accepts_new_canary() -> None:
    canary = "sentryprobe_deadbeef"
    baseline = "<html>Welcome guest</html>"
    response = f"<html>Hello <!--{canary}--></html>"

    confirmed, evidence = ResponseAnalyzer.verify_reflection(
        payload=f"<script>alert('{canary}')</script>",
        response_body=response,
        baseline_body=baseline,
        canary=canary,
    )

    assert confirmed
    assert evidence["canary_verified"] is True


def test_verify_reflection_requires_unencoded_xss_marker() -> None:
    payload = "<script>alert(1)</script>"
    response = "&lt;script&gt;alert(1)&lt;/script&gt;"

    confirmed, evidence = ResponseAnalyzer.verify_reflection(
        payload=payload,
        response_body=response,
        baseline_body="<html></html>",
    )

    assert not confirmed
    assert evidence["reason"] == "no_verified_reflection"


def test_pollution_filter_downgrades_reflected_without_canary() -> None:
    url = "https://example.com/page"
    stored = Finding(
        category=OwaspCategory.a05,
        vuln_type="Stored XSS",
        severity=SeverityLevel.high,
        url=url,
        parameter="comment",
        verified=True,
        confidence_score=90.0,
    )
    reflected = Finding(
        category=OwaspCategory.a05,
        vuln_type="Reflected XSS",
        severity=SeverityLevel.critical,
        url=url,
        parameter="name",
        verified=True,
        confidence_score=95.0,
        detection_evidence={"canary_verified": False},
        evidence="Payload reflected in response.",
    )

    results = TestPollutionFilter.filter_cross_module_contamination([stored, reflected])

    assert len(results) == 2
    downgraded = next(f for f in results if f.vuln_type == "Reflected XSS")
    assert downgraded.detection_evidence["suspected_test_pollution"] is True
    assert downgraded.verified is False
    assert downgraded.confidence_score <= 20.0


def test_pollution_filter_keeps_reflected_with_verified_canary() -> None:
    url = "https://example.com/page"
    stored = Finding(
        category=OwaspCategory.a05,
        vuln_type="Stored XSS",
        severity=SeverityLevel.high,
        url=url,
        parameter="comment",
        verified=True,
        confidence_score=90.0,
    )
    reflected = Finding(
        category=OwaspCategory.a05,
        vuln_type="Reflected XSS",
        severity=SeverityLevel.critical,
        url=url,
        parameter="name",
        verified=True,
        confidence_score=95.0,
        detection_evidence={
            "verification_canary": "sentryprobe_1234abcd",
            "canary_verified": True,
        },
        evidence="Canary verified in response.",
    )

    results = TestPollutionFilter.filter_cross_module_contamination([stored, reflected])

    kept = next(f for f in results if f.vuln_type == "Reflected XSS")
    assert kept.verified is True
    assert kept.confidence_score == 95.0
    assert "suspected_test_pollution" not in (kept.detection_evidence or {})


def test_generate_probe_canary_is_unique() -> None:
    a = ResponseAnalyzer.generate_probe_canary()
    b = ResponseAnalyzer.generate_probe_canary()
    assert a.startswith("sentryprobe_")
    assert a != b
