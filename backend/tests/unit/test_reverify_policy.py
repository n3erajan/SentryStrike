"""Unit tests for shared re-verification policy."""

from shared.models.scan import ScanAuthRole
from shared.models.vulnerability import (
    AuthContext,
    LocationInfo,
    OwaspCategory,
    SeverityLevel,
    VerificationTarget,
    Vulnerability,
)
from shared.reverification.policy import (
    CannotReverify,
    ReverifyClass,
    ReverifyFamily,
    assert_reverify_allowed,
    classify_finding,
    resolve_family,
)


def _vuln(**kwargs) -> Vulnerability:
    target_kwargs = kwargs.pop("target_kwargs", {})
    detector_id = kwargs.pop("detector_id", "security_headers")
    vuln_type = kwargs.pop("vuln_type", "Missing Security Header")
    category = kwargs.pop("category", OwaspCategory.a02)
    target = VerificationTarget(
        detector_id=detector_id,
        url="https://target.example/",
        vuln_type=vuln_type,
        **target_kwargs,
    )
    return Vulnerability(
        id="v1",
        category=category,
        vuln_type=vuln_type,
        severity=SeverityLevel.medium,
        location=LocationInfo(url="https://target.example/"),
        verification_target=target,
        **kwargs,
    )


def test_resolve_family_prefers_detector_id() -> None:
    assert resolve_family(detector_id="injection_sql_command") == ReverifyFamily.sql_injection
    assert resolve_family(detector_id="supply_chain") == ReverifyFamily.supply_chain
    assert resolve_family(vuln_type="Reflected XSS") == ReverifyFamily.xss


def test_supply_chain_requires_full_scan() -> None:
    family, classification = classify_finding(
        _vuln(
            detector_id="supply_chain",
            vuln_type="Vulnerable Component: jquery",
            category=OwaspCategory.a03,
        )
    )
    assert family == ReverifyFamily.supply_chain
    assert classification == ReverifyClass.requires_full_scan


def test_assert_rejects_supply_chain() -> None:
    try:
        assert_reverify_allowed(
            _vuln(
                detector_id="supply_chain",
                vuln_type="Vulnerable Component: jquery",
                category=OwaspCategory.a03,
            )
        )
        assert False, "expected CannotReverify"
    except CannotReverify as exc:
        assert exc.classification == ReverifyClass.requires_full_scan
        assert "full rescan" in exc.reason.lower() or "fingerprint" in exc.reason.lower()


def test_access_control_requires_secondary_identity() -> None:
    vuln = _vuln(
        detector_id="access_control",
        vuln_type="IDOR",
        category=OwaspCategory.a01,
        target_kwargs={"auth_context": AuthContext.authenticated},
    )
    family, classification = classify_finding(vuln)
    assert family == ReverifyFamily.access_control
    assert classification == ReverifyClass.requires_secondary_identity

    try:
        assert_reverify_allowed(vuln, auth_roles=[ScanAuthRole.main])
        assert False, "expected CannotReverify"
    except CannotReverify as exc:
        assert exc.classification == ReverifyClass.requires_secondary_identity

    assert (
        assert_reverify_allowed(vuln, auth_roles=[ScanAuthRole.main, ScanAuthRole.second])
        == ReverifyFamily.access_control
    )


def test_auth_brute_force_requires_full_scan() -> None:
    family, classification = classify_finding(
        _vuln(
            detector_id="authentication_failures",
            vuln_type="Weak Brute Force Protection",
            category=OwaspCategory.a07,
        )
    )
    assert classification == ReverifyClass.requires_full_scan


def test_security_headers_is_reverifiable() -> None:
    family, classification = classify_finding(_vuln())
    assert family == ReverifyFamily.security_headers
    assert classification == ReverifyClass.reverifiable
    assert assert_reverify_allowed(_vuln()) == ReverifyFamily.security_headers


def test_injection_body_without_template_is_insufficient() -> None:
    vuln = _vuln(
        detector_id="injection_sql_command",
        vuln_type="SQL Injection",
        category=OwaspCategory.a05,
        target_kwargs={
            "parameter": "id",
            "parameter_location": "json_body",
            "request_template": {},
        },
    )
    _, classification = classify_finding(vuln)
    assert classification == ReverifyClass.insufficient_replay_metadata


def test_injection_query_param_is_reverifiable() -> None:
    vuln = _vuln(
        detector_id="injection_sql_command",
        vuln_type="SQL Injection",
        category=OwaspCategory.a05,
        target_kwargs={
            "parameter": "id",
            "parameter_location": "query",
        },
    )
    _, classification = classify_finding(vuln)
    assert classification == ReverifyClass.reverifiable
