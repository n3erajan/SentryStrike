"""Classify findings for focused re-verification eligibility.

The backend uses this to reject full-scan-only (or identity-gated) findings
before enqueueing. The scanner uses the same family labels to pick a strategy.
"""

from __future__ import annotations

from enum import Enum

from shared.models.scan import ScanAuthRole
from shared.models.vulnerability import OwaspCategory, VerificationTarget, Vulnerability


class ReverifyClass(str, Enum):
    reverifiable = "reverifiable"
    requires_full_scan = "requires_full_scan"
    requires_secondary_identity = "requires_secondary_identity"
    insufficient_replay_metadata = "insufficient_replay_metadata"


class ReverifyFamily(str, Enum):
    security_headers = "security_headers"
    crypto_failures = "crypto_failures"
    supply_chain = "supply_chain"
    sensitive_paths = "sensitive_paths"
    exception_handling = "exception_handling"
    csrf = "csrf"
    open_redirect = "open_redirect"
    sql_injection = "sql_injection"
    nosql_injection = "nosql_injection"
    command_injection = "command_injection"
    file_inclusion = "file_inclusion"
    xss = "xss"
    ssrf = "ssrf"
    file_upload = "file_upload"
    access_control = "access_control"
    authentication = "authentication"
    unknown = "unknown"


class CannotReverify(Exception):
    """Finding cannot be re-verified in isolation."""

    def __init__(self, classification: ReverifyClass, reason: str) -> None:
        self.classification = classification
        self.reason = reason
        super().__init__(reason)


# Detector-name / detector_id tokens → family. Prefer exact detector `.name`
# values; also accept common aliases that appear in stored detector_id fields.
_DETECTOR_ID_ALIASES: dict[str, ReverifyFamily] = {
    "security_headers": ReverifyFamily.security_headers,
    "crypto_failures": ReverifyFamily.crypto_failures,
    "supply_chain": ReverifyFamily.supply_chain,
    "sensitive_paths": ReverifyFamily.sensitive_paths,
    "exception_handling": ReverifyFamily.exception_handling,
    "csrf": ReverifyFamily.csrf,
    "open_redirect": ReverifyFamily.open_redirect,
    "injection_sql_command": ReverifyFamily.sql_injection,
    "sql_injection": ReverifyFamily.sql_injection,
    "sqli": ReverifyFamily.sql_injection,
    "nosql_injection": ReverifyFamily.nosql_injection,
    "command_injection": ReverifyFamily.command_injection,
    "file_inclusion": ReverifyFamily.file_inclusion,
    "xss": ReverifyFamily.xss,
    "xss_detector": ReverifyFamily.xss,
    "ssrf": ReverifyFamily.ssrf,
    "file_upload": ReverifyFamily.file_upload,
    "access_control": ReverifyFamily.access_control,
    "idor": ReverifyFamily.access_control,
    "idor_detector": ReverifyFamily.access_control,
    "authentication_failures": ReverifyFamily.authentication,
    "auth": ReverifyFamily.authentication,
}

_VULN_TYPE_HINTS: tuple[tuple[tuple[str, ...], ReverifyFamily], ...] = (
    (("missing security header", "content security policy", "cors misconfiguration", "information disclosure in header"), ReverifyFamily.security_headers),
    (("insecure transport", "mixed content", "session cookie", "cookie without secure", "sensitive data in url"), ReverifyFamily.crypto_failures),
    (("vulnerable component",), ReverifyFamily.supply_chain),
    (("sensitive path", "exposed", ".git", "backup file"), ReverifyFamily.sensitive_paths),
    (("stack trace", "verbose error", "exception", "error disclosure"), ReverifyFamily.exception_handling),
    (("csrf", "cross-site request forgery"), ReverifyFamily.csrf),
    (("open redirect",), ReverifyFamily.open_redirect),
    (("sql injection", "sqli"), ReverifyFamily.sql_injection),
    (("nosql", "mongodb"), ReverifyFamily.nosql_injection),
    (("command injection", "os command", "rce"), ReverifyFamily.command_injection),
    (("file inclusion", "path traversal", "lfi", "rfi", "directory traversal"), ReverifyFamily.file_inclusion),
    (("xss", "cross-site scripting", "dom-based"), ReverifyFamily.xss),
    (("ssrf", "server-side request"), ReverifyFamily.ssrf),
    (("file upload", "unrestricted upload"), ReverifyFamily.file_upload),
    (("idor", "bola", "broken access", "forced browsing", "mass assignment", "authorization"), ReverifyFamily.access_control),
    (("authentication", "session fixation", "jwt", "brute force", "credential", "password over get"), ReverifyFamily.authentication),
)

# Auth sub-kinds that need crawl-wide context and cannot be re-verified alone.
_AUTH_FULL_SCAN_MARKERS: tuple[str, ...] = (
    "brute",
    "credential stuffing",
    "default credential",
    "lockout",
    "api workflow",
    "login recipe",
    "password spraying",
)

# Injection families that need AttackTarget structural metadata for verifier reuse.
_INJECTION_FAMILIES: frozenset[ReverifyFamily] = frozenset(
    {
        ReverifyFamily.sql_injection,
        ReverifyFamily.nosql_injection,
        ReverifyFamily.command_injection,
        ReverifyFamily.file_inclusion,
        ReverifyFamily.xss,
        ReverifyFamily.ssrf,
        ReverifyFamily.file_upload,
    }
)

# Access-control findings that need a second (or admin) identity to re-prove.
_ACCESS_CONTROL_SECONDARY_MARKERS: tuple[str, ...] = (
    "idor",
    "bola",
    "authorization matrix",
    "horizontal",
    "vertical",
    "privilege",
    "mass assignment",
    "mutating authorization",
)

# Feature flags flipped as later phases land. Defaults match Phase 1 (supply-chain
# hard gate only); Phase 5/6 flip the remaining gates on.
ENFORCE_SECONDARY_IDENTITY = True
ENFORCE_AUTH_FULL_SCAN_GATE = True
ENFORCE_INJECTION_METADATA = True


def resolve_family(
    *,
    detector_id: str | None = None,
    vuln_type: str | None = None,
    category: OwaspCategory | str | None = None,
    proof_type: str | None = None,
) -> ReverifyFamily:
    """Map stored finding metadata onto a stable reverify family."""
    detector = (detector_id or "").strip().lower().replace(" ", "_")
    if detector in _DETECTOR_ID_ALIASES:
        return _DETECTOR_ID_ALIASES[detector]
    for alias, family in _DETECTOR_ID_ALIASES.items():
        if alias in detector:
            return family

    haystack = " ".join(
        part for part in ((vuln_type or "").lower(), (proof_type or "").lower()) if part
    )
    for markers, family in _VULN_TYPE_HINTS:
        if any(marker in haystack for marker in markers):
            return family

    category_value = category.value if isinstance(category, OwaspCategory) else str(category or "")
    category_lower = category_value.lower()
    if "a03" in category_lower or "supply chain" in category_lower:
        return ReverifyFamily.supply_chain
    if "a04" in category_lower or "cryptographic" in category_lower:
        return ReverifyFamily.crypto_failures
    if "a01" in category_lower or "access control" in category_lower:
        return ReverifyFamily.access_control
    if "a07" in category_lower or "authentication" in category_lower:
        return ReverifyFamily.authentication
    if "a10" in category_lower or "exception" in category_lower:
        return ReverifyFamily.exception_handling
    if "a05" in category_lower or "injection" in category_lower:
        # Ambiguous injection without a clearer detector/vuln_type hint.
        return ReverifyFamily.unknown
    return ReverifyFamily.unknown


def _auth_requires_full_scan(vuln_type: str | None, proof_type: str | None) -> bool:
    haystack = f"{vuln_type or ''} {proof_type or ''}".lower()
    return any(marker in haystack for marker in _AUTH_FULL_SCAN_MARKERS)


def _access_control_needs_secondary(vuln_type: str | None, proof_type: str | None) -> bool:
    haystack = f"{vuln_type or ''} {proof_type or ''}".lower()
    if not haystack.strip():
        # Conservative: access_control family without a subtype still needs a
        # second identity for differential checks.
        return True
    if "forced browsing" in haystack:
        return False
    return any(marker in haystack for marker in _ACCESS_CONTROL_SECONDARY_MARKERS)


def classify_target(
    target: VerificationTarget,
    *,
    vuln_type: str | None = None,
    category: OwaspCategory | str | None = None,
) -> tuple[ReverifyFamily, ReverifyClass]:
    """Classify a VerificationTarget (+ optional finding fields)."""
    effective_vuln_type = vuln_type or target.vuln_type
    family = resolve_family(
        detector_id=target.detector_id,
        vuln_type=effective_vuln_type,
        category=category,
        proof_type=target.proof_type,
    )

    if family == ReverifyFamily.supply_chain:
        return family, ReverifyClass.requires_full_scan

    if family == ReverifyFamily.unknown:
        return family, ReverifyClass.requires_full_scan

    if ENFORCE_AUTH_FULL_SCAN_GATE and family == ReverifyFamily.authentication:
        if _auth_requires_full_scan(effective_vuln_type, target.proof_type):
            return family, ReverifyClass.requires_full_scan
        # Passive structural auth findings are reverifiable; everything else in
        # this family gates until metadata-backed strategies land.
        haystack = f"{effective_vuln_type or ''} {target.proof_type or ''}".lower()
        self_contained = any(
            marker in haystack
            for marker in (
                "password",
                "get method",
                "token in url",
                "token in query",
                "admin path",
                "session cookie",
                "jwt",
                "csrf",
            )
        )
        if not self_contained:
            return family, ReverifyClass.requires_full_scan

    if (
        ENFORCE_SECONDARY_IDENTITY
        and family == ReverifyFamily.access_control
        and _access_control_needs_secondary(effective_vuln_type, target.proof_type)
    ):
        return family, ReverifyClass.requires_secondary_identity

    if ENFORCE_INJECTION_METADATA and family in _INJECTION_FAMILIES:
        location = (target.parameter_location or "").lower()
        if location in {
            "form",
            "form_body",
            "body",
            "data",
            "json",
            "json_body",
            "body_json",
            "graphql_variable",
        }:
            template = target.request_template or {}
            if not (
                isinstance(template, dict)
                and (
                    template.get("form_inputs") is not None
                    or template.get("json_template") is not None
                    or template.get("json_body") is not None
                    or template.get("form_body") is not None
                    or template.get("replay_exact") is True
                )
            ):
                return family, ReverifyClass.insufficient_replay_metadata

    return family, ReverifyClass.reverifiable


def classify_finding(vulnerability: Vulnerability) -> tuple[ReverifyFamily, ReverifyClass]:
    """Classify a persisted Vulnerability for re-verification."""
    target = vulnerability.verification_target
    if target is None:
        return ReverifyFamily.unknown, ReverifyClass.requires_full_scan
    return classify_target(
        target,
        vuln_type=vulnerability.vuln_type,
        category=vulnerability.category,
    )


def assert_reverify_allowed(
    vulnerability: Vulnerability,
    auth_roles: list[ScanAuthRole] | list[str] | None = None,
) -> ReverifyFamily:
    """Raise CannotReverify when the finding must not be queued.

    Returns the resolved family when the finding may proceed.
    """
    if vulnerability.verification_target is None:
        raise CannotReverify(
            ReverifyClass.requires_full_scan,
            "This finding does not contain a replayable verification target.",
        )

    family, classification = classify_finding(vulnerability)
    roles = {
        (role.value if isinstance(role, ScanAuthRole) else str(role)).lower()
        for role in (auth_roles or [])
    }

    if classification == ReverifyClass.requires_full_scan:
        if family == ReverifyFamily.supply_chain:
            raise CannotReverify(
                classification,
                "Component/CVE findings require a full rescan to re-fingerprint the target.",
            )
        raise CannotReverify(
            classification,
            "This finding depends on crawl-wide context and cannot be re-verified in isolation. "
            "Run a full scan instead.",
        )

    if classification == ReverifyClass.insufficient_replay_metadata:
        raise CannotReverify(
            classification,
            "This finding lacks replay metadata needed for focused re-verification. "
            "Run a new scan to capture it.",
        )

    if classification == ReverifyClass.requires_secondary_identity:
        if "second" not in roles and "admin" not in roles:
            raise CannotReverify(
                classification,
                "Access-control re-verification requires a secondary (second or admin) identity "
                "in the request credentials.",
            )

    return family
