"""Version-applicability matching against NVD CPE configurations.

These tests pin the behaviour that the old ``keywordSearch`` lookup lacked
entirely: deciding whether a *detected* version actually falls inside the
version range an NVD CVE declares itself applicable to.
"""

import pytest

from app.integrations.cpe_match import (
    compare_versions,
    cpe_product,
    version_applies,
)


# --------------------------------------------------------------------------- #
# Version comparison
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "left,right,expected",
    [
        ("1.24.0", "1.24.0", 0),
        ("1.24.0", "1.25.2", -1),
        ("1.25.2", "1.24.0", 1),
        # Lexical comparison gets this backwards: "1.24.0" < "1.9.5" as strings.
        # nginx 1.24.0 is NEWER than 1.9.5, and CVE-2023-44487's range is
        # 1.9.5 -> 1.25.2, so a lexical compare would wrongly exclude it.
        ("1.24.0", "1.9.5", 1),
        ("1.9.5", "1.24.0", -1),
        # Unequal segment counts: the shorter version is the earlier release.
        ("7.1", "7.1.0", 0),
        ("7.1", "7.1.3", -1),
        ("7.0.4", "7.1", -1),
        ("6.9.7", "7.1", -1),
    ],
)
def test_compare_versions_orders_numerically_not_lexically(left, right, expected) -> None:
    assert compare_versions(left, right) == expected


def test_compare_versions_handles_non_numeric_suffixes() -> None:
    # Pre-release / packaging suffixes must not raise, and must sort before the
    # matching release ("1.2.3-rc1" precedes "1.2.3").
    assert compare_versions("1.2.3-rc1", "1.2.3") == -1
    assert compare_versions("r29", "r30") == -1


# --------------------------------------------------------------------------- #
# CPE product identity
# --------------------------------------------------------------------------- #

def test_cpe_product_extracts_vendor_and_product() -> None:
    assert cpe_product("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*") == ("f5", "nginx")
    assert cpe_product("cpe:2.3:a:wordpress:wordpress:7.1:*:*:*:*:*:*:*") == (
        "wordpress",
        "wordpress",
    )


def test_cpe_product_returns_none_for_malformed_cpe() -> None:
    assert cpe_product("nginx") is None
    assert cpe_product("") is None


# --------------------------------------------------------------------------- #
# Applicability
# --------------------------------------------------------------------------- #

def test_version_inside_start_including_end_excluding_range_applies() -> None:
    # CVE-2023-44487's real nginx range.
    match = {
        "criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
        "versionStartIncluding": "1.9.5",
        "versionEndIncluding": "1.25.2",
        "vulnerable": True,
    }
    assert version_applies("1.24.0", "f5", "nginx", match) is True


def test_version_below_range_start_does_not_apply() -> None:
    match = {
        "criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
        "versionStartIncluding": "1.9.5",
        "versionEndIncluding": "1.25.2",
        "vulnerable": True,
    }
    assert version_applies("1.8.0", "f5", "nginx", match) is False


def test_version_at_end_excluding_boundary_does_not_apply() -> None:
    match = {
        "criteria": "cpe:2.3:a:expressjs:express:*:*:*:*:*:*:*:*",
        "versionEndExcluding": "4.19.2",
        "vulnerable": True,
    }
    assert version_applies("4.19.2", "expressjs", "express", match) is False
    assert version_applies("4.18.2", "expressjs", "express", match) is True


def test_version_pinned_exactly_in_cpe_applies_only_to_that_version() -> None:
    match = {
        "criteria": "cpe:2.3:a:f5:nginx_plus:r29:-:*:*:*:*:*:*",
        "vulnerable": True,
    }
    assert version_applies("r29", "f5", "nginx_plus", match) is True
    assert version_applies("r30", "f5", "nginx_plus", match) is False


def test_unbounded_wildcard_cpe_never_applies() -> None:
    """The CVE-2007-2627 trap.

    Legacy NVD entries carry ``cpe:2.3:a:wordpress:wordpress:*`` with no version
    bounds at all, so a naive matcher treats them as applying to every version
    ever released. WordPress 7.1 is current and unaffected by a 2007 XSS; an
    un-versioned wildcard is an absence of data, not a statement of coverage.
    """
    match = {
        "criteria": "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
        "vulnerable": True,
    }
    assert version_applies("7.1", "wordpress", "wordpress", match) is False


def test_different_product_does_not_apply() -> None:
    """CVE-2023-44487 also lists nginx_ingress_controller; nginx must not match it."""
    match = {
        "criteria": "cpe:2.3:a:f5:nginx_ingress_controller:*:*:*:*:*:*:*:*",
        "versionStartIncluding": "2.0.0",
        "versionEndIncluding": "2.4.2",
        "vulnerable": True,
    }
    assert version_applies("1.24.0", "f5", "nginx", match) is False


def test_non_vulnerable_match_does_not_apply() -> None:
    """``vulnerable: false`` nodes describe running-on platforms, not victims."""
    match = {
        "criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
        "versionStartIncluding": "1.9.5",
        "versionEndIncluding": "1.25.2",
        "vulnerable": False,
    }
    assert version_applies("1.24.0", "f5", "nginx", match) is False


def test_start_excluding_and_end_including_bounds_are_honoured() -> None:
    match = {
        "criteria": "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*",
        "versionStartExcluding": "8.1.0",
        "versionEndIncluding": "8.1.10",
        "vulnerable": True,
    }
    assert version_applies("8.1.0", "php", "php", match) is False
    assert version_applies("8.1.1", "php", "php", match) is True
    assert version_applies("8.1.10", "php", "php", match) is True
    assert version_applies("8.1.11", "php", "php", match) is False
