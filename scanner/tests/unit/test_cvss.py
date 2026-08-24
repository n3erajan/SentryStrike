"""CVSS v3.x base-score computation from a vector string.

OSV.dev reports severity as a CVSS *vector* rather than a numeric base score,
while the supply-chain detector grades findings on the number. Expected values
here are the scores NVD publishes for those exact vectors, not values derived
from this implementation.
"""

import pytest

from app.integrations.cvss import base_score_from_vector


@pytest.mark.parametrize(
    "vector,expected",
    [
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L", 5.0),  # CVE-2024-43796
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),  # CVE-2024-29041
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),  # CVE-2023-44487
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),  # CVE-2021-44228
    ],
)
def test_base_score_matches_nvds_published_score(vector, expected) -> None:
    assert base_score_from_vector(vector) == expected


def test_v30_vectors_are_scored_with_the_same_formula() -> None:
    assert base_score_from_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H") == 7.5


def test_scope_changed_applies_the_multiplier() -> None:
    """Scope-changed impact uses a different curve plus a 1.08 factor."""
    unchanged = base_score_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    changed = base_score_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
    assert unchanged == 9.8
    assert changed == 10.0


def test_privileges_required_is_weighted_differently_when_scope_changes() -> None:
    """PR:H is worth 0.27 unchanged but 0.5 when scope changes."""
    unchanged = base_score_from_vector("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H")
    changed = base_score_from_vector("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H")
    assert changed > unchanged


def test_zero_impact_scores_zero() -> None:
    assert base_score_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0


def test_unsupported_or_malformed_vectors_return_none() -> None:
    """A None score is honest; a fabricated one would mis-grade the finding."""
    # CVSS 4.0 uses lookup tables, not this formula.
    assert base_score_from_vector("CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:N/VI:N/VA:N") is None
    assert base_score_from_vector("AV:N/AC:L/Au:N/C:P/I:P/A:P") is None  # CVSS v2
    assert base_score_from_vector("not a vector") is None
    assert base_score_from_vector("") is None
    assert base_score_from_vector(None) is None


def test_vector_missing_a_required_metric_returns_none() -> None:
    assert base_score_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H") is None
