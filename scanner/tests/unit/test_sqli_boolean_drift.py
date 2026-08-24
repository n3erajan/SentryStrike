"""A page that grows on every write must not read as a boolean SQLi differential.

DVWA's guestbook (``/vulnerabilities/xss_s/``) appends a row per POST. The
boolean loop always sends TRUE before FALSE, so FALSE is always one row further
from the baseline than TRUE. Measured live: two POSTs of an identical benign
value drifted apart by 0.000287, and the TRUE/FALSE pair by 0.000288 - the same
number. It was reported as High-severity SQL injection, twice over, because the
confirmation round reproduces a deterministic artifact perfectly.

The gate used to require the separation to exceed a *quarter* of the measured
variance, which any systematic drift clears by construction.
"""

import pytest

from app.core.verification.sqli_verifier import (
    _BOOL_MIN_SEPARATION,
    _BOOL_NOISE_MULTIPLE,
    _boolean_pair_is_directional,
)

# Live measurements from DVWA's append-on-POST guestbook.
DRIFT_SEPARATION = 0.000288
DRIFT_STABILITY = 1.0 - 0.000287

# Live measurements from confirmed blind SQLi on non-accumulating pages.
GENUINE_SEPARATION = 0.004546
GENUINE_STABILITY = 1.0


def _pair(separation: float) -> dict:
    """Analysis dict for a TRUE/FALSE pair with the given separation."""
    true_sim = 0.999
    return {
        "baseline_similarity_to_true": true_sim,
        "baseline_similarity_to_false": true_sim - separation,
        "true_vs_false_similarity": 1.0 - separation,
    }


def test_append_on_write_drift_is_not_a_differential():
    assert not _boolean_pair_is_directional(_pair(DRIFT_SEPARATION), DRIFT_STABILITY), (
        "page-growth drift is still being accepted as a boolean differential"
    )


def test_genuine_blind_sqli_still_detected():
    assert _boolean_pair_is_directional(_pair(GENUINE_SEPARATION), GENUINE_STABILITY)


def test_small_genuine_differential_on_stable_page_still_detected():
    """One row vanishing from a boilerplate-heavy page - the smallest real signal."""
    assert _boolean_pair_is_directional(_pair(0.000937), 1.0)


def test_separation_must_exceed_measured_variance_not_a_fraction():
    """The gate direction itself: noise sets a ceiling to clear, not a discount."""
    noise = 0.01
    stability = 1.0 - noise

    # Below the measured variance - indistinguishable from the page's own jitter.
    assert not _boolean_pair_is_directional(_pair(noise * 0.5), stability)
    # Comfortably above it.
    assert _boolean_pair_is_directional(_pair(noise * (_BOOL_NOISE_MULTIPLE + 1)), stability)


def test_absolute_floor_applies_when_page_measures_no_variance():
    assert not _boolean_pair_is_directional(_pair(_BOOL_MIN_SEPARATION / 2), 1.0)
    assert _boolean_pair_is_directional(_pair(_BOOL_MIN_SEPARATION * 2), 1.0)
