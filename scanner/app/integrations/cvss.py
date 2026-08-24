"""CVSS v3.x base-score computation from a vector string.

OSV.dev and GitHub Security Advisories express severity as a CVSS vector, while
the supply-chain detector grades findings on a numeric base score. Rather than
substitute a placeholder number - the old detector defaulted a missing score to
7.5, inventing "high" out of nothing - this computes the real score from the
vector per the CVSS v3.1 specification, and returns None when it genuinely
cannot.
"""

import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
# v3 impact metrics are High/Low/None - "M" is v2's naming and is not valid here.
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
# Privileges Required is weighted higher when the vulnerability escapes its scope.
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}

_SUPPORTED_PREFIXES = ("CVSS:3.1/", "CVSS:3.0/")


def _roundup(value: float) -> float:
    """CVSS 3.1 Appendix A roundup: round *up* to one decimal place.

    Uses integer arithmetic as the spec prescribes, because floating-point
    ``ceil(x * 10) / 10`` misrounds values that are already exact at one decimal.
    """
    scaled = int(round(value * 100000))
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0


def base_score_from_vector(vector: str | None) -> float | None:
    """Return the CVSS v3.x base score for ``vector``, or None if unsupported.

    None is returned for CVSS v2 and v4.0 vectors (v4.0 scores via lookup tables,
    not this formula), for malformed input, and for vectors missing any of the
    eight base metrics.
    """
    if not vector or not vector.startswith(_SUPPORTED_PREFIXES):
        return None

    metrics: dict[str, str] = {}
    for part in vector.split("/")[1:]:
        key, _, value = part.partition(":")
        if key and value:
            metrics[key] = value

    scope = metrics.get("S")
    if scope not in ("U", "C"):
        return None
    pr_weights = _PR_UNCHANGED if scope == "U" else _PR_CHANGED

    try:
        av = _AV[metrics["AV"]]
        ac = _AC[metrics["AC"]]
        pr = pr_weights[metrics["PR"]]
        ui = _UI[metrics["UI"]]
        conf = _CIA[metrics["C"]]
        integ = _CIA[metrics["I"]]
        avail = _CIA[metrics["A"]]
    except KeyError:
        return None

    iss = 1 - ((1 - conf) * (1 - integ) * (1 - avail))
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui
    raw = impact + exploitability
    if scope == "C":
        raw *= 1.08
    return _roundup(min(raw, 10.0))
