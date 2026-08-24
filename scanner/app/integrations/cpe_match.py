"""CPE identity + version-applicability matching for NVD configurations.

The NVD API's ``keywordSearch`` is a full-text search over CVE *description
prose*: it has no concept of product identity or version applicability. Asking
it for ``"WordPress 7.1"`` returns CVEs whose descriptions merely contain both
tokens - e.g. "the wp-live-chat-support plugin before 7.1.03 for WordPress" -
while asking for ``"Nginx 1.24.0"`` returns nothing at all, because NVD prose
rarely spells out a full patch version.

The structured answer lives in each CVE's ``configurations`` block, which
declares the vendor/product and the version ranges the CVE applies to. This
module is the pure, offline half of consuming that: given a detected version and
a single ``cpeMatch`` entry, decide whether the CVE genuinely applies.
"""

import re

# Split a version into runs of digits and runs of non-digits, discarding the
# separators. "1.2.3-rc1" -> ["1", "2", "3", "rc", "1"]; "r29" -> ["r", "29"].
_TOKEN_RE = re.compile(r"\d+|[A-Za-z]+")


def _tokenize(version: str) -> list[int | str]:
    return [int(t) if t.isdigit() else t.lower() for t in _TOKEN_RE.findall(version or "")]


def _compare_tokens(left: int | str, right: int | str) -> int:
    if isinstance(left, int) and isinstance(right, int):
        return (left > right) - (left < right)
    # A numeric identifier outranks an alphabetic one at the same position:
    # a release ("1.2") is later than a pre-release marker ("1.a").
    if isinstance(left, int):
        return 1
    if isinstance(right, int):
        return -1
    return (left > right) - (left < right)


def _compare_remainder(rest: list[int | str]) -> int:
    """Rank a version against a longer one sharing its prefix.

    Returns the sign to apply to the *longer* version. Trailing zeros mean the
    two are equal ("7.1" == "7.1.0"); a further numeric segment means the longer
    one is later ("7.1" < "7.1.3"); an alphabetic segment marks a pre-release, so
    the longer one is *earlier* ("1.2.3-rc1" < "1.2.3").
    """
    if all(isinstance(t, int) and t == 0 for t in rest):
        return 0
    return -1 if isinstance(rest[0], str) else 1


def compare_versions(left: str, right: str) -> int:
    """Order two version strings numerically. Returns -1, 0 or 1.

    Segment-wise numeric comparison, not lexical: nginx 1.24.0 is *newer* than
    1.9.5, though it sorts earlier as a string. CVE-2023-44487 declares the range
    1.9.5 - 1.25.2, so a lexical compare would wrongly rule 1.24.0 out.
    """
    lt, rt = _tokenize(left), _tokenize(right)
    for a, b in zip(lt, rt):
        cmp = _compare_tokens(a, b)
        if cmp:
            return cmp
    if len(lt) == len(rt):
        return 0
    if len(lt) < len(rt):
        return -_compare_remainder(rt[len(lt) :])
    return _compare_remainder(lt[len(rt) :])


def cpe_product(criteria: str) -> tuple[str, str] | None:
    """Return ``(vendor, product)`` from a CPE 2.3 URI, or None if malformed."""
    if not criteria:
        return None
    parts = criteria.split(":")
    if len(parts) < 6 or parts[0] != "cpe":
        return None
    return parts[3].lower(), parts[4].lower()


def cpe_version_field(criteria: str) -> str | None:
    """Return the version component of a CPE 2.3 URI, or None if malformed."""
    parts = (criteria or "").split(":")
    return parts[5] if len(parts) >= 6 and parts[0] == "cpe" else None


def version_applies(version: str, vendor: str, product: str, cpe_match: dict) -> bool:
    """Does ``version`` of ``vendor:product`` fall inside this cpeMatch entry?

    Four things have to hold, and dropping any one of them is how a scanner ends
    up reporting somebody else's CVE:

    * ``vulnerable`` is true - false entries describe the platform a CVE runs
      *on*, not the software that is vulnerable.
    * the vendor and product match - CVE-2023-44487 lists ``f5:nginx`` alongside
      ``f5:nginx_ingress_controller``, and only one of them is what we detected.
    * a version *bound* exists - legacy entries such as CVE-2007-2627's
      ``cpe:2.3:a:wordpress:wordpress:*`` carry no range whatsoever. That is
      missing data, not a claim of universal applicability, so it is rejected
      rather than allowed to match every release forever.
    * the detected version sits inside that bound.
    """
    if not cpe_match.get("vulnerable", True):
        return False

    criteria = cpe_match.get("criteria") or cpe_match.get("cpe23Uri") or ""
    identity = cpe_product(criteria)
    if identity != (vendor.lower(), product.lower()):
        return False

    if not version:
        return False

    # A CPE that pins an exact version needs no range and applies only to it.
    pinned = cpe_version_field(criteria)
    if pinned and pinned not in ("*", "-"):
        return compare_versions(version, pinned) == 0

    start_incl = cpe_match.get("versionStartIncluding")
    start_excl = cpe_match.get("versionStartExcluding")
    end_incl = cpe_match.get("versionEndIncluding")
    end_excl = cpe_match.get("versionEndExcluding")
    if not any((start_incl, start_excl, end_incl, end_excl)):
        return False

    if start_incl and compare_versions(version, start_incl) < 0:
        return False
    if start_excl and compare_versions(version, start_excl) <= 0:
        return False
    if end_incl and compare_versions(version, end_incl) > 0:
        return False
    if end_excl and compare_versions(version, end_excl) >= 0:
        return False
    return True


def any_config_applies(version: str, vendor: str, product: str, configurations: list) -> bool:
    """True if any cpeMatch across a CVE's configurations covers this version."""
    for config in configurations or []:
        for node in config.get("nodes", []) or []:
            for match in node.get("cpeMatch", []) or []:
                if version_applies(version, vendor, product, match):
                    return True
    return False
