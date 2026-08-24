"""Resolve WordPress plugin and theme identities from enqueued asset URLs.

The Wordfence feed is keyed on slug, so a component named only "Smart Slider 3"
can never be looked up - and WordPress plugins and themes, not core, are where
almost all real WordPress risk lives. WordPress serves extension assets from
predictable paths and stamps them with a version:

    /wp-content/plugins/<slug>/css/app.css?ver=3.5.1

which yields both the slug and, usually, the extension's own version.

"Usually" is the catch. ``?ver`` is whatever was passed to ``wp_enqueue_script``:
often the extension version, sometimes a cache-busting hash, and - when the
extension declares no version - WordPress's own core version. The last case is the
dangerous one, because it looks exactly like a plausible version number. Both are
rejected here rather than guessed at; an unknown version yields ``not_assessed``,
whereas a wrong one silently matches somebody else's advisory range.
"""

import re

from shared.models.vulnerability import TechnologyComponent

# /wp-content/{plugins,mu-plugins,themes}/<slug>/<path>[?ver=<version>]
_ASSET_RE = re.compile(
    r"/wp-content/(?P<kind>plugins|mu-plugins|themes)/(?P<slug>[^/?\"'\s]+)/"
    r"[^\"'\s>]*?(?:\?|&(?:amp;)?)ver=(?P<version>[^\"'&\s>]+)|"
    r"/wp-content/(?P<kind2>plugins|mu-plugins|themes)/(?P<slug2>[^/?\"'\s]+)/",
    re.IGNORECASE,
)

# A plausible extension version: digits and dots, optionally a pre-release or
# build suffix. Deliberately excludes bare hex hashes such as "1c12b24c" and
# 32-character md5 cache busters, both of which appear in the wild.
_VERSION_RE = re.compile(r"^\d+(?:\.\d+)*(?:[-.][A-Za-z0-9]+)*$")

_CATEGORIES = {
    "plugins": "wordpress plugins",
    "mu-plugins": "wordpress plugins",
    "themes": "wordpress themes",
}


def _clean_version(raw: str | None, core_version: str | None) -> str | None:
    """Accept only values that are plausibly the *extension's* own version."""
    if not raw:
        return None
    candidate = raw.strip()
    if not _VERSION_RE.match(candidate):
        return None
    # WordPress falls back to stamping its own core version when an extension
    # declares none, so a match there is ambiguous rather than informative.
    if core_version and candidate == core_version.strip():
        return None
    return candidate


def _is_valid_slug(slug: str) -> bool:
    return bool(slug) and slug not in (".", "..") and "." != slug[0]


def extract_extensions(
    html: str, script_src: list[str], core_version: str | None = None
) -> list[TechnologyComponent]:
    """Return one component per (kind, slug) found in the supplied evidence.

    A version-bearing asset takes precedence over a version-less one for the same
    extension, since a single plugin ships many assets and only some carry a
    ``?ver``.
    """
    haystack = "\n".join([html or "", *(script_src or [])])
    if "/wp-content/" not in haystack:
        return []

    found: dict[tuple[str, str], str | None] = {}
    for match in _ASSET_RE.finditer(haystack):
        kind = (match.group("kind") or match.group("kind2") or "").lower()
        slug = match.group("slug") or match.group("slug2") or ""
        if not kind or not _is_valid_slug(slug):
            continue
        key = (kind, slug.lower())
        version = _clean_version(match.group("version"), core_version)
        # Never let a later version-less asset erase a version already resolved.
        if version or key not in found:
            found[key] = version if version else found.get(key)

    return [
        TechnologyComponent(
            name=_display_name(slug),
            version=version,
            category=_CATEGORIES[kind],
            slug=slug,
        )
        for (kind, slug), version in found.items()
    ]


def _display_name(slug: str) -> str:
    """Humanise a slug for the report: "smart-slider-3" -> "Smart Slider 3"."""
    return " ".join(word.capitalize() for word in re.split(r"[-_]+", slug) if word)


def merge_key(name: str) -> str:
    """Normalise a name or slug for cross-source matching.

    Fingerprint matching names an extension ("Smart Slider 3") while asset paths
    give its slug ("smart-slider-3"); both reduce to "smartslider3", which lets
    the slug be back-filled onto the already-detected component instead of adding
    a duplicate row.
    """
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())
