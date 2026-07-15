"""Wappalyzer-schema fingerprint matching engine (pure, no I/O).

Implements the documented Wappalyzer detection algorithm over a vendored,
MIT-licensed fingerprint database (see ``fingerprints/NOTICE.md``). The engine
is deliberately I/O-free so it is fast and unit-testable: evidence is gathered
by the caller (:class:`app.integrations.wappalyzer.TechnologyDetector`) and
passed in via :class:`Evidence`.

Pattern format (Wappalyzer): ``"<regex>\\;confidence:50\\;version:\\1"`` — a
regex followed by optional ``\\;``-delimited tags. ``version:\\1`` back-references
a regex capture group to extract the version (supports the ternary
``\\1?a:b`` form). Patterns are JS regexes; the minority that don't compile
under Python ``re`` are skipped gracefully rather than crashing the load.

Field → evidence mapping:
  headers, cookies   -> dict{name: pattern}   matched against response evidence
  html, scriptSrc,   -> str | list[str]       matched against HTML / <script src>
  scripts, url, meta
  js                 -> dict{path: pattern}    matched against window.<path> value
  dom                -> selector rules         matched against queried DOM nodes
Plus ``implies`` (add implied techs, transitively), ``excludes`` (drop), and
``cats`` (category ids → a normalized category string).
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_FINGERPRINT_DIR = Path(__file__).resolve().parent / "fingerprints"

# Wappalyzer category-id → normalized category string used by TechnologyComponent.
# Only the security-relevant / common buckets are normalized; the rest fall back
# to the upstream category name lowercased.
_CATEGORY_NORMALIZE = {
    "Web servers": "server",
    "Web frameworks": "framework",
    "JavaScript frameworks": "library",
    "JavaScript libraries": "library",
    "Programming languages": "language",
    "Databases": "database",
    "Operating systems": "os",
    "Reverse proxies": "server",
    "Web server extensions": "server",
    "CMS": "cms",
    "Caching": "cache",
    "PaaS": "hosting",
    "CDN": "cdn",
}


@dataclass
class Evidence:
    """Signals gathered from crawl data + an optional browser runtime pass."""

    headers: dict[str, str] = field(default_factory=dict)      # name(lower) -> joined value
    cookies: dict[str, str] = field(default_factory=dict)      # name -> value
    html: str = ""                                             # merged HTML bodies
    script_src: list[str] = field(default_factory=list)        # <script src> URLs
    meta: dict[str, str] = field(default_factory=dict)         # meta name -> content
    url: str = ""
    js: dict[str, str] = field(default_factory=dict)           # window path -> value
    dom: dict[str, dict] = field(default_factory=dict)         # selector -> {exists,text,attributes,properties}


@dataclass
class TechComponent:
    name: str
    version: str | None = None
    category: str = "framework"
    confidence: int = 0


# --------------------------------------------------------------------------- #
# Pattern parsing / compilation
# --------------------------------------------------------------------------- #

@dataclass
class _Pattern:
    regex: re.Pattern
    version: str | None = None
    confidence: int = 100


def _parse_pattern(raw: Any) -> _Pattern | None:
    """Parse a single Wappalyzer pattern string into a compiled _Pattern.

    Returns None if the value is empty (existence-only) handled by caller, or if
    the regex cannot be compiled under Python ``re``.
    """
    if not isinstance(raw, str):
        raw = str(raw) if raw is not None else ""
    parts = raw.split("\\;")
    body = parts[0]
    version: str | None = None
    confidence = 100
    for tag in parts[1:]:
        if tag.startswith("version:"):
            version = tag[len("version:"):]
        elif tag.startswith("confidence:"):
            try:
                confidence = int(tag[len("confidence:"):])
            except ValueError:
                pass
    if body == "":
        # Existence-only pattern: match anything present.
        body = ".*"
    try:
        return _Pattern(re.compile(body, re.IGNORECASE), version=version, confidence=confidence)
    except re.error:
        return None


def _as_pattern_list(value: Any) -> list[_Pattern]:
    """Normalize a str | list[str] field into compiled patterns (skipping bad)."""
    out: list[_Pattern] = []
    values = value if isinstance(value, list) else [value]
    for v in values:
        p = _parse_pattern(v)
        if p is not None:
            out.append(p)
    return out


def _as_pattern_map(value: Any) -> dict[str, list[_Pattern]]:
    """Normalize a dict{name: str|list} field into {name(lower): [patterns]}."""
    out: dict[str, list[_Pattern]] = {}
    if not isinstance(value, dict):
        return out
    for name, pat in value.items():
        patterns = _as_pattern_list(pat)
        if patterns:
            out[name.lower()] = patterns
    return out


@dataclass
class _CompiledTech:
    name: str
    cats: list[int]
    category: str
    headers: dict[str, list[_Pattern]]
    cookies: dict[str, list[_Pattern]]
    meta: dict[str, list[_Pattern]]
    html: list[_Pattern]
    script_src: list[_Pattern]
    scripts: list[_Pattern]
    url: list[_Pattern]
    js: dict[str, list[_Pattern]]
    dom: dict  # raw dom spec, evaluated against Evidence.dom
    implies: list[str]
    excludes: list[str]


def _normalize_dom(value: Any) -> dict:
    """Normalize the several dom shapes into {selector: {rules}}.

    Shapes: str selector, list[str] selectors (existence), or
    {selector: {exists|text|attributes|properties}}.
    """
    if isinstance(value, str):
        return {value: {"exists": True}}
    if isinstance(value, list):
        return {sel: {"exists": True} for sel in value if isinstance(sel, str)}
    if isinstance(value, dict):
        return value
    return {}


def _resolve_category(cats: list[int], categories: dict[str, dict]) -> str:
    for cat_id in cats:
        entry = categories.get(str(cat_id))
        if not entry:
            continue
        name = entry.get("name", "")
        if name in _CATEGORY_NORMALIZE:
            return _CATEGORY_NORMALIZE[name]
        return name.lower()
    return "framework"


@lru_cache(maxsize=1)
def _load_db() -> tuple[dict[str, _CompiledTech], int]:
    """Load + compile the vendored fingerprint DB once. Returns (techs, skipped)."""
    tech_path = _FINGERPRINT_DIR / "technologies.json"
    cat_path = _FINGERPRINT_DIR / "categories.json"
    if not tech_path.exists():
        logger.warning(
            "Fingerprint DB missing at %s; run scanner/scripts/update_fingerprints.py",
            tech_path,
        )
        return {}, 0

    # Tolerate trailing junk after the JSON object (a corrupt regeneration once
    # appended stray bytes, which made the whole DB fail to load): decode just
    # the leading JSON document and ignore anything after it. ``lstrip`` mirrors
    # ``json.loads``'s leading-whitespace tolerance, which ``raw_decode`` lacks.
    raw_techs, _ = json.JSONDecoder().raw_decode(tech_path.read_text(encoding="utf-8").lstrip())
    categories = json.loads(cat_path.read_text(encoding="utf-8")) if cat_path.exists() else {}

    compiled: dict[str, _CompiledTech] = {}
    skipped = 0

    def _count_skipped(field_value: Any, compiled_list: list) -> None:
        nonlocal skipped
        expected = field_value if isinstance(field_value, list) else [field_value]
        skipped += max(0, len(expected) - len(compiled_list))

    for name, spec in raw_techs.items():
        if not isinstance(spec, dict):
            continue
        cats = spec.get("cats", []) or []
        html = _as_pattern_list(spec.get("html", []))
        _count_skipped(spec.get("html", []), html)
        compiled[name] = _CompiledTech(
            name=name,
            cats=cats,
            category=_resolve_category(cats, categories),
            headers=_as_pattern_map(spec.get("headers", {})),
            cookies=_as_pattern_map(spec.get("cookies", {})),
            meta=_as_pattern_map(spec.get("meta", {})),
            html=html,
            script_src=_as_pattern_list(spec.get("scriptSrc", [])),
            scripts=_as_pattern_list(spec.get("scripts", [])),
            url=_as_pattern_list(spec.get("url", [])),
            js=_as_pattern_map(spec.get("js", {})),
            dom=_normalize_dom(spec.get("dom", {})),
            implies=[i.split("\\;")[0] for i in (spec.get("implies", []) or [])],
            excludes=[e.split("\\;")[0] for e in (spec.get("excludes", []) or [])],
        )

    logger.debug("Fingerprint DB loaded: %d technologies (%d patterns skipped)", len(compiled), skipped)
    return compiled, skipped


# --------------------------------------------------------------------------- #
# Version extraction + matching
# --------------------------------------------------------------------------- #

def _extract_version(match: re.Match, template: str | None) -> str | None:
    if not template:
        return None
    result = template
    # Ternary form: \1?value_if_present:value_if_absent
    ternary = re.match(r"\\(\d+)\?([^:]*):(.*)$", template)
    if ternary:
        idx = int(ternary.group(1))
        try:
            group_val = match.group(idx)
        except (IndexError, re.error):
            group_val = None
        return ternary.group(2) if group_val else ternary.group(3)
    # Plain backreferences \1, \2, ...
    def _sub(m: re.Match) -> str:
        idx = int(m.group(1))
        try:
            return match.group(idx) or ""
        except (IndexError, re.error):
            return ""
    result = re.sub(r"\\(\d+)", _sub, result)
    return result.strip() or None


def _match_patterns(patterns: list[_Pattern], value: str) -> tuple[bool, int, str | None]:
    """Return (matched, confidence, version) for the first hit."""
    for p in patterns:
        m = p.regex.search(value)
        if m:
            return True, p.confidence, _extract_version(m, p.version)
    return False, 0, None


def _match_dom(spec: dict, dom_evidence: dict[str, dict]) -> tuple[bool, str | None]:
    """Match a tech's dom spec against browser-collected dom evidence."""
    for selector, rules in spec.items():
        node = dom_evidence.get(selector)
        if not node:
            continue
        if not isinstance(rules, dict):
            # bare existence
            if node.get("exists"):
                return True, None
            continue
        if "exists" in rules and node.get("exists"):
            return True, None
        # text
        if "text" in rules:
            for p in _as_pattern_list(rules["text"]):
                m = p.regex.search(node.get("text", "") or "")
                if m:
                    return True, _extract_version(m, p.version)
        # attributes
        for attr, pat in (rules.get("attributes") or {}).items():
            attr_val = (node.get("attributes") or {}).get(attr.lower())
            if attr_val is None:
                continue
            for p in _as_pattern_list(pat):
                m = p.regex.search(attr_val)
                if m:
                    return True, _extract_version(m, p.version)
        # properties
        for prop, pat in (rules.get("properties") or {}).items():
            prop_val = (node.get("properties") or {}).get(prop)
            if prop_val is None:
                continue
            for p in _as_pattern_list(pat):
                m = p.regex.search(str(prop_val))
                if m:
                    return True, _extract_version(m, p.version)
    return False, None


def match(evidence: Evidence) -> list[TechComponent]:
    """Run the full fingerprint match against gathered evidence."""
    techs, _ = _load_db()
    detected: dict[str, TechComponent] = {}

    def _record(name: str, version: str | None, confidence: int) -> None:
        tech = techs.get(name)
        category = tech.category if tech else "framework"
        existing = detected.get(name)
        if existing:
            existing.confidence = min(100, existing.confidence + confidence)
            if version and not existing.version:
                existing.version = version
        else:
            detected[name] = TechComponent(name=name, version=version, category=category, confidence=confidence)

    for name, tech in techs.items():
        hit = False
        version: str | None = None

        # headers / cookies (dict{name: patterns})
        for ev_map, tech_map in ((evidence.headers, tech.headers), (evidence.cookies, tech.cookies)):
            for hname, patterns in tech_map.items():
                ev_val = ev_map.get(hname)
                if ev_val is None:
                    continue
                ok, conf, ver = _match_patterns(patterns, ev_val)
                if ok:
                    hit = True
                    version = version or ver
                    _record(name, ver, conf)

        # meta
        for mname, patterns in tech.meta.items():
            ev_val = evidence.meta.get(mname)
            if ev_val is None:
                continue
            ok, conf, ver = _match_patterns(patterns, ev_val)
            if ok:
                hit = True
                version = version or ver
                _record(name, ver, conf)

        # html / url (single string evidence)
        for patterns, ev_val in ((tech.html, evidence.html), (tech.url, evidence.url)):
            if not patterns or not ev_val:
                continue
            ok, conf, ver = _match_patterns(patterns, ev_val)
            if ok:
                hit = True
                version = version or ver
                _record(name, ver, conf)

        # scriptSrc / scripts (list of script urls; scripts also matches inline via html)
        for patterns in (tech.script_src,):
            for src in evidence.script_src:
                ok, conf, ver = _match_patterns(patterns, src)
                if ok:
                    hit = True
                    version = version or ver
                    _record(name, ver, conf)

        # js (dict{path: patterns})
        for path, patterns in tech.js.items():
            ev_val = evidence.js.get(path)
            if ev_val is None:
                continue
            ok, conf, ver = _match_patterns(patterns, ev_val)
            if ok:
                hit = True
                version = version or ver
                _record(name, ver, conf)

        # dom
        if tech.dom and evidence.dom:
            ok, ver = _match_dom(tech.dom, evidence.dom)
            if ok:
                hit = True
                version = version or ver
                _record(name, ver, 100)

        if hit and version and name in detected and not detected[name].version:
            detected[name].version = version

    # Resolve implies (transitively) and excludes.
    _resolve_implications(detected, techs)
    return list(detected.values())


def _resolve_implications(detected: dict[str, TechComponent], techs: dict[str, _CompiledTech]) -> None:
    queue = list(detected.keys())
    while queue:
        name = queue.pop()
        tech = techs.get(name)
        if not tech:
            continue
        for implied in tech.implies:
            if implied not in detected:
                itech = techs.get(implied)
                detected[implied] = TechComponent(
                    name=implied,
                    version=None,
                    category=itech.category if itech else "framework",
                    confidence=100,
                )
                queue.append(implied)
    # excludes: drop any tech excluded by a confidently-detected one.
    for name in list(detected.keys()):
        tech = techs.get(name)
        if not tech:
            continue
        for excluded in tech.excludes:
            detected.pop(excluded, None)


# --------------------------------------------------------------------------- #
# Runtime probe collection (for the browser pass)
# --------------------------------------------------------------------------- #

def runtime_probes() -> tuple[list[str], list[str]]:
    """Return (js_property_paths, dom_selectors) referenced by the whole DB.

    The browser pass evaluates these once and fills Evidence.js / Evidence.dom.
    """
    techs, _ = _load_db()
    js_paths: set[str] = set()
    dom_selectors: set[str] = set()
    for tech in techs.values():
        js_paths.update(tech.js.keys())
        dom_selectors.update(tech.dom.keys())
    return sorted(js_paths), sorted(dom_selectors)


def db_stats() -> tuple[int, int]:
    """(technology_count, skipped_pattern_count) — for diagnostics/tests."""
    techs, skipped = _load_db()
    return len(techs), skipped
