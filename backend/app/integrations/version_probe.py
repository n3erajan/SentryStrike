"""Generic component-version extraction from manifests, lockfiles, and headers.

The scanner's supply-chain gate (``supply_chain.py``) — correctly — refuses to
emit an A03 finding without a component *version*: a CVE against "Express" is
meaningless until you know the target's Express version. Error/HTML/runtime
fingerprinting frequently identifies a technology but not its version. This
module fills that gap from the version-bearing surfaces almost every app
exposes:

* **Package manifests / lockfiles** — ``/package.json``, ``/package-lock.json``,
  ``/composer.json``, ``/composer.lock``, ``/requirements.txt``, ``/Gemfile.lock``.
  When reachable, these static files give exact dependency versions. Each path
  is an *ecosystem standard* (npm/Composer/pip/Bundler), never a target rule.
* **Version-bearing response headers** — ``Server``, ``X-Powered-By``,
  ``X-AspNet-Version``, ``X-Generator``: standard ``name/version`` carriers.

Every mapping here encodes a *universal property of a technology* (the npm
package ``express`` IS the "Express" framework, in any app) — the same identity
aliasing an ecosystem's own registry uses. Nothing is Juice-Shop-specific.

Design contract: **never raises** (best-effort, debug-logs on failure) and adds
**near-zero cost** when nothing is exposed — manifests are only fetched for
ecosystems whose components were already detected, and the total request count
is bounded.
"""

from __future__ import annotations

import json
import logging
import re

from app.integrations.wappalyzer_engine import TechComponent

logger = logging.getLogger(__name__)

# Hard cap on manifest fetches per probe — keeps cost bounded on any target.
_MAX_PROBE_REQUESTS = 8


# --------------------------------------------------------------------------- #
# Technology-identity alias tables.
#
# Left  = the dependency name as it appears in an ecosystem manifest/registry.
# Right = (canonical component name aligned with Wappalyzer / error_fingerprints
#          so downstream CVE lookup + de-dup are consistent, category).
# Each entry is a universal identity: the package IS that technology in any app.
# --------------------------------------------------------------------------- #

# npm (package.json / package-lock.json dependency name -> component)
_NPM_ALIASES: dict[str, tuple[str, str]] = {
    "express": ("Express", "framework"),
    "sequelize": ("Sequelize", "orm"),
    "typeorm": ("TypeORM", "orm"),
    "@prisma/client": ("Prisma", "orm"),
    "prisma": ("Prisma", "orm"),
    "mongoose": ("Mongoose", "orm"),
    "@angular/core": ("Angular", "framework"),
    "react": ("React", "framework"),
    "vue": ("Vue.js", "framework"),
    "next": ("Next.js", "framework"),
    "koa": ("Koa", "framework"),
    "@nestjs/core": ("Nest.js", "framework"),
    "fastify": ("Fastify", "framework"),
    "lodash": ("Lodash", "library"),
    "axios": ("Axios", "library"),
}

# Composer (composer.json require / composer.lock package name -> component)
_COMPOSER_ALIASES: dict[str, tuple[str, str]] = {
    "laravel/framework": ("Laravel", "framework"),
    "symfony/symfony": ("Symfony", "framework"),
    "symfony/http-kernel": ("Symfony", "framework"),
    "slim/slim": ("Slim", "framework"),
    "yiisoft/yii2": ("Yii", "framework"),
    "cakephp/cakephp": ("CakePHP", "framework"),
    "doctrine/orm": ("Doctrine", "orm"),
}

# pip (requirements.txt distribution name -> component); keys are lowercased.
_PIP_ALIASES: dict[str, tuple[str, str]] = {
    "django": ("Django", "framework"),
    "flask": ("Flask", "framework"),
    "fastapi": ("FastAPI", "framework"),
    "tornado": ("Tornado", "framework"),
    "sqlalchemy": ("SQLAlchemy", "orm"),
    "pyramid": ("Pyramid", "framework"),
    "bottle": ("Bottle", "framework"),
}

# RubyGems (Gemfile.lock gem name -> component)
_GEM_ALIASES: dict[str, tuple[str, str]] = {
    "rails": ("Ruby on Rails", "framework"),
    "rack": ("Rack", "framework"),
    "sinatra": ("Sinatra", "framework"),
    "activerecord": ("Active Record", "orm"),
}

# Response-header token -> component. Server / X-Powered-By carry "Name/version";
# these normalize the common bare tokens to canonical identities.
_HEADER_ALIASES: dict[str, tuple[str, str]] = {
    "nginx": ("Nginx", "server"),
    "apache": ("Apache", "server"),
    "openresty": ("OpenResty", "server"),
    "iis": ("IIS", "server"),
    "microsoft-iis": ("IIS", "server"),
    "php": ("PHP", "language"),
    "express": ("Express", "framework"),
    "kestrel": ("Kestrel", "server"),
    "gunicorn": ("Gunicorn", "server"),
    "werkzeug": ("Werkzeug", "server"),
    "jetty": ("Jetty", "server"),
    "tomcat": ("Apache Tomcat", "server"),
    "coyote": ("Apache Tomcat", "server"),  # "Apache-Coyote/1.1" is Tomcat's connector
    "puma": ("Puma", "server"),
    "unicorn": ("Unicorn", "server"),
}

# Which ecosystems does the already-detected stack imply? Used to bound probing
# to relevant manifests only. Keys are canonical component-name substrings.
_ECOSYSTEM_MARKERS: dict[str, list[str]] = {
    # Node markers include SPA/build frameworks: those apps ship a package.json.
    "node": [
        "node", "express", "sequelize", "typeorm", "prisma", "mongoose",
        "angular", "react", "vue", "next", "koa", "nest", "fastify",
    ],
    "php": ["php", "laravel", "symfony", "slim", "yii", "cakephp", "doctrine", "wordpress", "drupal"],
    "python": ["python", "django", "flask", "fastapi", "tornado", "sqlalchemy", "pyramid", "bottle", "werkzeug", "gunicorn"],
    "ruby": ["ruby", "rails", "rack", "sinatra", "active record", "puma", "unicorn", "passenger"],
}

# Ecosystem -> manifest paths to try (order = most-exact version source first).
_ECOSYSTEM_MANIFESTS: dict[str, list[str]] = {
    "node": ["/package.json", "/package-lock.json"],
    "php": ["/composer.json", "/composer.lock"],
    "python": ["/requirements.txt"],
    "ruby": ["/Gemfile.lock"],
}


# --------------------------------------------------------------------------- #
# Version normalization
# --------------------------------------------------------------------------- #

def _clean_version(raw: str | None) -> str | None:
    """Extract a bare ``major.minor[.patch]`` from a version spec/constraint.

    Strips npm/pip/composer operators and prefixes (``^``, ``~``, ``>=``, ``v``,
    distro suffixes) to the upstream version the CVE feeds key on. Returns
    ``None`` when no numeric version token is present (e.g. ``"*"``, ``"latest"``).
    """
    if not raw:
        return None
    m = re.search(r"[0-9]+(?:\.[0-9]+){1,3}", str(raw))
    if not m:
        # Accept a lone major (e.g. ">=18") as a coarse version.
        m2 = re.search(r"[0-9]+", str(raw))
        return m2.group(0) if m2 else None
    return m.group(0)


def _emit(alias: tuple[str, str], raw_version: str | None) -> TechComponent | None:
    version = _clean_version(raw_version)
    if not version:
        return None
    name, category = alias
    return TechComponent(name=name, version=version, category=category, confidence=100)


# --------------------------------------------------------------------------- #
# Manifest parsers — each maps a manifest body to versioned components.
# --------------------------------------------------------------------------- #

def _parse_package_json(body: str) -> list[TechComponent]:
    out: list[TechComponent] = []
    data = json.loads(body)
    if not isinstance(data, dict):
        return out
    # Runtime version from engines.node (direct runtime field).
    engines = data.get("engines")
    if isinstance(engines, dict) and engines.get("node"):
        comp = _emit(("Node.js", "language"), engines.get("node"))
        if comp:
            out.append(comp)
    for section in ("dependencies", "devDependencies"):
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        for dep, spec in deps.items():
            alias = _NPM_ALIASES.get(str(dep).lower())
            if alias:
                comp = _emit(alias, spec if isinstance(spec, str) else None)
                if comp:
                    out.append(comp)
    return out


def _parse_package_lock(body: str) -> list[TechComponent]:
    out: list[TechComponent] = []
    data = json.loads(body)
    if not isinstance(data, dict):
        return out
    # lockfileVersion 2/3: {"packages": {"node_modules/<name>": {"version": ...}}}
    packages = data.get("packages")
    if isinstance(packages, dict):
        for path, meta in packages.items():
            if not isinstance(meta, dict) or not path:
                continue
            name = str(path).rsplit("node_modules/", 1)[-1]
            alias = _NPM_ALIASES.get(name.lower())
            if alias:
                comp = _emit(alias, meta.get("version"))
                if comp:
                    out.append(comp)
    # lockfileVersion 1: {"dependencies": {"<name>": {"version": ...}}}
    deps = data.get("dependencies")
    if isinstance(deps, dict):
        for name, meta in deps.items():
            alias = _NPM_ALIASES.get(str(name).lower())
            if alias and isinstance(meta, dict):
                comp = _emit(alias, meta.get("version"))
                if comp:
                    out.append(comp)
    return out


def _parse_composer_json(body: str) -> list[TechComponent]:
    out: list[TechComponent] = []
    data = json.loads(body)
    if not isinstance(data, dict):
        return out
    require = data.get("require")
    if isinstance(require, dict):
        if require.get("php"):
            comp = _emit(("PHP", "language"), require.get("php"))
            if comp:
                out.append(comp)
        for pkg, spec in require.items():
            alias = _COMPOSER_ALIASES.get(str(pkg).lower())
            if alias:
                comp = _emit(alias, spec if isinstance(spec, str) else None)
                if comp:
                    out.append(comp)
    return out


def _parse_composer_lock(body: str) -> list[TechComponent]:
    out: list[TechComponent] = []
    data = json.loads(body)
    if not isinstance(data, dict):
        return out
    for section in ("packages", "packages-dev"):
        pkgs = data.get(section)
        if not isinstance(pkgs, list):
            continue
        for entry in pkgs:
            if not isinstance(entry, dict):
                continue
            alias = _COMPOSER_ALIASES.get(str(entry.get("name", "")).lower())
            if alias:
                comp = _emit(alias, entry.get("version"))
                if comp:
                    out.append(comp)
    return out


_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*(?:==|>=|~=|>)\s*([0-9][0-9A-Za-z.\-]*)")


def _parse_requirements_txt(body: str) -> list[TechComponent]:
    out: list[TechComponent] = []
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _REQ_LINE.match(line)
        if not m:
            continue
        alias = _PIP_ALIASES.get(m.group(1).lower())
        if alias:
            comp = _emit(alias, m.group(2))
            if comp:
                out.append(comp)
    return out


_GEM_LINE = re.compile(r"^\s{4}([A-Za-z0-9_.\-]+)\s+\(([0-9][0-9A-Za-z.\-]*)\)")


def _parse_gemfile_lock(body: str) -> list[TechComponent]:
    out: list[TechComponent] = []
    for line in body.splitlines():
        m = _GEM_LINE.match(line)
        if not m:
            continue
        alias = _GEM_ALIASES.get(m.group(1).lower())
        if alias:
            comp = _emit(alias, m.group(2))
            if comp:
                out.append(comp)
    return out


_MANIFEST_PARSERS = {
    "/package.json": _parse_package_json,
    "/package-lock.json": _parse_package_lock,
    "/composer.json": _parse_composer_json,
    "/composer.lock": _parse_composer_lock,
    "/requirements.txt": _parse_requirements_txt,
    "/Gemfile.lock": _parse_gemfile_lock,
}


def parse_manifest(path: str, body: str) -> list[TechComponent]:
    """Parse a manifest body into versioned components. Never raises."""
    parser = None
    for suffix, fn in _MANIFEST_PARSERS.items():
        if path.endswith(suffix):
            parser = fn
            break
    if parser is None or not body:
        return []
    try:
        return parser(body)
    except Exception as exc:  # malformed body / unexpected shape
        logger.debug("version_probe: failed to parse %s: %s", path, exc)
        return []


# --------------------------------------------------------------------------- #
# Header version extraction
# --------------------------------------------------------------------------- #

# "name/version" or "name version" tokens inside a header value.
_HEADER_TOKEN = re.compile(r"([A-Za-z][A-Za-z0-9_.\-]*)[/ ]([0-9]+(?:\.[0-9]+){0,3})")


def extract_header_versions(headers: dict[str, str]) -> list[TechComponent]:
    """Parse version-bearing response headers into components. Never raises."""
    out: list[TechComponent] = []
    seen: set[str] = set()
    if not headers:
        return out
    lower = {str(k).lower(): str(v) for k, v in headers.items()}

    # Server / X-Powered-By / X-Generator carry "Name/version" tokens.
    for hname in ("server", "x-powered-by", "x-generator"):
        val = lower.get(hname)
        if not val:
            continue
        for tok, ver in _HEADER_TOKEN.findall(val):
            alias = _HEADER_ALIASES.get(tok.lower())
            if not alias:
                continue
            comp = _emit(alias, ver)
            if comp and comp.name not in seen:
                seen.add(comp.name)
                out.append(comp)

    # X-AspNet-Version / X-AspNetMvc-Version carry a bare version for ASP.NET.
    for hname in ("x-aspnet-version", "x-aspnetmvc-version"):
        val = lower.get(hname)
        if val:
            comp = _emit(("Microsoft ASP.NET", "framework"), val)
            if comp and comp.name not in seen:
                seen.add(comp.name)
                out.append(comp)

    return out


# --------------------------------------------------------------------------- #
# Bounded manifest probe over HTTP
# --------------------------------------------------------------------------- #

def _relevant_ecosystems(component_names: list[str]) -> list[str]:
    lowered = [str(n).lower() for n in component_names]
    hits: list[str] = []
    for eco, markers in _ECOSYSTEM_MARKERS.items():
        if any(any(m in name for m in markers) for name in lowered):
            hits.append(eco)
    return hits


async def probe_versions(root_url: str, http_client, component_names: list[str]) -> list[TechComponent]:
    """Fetch ecosystem-standard manifests and return versioned components.

    Only probes ecosystems implied by ``component_names`` (bounded + relevant),
    caps total requests at ``_MAX_PROBE_REQUESTS``, and never raises.
    """
    ecosystems = _relevant_ecosystems(component_names)
    if not ecosystems:
        return []

    base = root_url.rstrip("/")
    results: list[TechComponent] = []
    requests_made = 0

    for eco in ecosystems:
        for path in _ECOSYSTEM_MANIFESTS.get(eco, []):
            if requests_made >= _MAX_PROBE_REQUESTS:
                return results
            url = f"{base}{path}"
            requests_made += 1
            try:
                resp = await http_client.get(url)
            except Exception as exc:
                logger.debug("version_probe: fetch failed for %s: %s", url, exc)
                continue
            if getattr(resp, "status_code", 0) != 200:
                continue
            body = getattr(resp, "text", "") or ""
            # Content sanity: a manifest must parse; HTML error pages won't.
            parsed = parse_manifest(path, body)
            if parsed:
                results.extend(parsed)

    return results
