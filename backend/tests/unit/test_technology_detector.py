"""Tests for the Wappalyzer-schema technology fingerprinting engine + detector.

Covers RC-6 from the detection audit: the old header-only detector returned an
empty stack for header-hiding SPAs. These lock in the new engine's matching
(headers/cookies/scriptSrc/meta/js/dom), version extraction, implies/excludes
resolution, and the detector's passive evidence assembly.

Tests run against the real vendored fingerprint DB (committed under
``app/integrations/fingerprints/``) using stable, well-known fingerprints.
"""

from __future__ import annotations

import re
from types import SimpleNamespace

import pytest

from app.integrations import wappalyzer_engine as engine
from app.integrations.wappalyzer import TechnologyDetector


# --------------------------------------------------------------------------- #
# Engine: DB load + robustness
# --------------------------------------------------------------------------- #

def test_db_loads_and_is_populated():
    count, skipped = engine.db_stats()
    assert count > 1000, "vendored fingerprint DB should hold thousands of techs"
    assert isinstance(skipped, int) and skipped >= 0


def test_runtime_probes_nonempty():
    js_paths, dom_selectors = engine.runtime_probes()
    assert js_paths, "DB references js window properties"
    assert dom_selectors, "DB references dom selectors"
    # ng-version is the canonical modern-Angular DOM signal.
    assert any("ng-version" in s for s in dom_selectors)


# --------------------------------------------------------------------------- #
# Engine: pattern parsing + version extraction
# --------------------------------------------------------------------------- #

def test_invalid_regex_is_skipped_not_raised():
    assert engine._parse_pattern(r"a{99999,}{5,}(") is None


def test_version_backreference_extraction():
    p = engine._parse_pattern(r"nginx(?:/([\d.]+))?\;version:\1")
    m = p.regex.search("nginx/1.25.3")
    assert engine._extract_version(m, p.version) == "1.25.3"


def test_version_ternary_form():
    p = engine._parse_pattern(r"([\d.]+)?\;version:\1?yes:no")
    assert engine._extract_version(p.regex.search("2.0"), p.version) == "yes"
    assert engine._extract_version(p.regex.search("xx"), p.version) == "no"


def test_confidence_tag_parsed():
    p = engine._parse_pattern(r"foo\;confidence:50")
    assert p.confidence == 50


# --------------------------------------------------------------------------- #
# Engine: matching by evidence field
# --------------------------------------------------------------------------- #

def _names(components):
    return {c.name for c in components}


def test_header_match_and_implies_resolution():
    # Express is detected via X-Powered-By and implies Node.js (transitive).
    ev = engine.Evidence(headers={"x-powered-by": "Express"})
    res = engine.match(ev)
    names = _names(res)
    assert "Express" in names
    assert "Node.js" in names, "Express implies Node.js"


def test_server_header_version_extraction():
    ev = engine.Evidence(headers={"server": "nginx/1.25.3"})
    res = engine.match(ev)
    nginx = next((c for c in res if c.name == "Nginx"), None)
    assert nginx is not None
    assert nginx.version == "1.25.3"
    assert nginx.category == "server"


def test_scriptsrc_match():
    ev = engine.Evidence(script_src=["/assets/jquery-3.6.0.min.js"])
    assert "jQuery" in _names(engine.match(ev))


def test_meta_generator_match_and_implies():
    ev = engine.Evidence(meta={"generator": "Drupal 10 (https://www.drupal.org)"})
    names = _names(engine.match(ev))
    assert "Drupal" in names
    assert "PHP" in names, "Drupal implies PHP"


def test_dom_attribute_match_extracts_version():
    # Modern Angular: no window global, detected only via [ng-version] DOM attr.
    ev = engine.Evidence(
        dom={"[ng-version]": {"exists": True, "attributes": {"ng-version": "17.3.1"}}}
    )
    res = engine.match(ev)
    angular = next((c for c in res if c.name == "Angular"), None)
    assert angular is not None, "Angular must be detected from the ng-version DOM attribute"
    assert angular.version == "17.3.1"


def test_no_evidence_yields_nothing():
    assert engine.match(engine.Evidence()) == []


# --------------------------------------------------------------------------- #
# Detector: passive evidence assembly (no browser)
# --------------------------------------------------------------------------- #

class _Obs:
    def __init__(self, response_headers=None, request_cookies=None, response_snippet=""):
        self.response_headers = response_headers or {}
        self.request_cookies = request_cookies or {}
        self.response_snippet = response_snippet


async def test_detector_passive_from_crawl_result():
    det = TechnologyDetector()
    crawl_result = SimpleNamespace(
        spa_root_html=(
            '<html><head>'
            '<script src="/assets/jquery-3.6.0.min.js"></script>'
            '<meta name="generator" content="Drupal 10">'
            "</head><body></body></html>"
        ),
        requests=[_Obs(response_headers={"X-Powered-By": "Express", "Server": "nginx/1.25.3"})],
    )
    res = await det.detect(
        "http://target.test/", crawl_result=crawl_result, browser_available=False
    )
    names = {c.name for c in res}
    assert {"Express", "Node.js", "jQuery", "Nginx", "Drupal", "PHP"} <= names


async def test_detector_skips_browser_when_unavailable(monkeypatch):
    # Ensure the runtime pass is not attempted when browser_available=False.
    det = TechnologyDetector()
    called = {"runtime": False}

    async def _boom(*a, **k):
        called["runtime"] = True
        raise AssertionError("runtime pass must not run")

    monkeypatch.setattr(det, "_augment_with_runtime", _boom)
    crawl_result = SimpleNamespace(
        spa_root_html="<html></html>",
        requests=[_Obs(response_headers={"Server": "nginx/1.25.3"})],
    )
    res = await det.detect("http://target.test/", crawl_result=crawl_result, browser_available=False)
    assert called["runtime"] is False
    assert any(c.name == "Nginx" for c in res)


async def test_detector_output_contract():
    # Output must be TechnologyComponent(name, version, category) for CVE enrichment.
    det = TechnologyDetector()
    crawl_result = SimpleNamespace(
        spa_root_html="<html></html>",
        requests=[_Obs(response_headers={"Server": "nginx/1.25.3"})],
    )
    res = await det.detect("http://target.test/", crawl_result=crawl_result, browser_available=False)
    for c in res:
        assert hasattr(c, "name") and hasattr(c, "version") and hasattr(c, "category")
        assert hasattr(c, "cves") and hasattr(c, "cve_scores")
