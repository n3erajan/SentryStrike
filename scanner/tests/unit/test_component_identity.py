"""Component identity: CPE for NVD lookups, ecosystem package for OSV lookups.

Neither lookup may guess. A CVE query keyed on a display name is how "PHP" ends
up carrying TYPO3's CVE-2021-41113 and "HTTP/3" carries the H2O server's
CVE-2021-43848 - both real entries from a production report. A component we
cannot identify is reported as unassessed instead.
"""

from app.integrations.package_identity import osv_package
from app.integrations.wappalyzer_engine import cpe_for


# --------------------------------------------------------------------------- #
# CPE lookup (NVD path)
# --------------------------------------------------------------------------- #

def test_cpe_for_returns_the_vendor_pinned_cpe_from_the_fingerprint_db() -> None:
    assert cpe_for("Nginx") == "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"
    assert cpe_for("WordPress") == "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*"
    assert cpe_for("PHP") == "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"
    assert cpe_for("Express") == "cpe:2.3:a:expressjs:express:*:*:*:*:*:*:*:*"


def test_cpe_for_is_case_insensitive() -> None:
    """Names reach us from three sources with inconsistent casing."""
    assert cpe_for("nginx") == cpe_for("Nginx")
    assert cpe_for("GUNICORN") == "cpe:2.3:a:gunicorn:gunicorn:*:*:*:*:*:*:*:*"


def test_cpe_for_resolves_canonical_names_that_differ_from_db_keys() -> None:
    """``version_probe`` emits "Apache" from a Server header; the DB key is longer."""
    assert cpe_for("Apache") == "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"


def test_cpe_for_returns_none_when_the_db_has_no_cpe() -> None:
    # Present in the fingerprint DB but with no CPE recorded.
    assert cpe_for("jQuery Migrate") is None
    assert cpe_for("Smart Slider 3") is None


def test_cpe_for_returns_none_for_unknown_technologies() -> None:
    assert cpe_for("Totally Made Up Tech 9000") is None
    assert cpe_for("") is None


# --------------------------------------------------------------------------- #
# Ecosystem package lookup (OSV path)
# --------------------------------------------------------------------------- #

def test_osv_package_maps_components_to_their_published_package() -> None:
    assert osv_package("Express") == ("npm", "express")
    assert osv_package("jQuery") == ("npm", "jquery")
    assert osv_package("Laravel") == ("Packagist", "laravel/framework")
    assert osv_package("Django") == ("PyPI", "django")
    assert osv_package("Ruby on Rails") == ("RubyGems", "rails")


def test_osv_package_uses_the_scoped_package_that_carries_advisories() -> None:
    """Advisories are filed against the published artifact, not the brand name."""
    assert osv_package("Angular") == ("npm", "@angular/core")
    assert osv_package("Prisma") == ("npm", "@prisma/client")
    assert osv_package("Nest.js") == ("npm", "@nestjs/core")


def test_osv_package_is_case_insensitive() -> None:
    assert osv_package("express") == osv_package("Express")


def test_osv_package_returns_none_for_things_that_are_not_packages() -> None:
    """Servers, languages and CMS cores are not ecosystem packages.

    They have to route to NVD's CPE index instead; inventing a package name for
    them would silently query the wrong software.
    """
    assert osv_package("Nginx") is None
    assert osv_package("PHP") is None
    assert osv_package("WordPress") is None
    assert osv_package("LiteSpeed") is None
    assert osv_package("Unknown Thing") is None


def test_every_mapped_package_names_a_real_osv_ecosystem() -> None:
    from app.integrations.package_identity import _OSV_PACKAGES

    valid = {"npm", "PyPI", "Packagist", "RubyGems", "Go", "Maven", "NuGet", "crates.io", "Hex"}
    for component, (ecosystem, package) in _OSV_PACKAGES.items():
        assert ecosystem in valid, f"{component} -> unknown ecosystem {ecosystem!r}"
        assert package and package == package.strip()
