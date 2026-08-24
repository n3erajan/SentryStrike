"""Component name -> published package identity, for OSV.dev lookups.

NVD indexes software by CPE, which covers servers, languages and CMS cores well
but library releases poorly and late. Ecosystem advisory databases are the better
source for libraries: OSV.dev aggregates GitHub Security Advisories, RustSec,
PyPA and friends, resolves version ranges natively per ecosystem, and needs no
API key. Asking OSV for ``express@4.18.2`` returns CVE-2024-43796 and
CVE-2024-29041 - both of which NVD's ``keywordSearch`` missed entirely.

Mappings are written out explicitly rather than derived from
``version_probe``'s alias tables. Those tables are many-to-one in the wrong
direction (both ``prisma`` and ``@prisma/client`` collapse to "Prisma"), so
inverting them would pick an arbitrary package name - and the wrong package name
means the wrong CVEs, which is the bug class this whole module exists to close.
"""

# Canonical component name (lowercased) -> (OSV ecosystem, package name).
# The package is the *published artifact* advisories are filed against, which for
# scoped npm packages is not the brand name: Angular advisories live under
# ``@angular/core``, not ``angular``.
#
# INVARIANT: every package name here must exist in its registry. OSV answers an
# unknown package with an empty result, which the orchestrator would faithfully
# report as "assessed, no vulnerabilities" - a false clean, the exact failure mode
# this module exists to prevent. Before adding an entry, confirm it resolves:
#   npm       https://registry.npmjs.org/<pkg>
#   PyPI      https://pypi.org/pypi/<pkg>/json
#   Packagist https://repo.packagist.org/p2/<vendor>/<pkg>.json
#   RubyGems  https://rubygems.org/api/v1/gems/<pkg>.json
_OSV_PACKAGES: dict[str, tuple[str, str]] = {
    # --- npm ---------------------------------------------------------------- #
    "express": ("npm", "express"),
    "koa": ("npm", "koa"),
    "fastify": ("npm", "fastify"),
    "nest.js": ("npm", "@nestjs/core"),
    "next.js": ("npm", "next"),
    "nuxt.js": ("npm", "nuxt"),
    "react": ("npm", "react"),
    "vue.js": ("npm", "vue"),
    "angular": ("npm", "@angular/core"),
    "angularjs": ("npm", "angular"),
    "socket.io": ("npm", "socket.io"),
    "sequelize": ("npm", "sequelize"),
    "typeorm": ("npm", "typeorm"),
    "prisma": ("npm", "@prisma/client"),
    "mongoose": ("npm", "mongoose"),
    "lodash": ("npm", "lodash"),
    "axios": ("npm", "axios"),
    "jquery": ("npm", "jquery"),
    "jquery ui": ("npm", "jquery-ui"),
    "jquery migrate": ("npm", "jquery-migrate"),
    "bootstrap": ("npm", "bootstrap"),
    "moment.js": ("npm", "moment"),
    "handlebars": ("npm", "handlebars"),
    "underscore.js": ("npm", "underscore"),
    "d3": ("npm", "d3"),
    "webpack": ("npm", "webpack"),
    # --- Packagist (PHP) ---------------------------------------------------- #
    "laravel": ("Packagist", "laravel/framework"),
    "symfony": ("Packagist", "symfony/symfony"),
    "slim": ("Packagist", "slim/slim"),
    "yii": ("Packagist", "yiisoft/yii2"),
    "cakephp": ("Packagist", "cakephp/cakephp"),
    "doctrine": ("Packagist", "doctrine/orm"),
    "twig": ("Packagist", "twig/twig"),
    "guzzle": ("Packagist", "guzzlehttp/guzzle"),
    # --- PyPI --------------------------------------------------------------- #
    "django": ("PyPI", "django"),
    "flask": ("PyPI", "flask"),
    "fastapi": ("PyPI", "fastapi"),
    "tornado": ("PyPI", "tornado"),
    "sqlalchemy": ("PyPI", "sqlalchemy"),
    "pyramid": ("PyPI", "pyramid"),
    "bottle": ("PyPI", "bottle"),
    "werkzeug": ("PyPI", "werkzeug"),
    "gunicorn": ("PyPI", "gunicorn"),
    "jinja": ("PyPI", "jinja2"),
    # --- RubyGems ----------------------------------------------------------- #
    "ruby on rails": ("RubyGems", "rails"),
    "rack": ("RubyGems", "rack"),
    "sinatra": ("RubyGems", "sinatra"),
    "active record": ("RubyGems", "activerecord"),
    "puma": ("RubyGems", "puma"),
    "unicorn": ("RubyGems", "unicorn"),
    "passenger": ("RubyGems", "passenger"),
}


def osv_package(name: str) -> tuple[str, str] | None:
    """Return ``(ecosystem, package)`` for a component, or None if it isn't one.

    None is a real answer, not a failure: servers (Nginx), languages (PHP) and
    CMS cores (WordPress) are not ecosystem packages and must route to NVD's CPE
    index instead. Fabricating a package name for them would query unrelated
    software and attach its CVEs.
    """
    if not name:
        return None
    return _OSV_PACKAGES.get(name.strip().lower())
