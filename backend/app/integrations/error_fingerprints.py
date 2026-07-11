"""Technology fingerprinting from error responses / stack traces.

Complements the Wappalyzer-schema engine (:mod:`app.integrations.wappalyzer_engine`),
which fingerprints *normal* page markup + runtime globals. That engine matches
almost nothing against stack traces and framework error pages — yet those are the
single richest technology surface an app exposes: they leak the framework, ORM,
database engine, language/runtime, and frequently a version, none of which need a
version header.

This module is a curated, **stack-agnostic** signature table. Each signature
encodes a universal property of a *technology* (e.g. "Sequelize, in any app,
emits ``node_modules/sequelize`` and ``Sequelize<X>Error``") — never a property
of any particular target. It is the same technique DB-error fingerprinters (e.g.
sqlmap) use, broadened across ORMs, languages, frameworks, and servers.

The scanner already *triggers* these errors (the exception-handling detector and
the SQLi verifier) and stores the bodies on findings; this module turns that
already-collected evidence into named ``TechComponent`` identities + versions.
"""

from __future__ import annotations

import logging
import re

from app.integrations.wappalyzer_engine import TechComponent

logger = logging.getLogger(__name__)


class _Sig:
    """A single error-surface signature.

    ``pattern``  — regex (compiled case-insensitively) matched against error text.
    ``name``     — technology name (aligned with Wappalyzer names where possible so
                   downstream CVE lookups and de-dup are consistent).
    ``category`` — normalized category string (matches engine categories).
    ``version_group`` — regex group index holding the version, if the marker
                   carries one; else ``None``.
    """

    __slots__ = ("pattern", "name", "category", "version_group")

    def __init__(self, pattern: str, name: str, category: str, version_group: int | None = None):
        self.pattern = pattern
        self.name = name
        self.category = category
        self.version_group = version_group


# --------------------------------------------------------------------------- #
# Signature table — grouped by layer for auditability. Anchored to unambiguous
# error-class names / module paths / framework markers to minimise false
# positives (an app merely echoing the word "mysql" must NOT match).
# --------------------------------------------------------------------------- #

_SIGNATURES: list[_Sig] = [
    # ---- Databases (from SQL/driver error text) ----
    _Sig(r"SQLITE_ERROR|SQLITE_CONSTRAINT|sqlite3\.(?:Operational|Integrity|Database)Error", "SQLite", "database"),
    _Sig(r"You have an error in your SQL syntax|check the manual that corresponds to your (?:MySQL|MariaDB)", "MySQL", "database"),
    _Sig(r"com\.mysql\.(?:jdbc|cj)|MySQLSyntaxErrorException|MySQLIntegrityConstraintViolationException", "MySQL", "database"),
    _Sig(r"\bMariaDB\b(?:[^\d]{0,20}([0-9]+\.[0-9][0-9.]*))?", "MariaDB", "database", 1),
    _Sig(r"PG::(?:Syntax|Undefined|Unique|Connection|Program)|org\.postgresql\.util\.PSQLException|invalid input syntax for", "PostgreSQL", "database"),
    _Sig(r"System\.Data\.SqlClient\.SqlException|Unclosed quotation mark after the character string|Microsoft SQL Server", "Microsoft SQL Server", "database"),
    _Sig(r"\bORA-[0-9]{5}\b|oracle\.jdbc\.|quoted string not properly terminated", "Oracle", "database"),
    _Sig(r"MongoError|MongoServerError|E11000 duplicate key|BSONError|com\.mongodb", "MongoDB", "database"),

    # ---- ORMs / data-access layers (from stack file paths + error classes) ----
    _Sig(r"node_modules[/\\]sequelize|Sequelize(?:Database|Validation|UniqueConstraint|Foreign|Connection)?Error", "Sequelize", "orm"),
    _Sig(r"node_modules[/\\]typeorm|TypeORMError|QueryFailedError", "TypeORM", "orm"),
    _Sig(r"node_modules[/\\]@prisma|PrismaClient(?:Known|Unknown|Validation)?RequestError", "Prisma", "orm"),
    _Sig(r"node_modules[/\\]mongoose|MongooseError|ValidatorError", "Mongoose", "orm"),
    _Sig(r"org\.hibernate\.|HibernateException|LazyInitializationException", "Hibernate", "orm"),
    _Sig(r"sqlalchemy\.exc\.|site-packages[/\\]sqlalchemy", "SQLAlchemy", "orm"),
    _Sig(r"django\.db\.(?:utils|models)|django\.core\.exceptions\.(?:ObjectDoesNotExist|ValidationError)", "Django ORM", "orm"),
    _Sig(r"ActiveRecord::(?:RecordNotFound|StatementInvalid|RecordInvalid)", "Active Record", "orm"),
    _Sig(r"Illuminate\\\\Database|Eloquent(?:\\\\|\.)ModelNotFoundException", "Eloquent", "orm"),

    # ---- Languages / runtimes (from stack-frame grammar) ----
    _Sig(r"node:internal[/\\]|\bat process\.processTicksAndRejections\b|node_modules[/\\]", "Node.js", "language"),
    _Sig(r"Traceback \(most recent call last\)|site-packages[/\\]|File \"[^\"]+\", line \d+, in ", "Python", "language"),
    _Sig(r"\bat [\w.$]+\([\w.$]+\.java:\d+\)|Exception in thread \"|\bjava\.lang\.[A-Z]\w+Exception", "Java", "language"),
    _Sig(r"Fatal error:|Parse error:|\bStack trace:\n?#0|[/\\]vendor[/\\]composer[/\\]", "PHP", "language"),
    _Sig(r"\.rb:\d+:in [`']|[/\\]gems[/\\]|from [\w./-]+\.rb:\d+", "Ruby", "language"),
    _Sig(r"System\.[A-Z]\w+Exception:|\bat [\w.<>]+\(\)(?: in [^\n]+:line \d+)|Microsoft\.AspNetCore", "Microsoft ASP.NET", "framework"),
    _Sig(r"\bgoroutine \d+ \[|\b[\w./-]+\.go:\d+ \+0x|panic: ", "Go", "language"),

    # ---- Web frameworks (from error markup / trace signatures) ----
    _Sig(r"node_modules[/\\]express[/\\]lib|at Layer\.handle \[as handle_request\]|at (?:Route|Router)\.(?:dispatch|handle)", "Express", "framework"),
    _Sig(r"Django Version:\s*([0-9]+\.[0-9][0-9.]*)", "Django", "framework", 1),
    _Sig(r"You're seeing this error because you have <code>DEBUG = True|django\.core\.handlers", "Django", "framework"),
    _Sig(r"\brails \(([0-9]+\.[0-9][0-9.]*)\)", "Ruby on Rails", "framework", 1),
    _Sig(r"ActionController::|ActionDispatch::", "Ruby on Rails", "framework"),
    _Sig(r"laravel[/\\]framework|Whoops\\\\|Illuminate\\\\Foundation", "Laravel", "framework"),
    _Sig(r"werkzeug\.exceptions|site-packages[/\\]flask[/\\]|flask[/\\]app\.py", "Flask", "framework"),
    _Sig(r"org\.springframework\.|Whitelabel Error Page|SpringApplication", "Spring", "framework"),
    _Sig(r"ASP\.NET Version:\s*([0-9]+\.[0-9][0-9.]*)", "Microsoft ASP.NET", "framework", 1),
    _Sig(r"Server Error in '/' Application", "Microsoft ASP.NET", "framework"),
    _Sig(r"Symfony\\\\Component|vendor[/\\]symfony[/\\]", "Symfony", "framework"),
    _Sig(r"Apache Tomcat/([0-9]+\.[0-9][0-9.]*)", "Apache Tomcat", "server", 1),
    _Sig(r"org\.apache\.catalina|org\.apache\.jasper", "Apache Tomcat", "server"),
    _Sig(r"Ruby version|Rack::|[/\\]rack[/\\]", "Rack", "framework"),
]


def _compile(sig: _Sig) -> tuple[re.Pattern, _Sig] | None:
    try:
        return re.compile(sig.pattern, re.IGNORECASE), sig
    except re.error:
        logger.debug("error_fingerprints: skipping bad regex for %s", sig.name)
        return None


_COMPILED: list[tuple[re.Pattern, _Sig]] = [c for c in (_compile(s) for s in _SIGNATURES) if c]


def match_error_evidence(texts: list[str]) -> list[TechComponent]:
    """Fingerprint technologies from error/stack-trace text.

    Accepts any collection of error-ish strings (finding snippets, evidence,
    detection metadata). Returns one ``TechComponent`` per distinct technology,
    with a version when a signature captured one. Confidence is fixed high
    because these markers are strong, unambiguous identifiers.
    """
    detected: dict[str, TechComponent] = {}
    for text in texts:
        if not text:
            continue
        for pattern, sig in _COMPILED:
            m = pattern.search(text)
            if not m:
                continue
            version: str | None = None
            if sig.version_group is not None:
                try:
                    version = m.group(sig.version_group)
                except (IndexError, re.error):
                    version = None
            existing = detected.get(sig.name)
            if existing is None:
                detected[sig.name] = TechComponent(
                    name=sig.name, version=version, category=sig.category, confidence=100
                )
            elif version and not existing.version:
                existing.version = version
    return list(detected.values())


def signature_count() -> int:
    """Number of compiled signatures — for diagnostics/tests."""
    return len(_COMPILED)
