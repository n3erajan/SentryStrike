"""Tests for error-response technology fingerprinting (generic, all-stacks).

Locks in the user's requirement: technology identity + version must be recovered
from stack traces / DB errors for ANY stack, not just the Juice Shop one. Also
covers the scanner merge semantics (de-dup, version back-fill, only-new CVE
enrichment).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.integrations import error_fingerprints as ef
from app.integrations.wappalyzer_engine import TechComponent
from app.core.scanner import ScanOrchestrator
from shared.models.vulnerability import TechnologyComponent


# --------------------------------------------------------------------------- #
# Signature table: generality across diverse stacks
# --------------------------------------------------------------------------- #

# label -> (error body, {expected tech names}, {name: expected version})
_CORPUS = {
    "juice-shop-real": (
        "SequelizeDatabaseError at SQLiteQueryGenerator.whereItemQuery "
        "(/juice-shop/node_modules/sequelize/lib/dialects/sqlite/query.js:185:27) "
        "SQLITE_ERROR: unrecognized token at process.processTicksAndRejections "
        "(node:internal/process/task_queues:104:5)",
        {"Sequelize", "SQLite", "Node.js"}, {},
    ),
    "django-pg": (
        'Traceback (most recent call last): File "/usr/lib/python3/site-packages/'
        'django/core/handlers/base.py", line 47 Django Version: 4.2.1 '
        "django.db.utils org.postgresql invalid input syntax for integer",
        {"Django", "Python", "PostgreSQL", "Django ORM"}, {"Django": "4.2.1"},
    ),
    "rails-mysql": (
        "ActiveRecord::StatementInvalid (Mysql2::Error: You have an error in your "
        "SQL syntax) app/controllers/users_controller.rb:14:in `show` rails (7.0.4)",
        {"Active Record", "MySQL", "Ruby", "Ruby on Rails"}, {"Ruby on Rails": "7.0.4"},
    ),
    "laravel-php": (
        "Illuminate\\Database\\QueryException Fatal error: vendor/laravel/framework/"
        "src/Illuminate/Routing/Router.php Stack trace:\n#0 Symfony\\Component\\HttpKernel",
        {"Laravel", "PHP"}, {},
    ),
    "flask": (
        'werkzeug.exceptions.NotFound File "/usr/lib/python3/site-packages/flask/'
        'app.py", line 2464 Traceback (most recent call last)',
        {"Flask", "Python"}, {},
    ),
    "spring-oracle": (
        "org.springframework.web.HttpRequestMethodNotSupportedException Whitelabel "
        "Error Page at com.app.Service(Service.java:42) ORA-01756: quoted string",
        {"Spring", "Java", "Oracle"}, {},
    ),
    "aspnet-mssql": (
        "Server Error in '/' Application. ASP.NET Version: 4.8.4515 "
        "System.Data.SqlClient.SqlException: Unclosed quotation mark",
        {"Microsoft ASP.NET", "Microsoft SQL Server"}, {"Microsoft ASP.NET": "4.8.4515"},
    ),
    "tomcat": (
        "Apache Tomcat/9.0.65 - Error report org.apache.jasper.JasperException",
        {"Apache Tomcat"}, {"Apache Tomcat": "9.0.65"},
    ),
    "go-mongo": (
        "panic: runtime error goroutine 42 [running]: main.handler /app/server.go:88 "
        "+0x1a5 MongoServerError: E11000 duplicate key",
        {"Go", "MongoDB"}, {},
    ),
    "prisma-node": (
        "PrismaClientKnownRequestError at /app/node_modules/@prisma/client/runtime "
        "node:internal/process",
        {"Prisma", "Node.js"}, {},
    ),
    "express-500": (
        "Error at Layer.handle [as handle_request] "
        "(/app/node_modules/express/lib/router/layer.js:95:5)",
        {"Express", "Node.js"}, {},
    ),
    "node-crash-banner": (
        "Error: connect ECONNREFUSED 127.0.0.1:5432\n"
        "    at TCPConnectWrap.afterConnect (node:net:1595:16)\n"
        "Node.js v18.16.0",
        {"Node.js"}, {"Node.js": "18.16.0"},
    ),
    "pnpm-express-sequelize": (
        "SequelizeDatabaseError at Query.run "
        "(/app/node_modules/.pnpm/sequelize@6.28.0/node_modules/sequelize/lib/query.js:50) "
        "at Layer.handle_request "
        "(/app/node_modules/.pnpm/express@4.18.2/node_modules/express/lib/router/layer.js:95)",
        {"Sequelize", "Express"}, {"Sequelize": "6.28.0", "Express": "4.18.2"},
    ),
    "express-error-banner": (
        "<html><head><title>Error: SQLITE_ERROR</title></head>"
        "<body><h1>OWASP Juice Shop (Express ^4.22.1)</h1>"
        "<h2><em>500</em> Error: SQLITE_ERROR: unrecognized token</h2></body></html>",
        {"Express"}, {"Express": "4.22.1"},
    ),
    "express-banner-vprefix": (
        "Internal Server Error (Express v4.18.2) - request failed",
        {"Express"}, {"Express": "4.18.2"},
    ),
}


@pytest.mark.parametrize("label", list(_CORPUS.keys()))
def test_error_fingerprint_per_stack(label):
    body, expected_names, expected_versions = _CORPUS[label]
    res = ef.match_error_evidence([body])
    got = {c.name for c in res}
    assert expected_names <= got, f"{label}: missing {expected_names - got}"
    by_name = {c.name: c.version for c in res}
    for name, ver in expected_versions.items():
        assert by_name.get(name) == ver, f"{label}: {name} version {by_name.get(name)} != {ver}"


def test_generality_breadth():
    # Every distinct stack in the corpus is detected — proves this is not
    # hardcoded to one target.
    all_detected: set[str] = set()
    for body, _, _ in _CORPUS.values():
        all_detected |= {c.name for c in ef.match_error_evidence([body])}
    assert len(all_detected) >= 15, f"expected broad coverage, got {sorted(all_detected)}"


def test_empty_and_noise_input():
    assert ef.match_error_evidence([]) == []
    assert ef.match_error_evidence(["", None]) == []  # type: ignore[list-item]
    # A benign page merely mentioning a word must not trigger (anchored markers).
    assert ef.match_error_evidence(["Welcome to our MySQL tutorial blog"]) == []


def test_signatures_all_compiled():
    assert ef.signature_count() >= 25


# --------------------------------------------------------------------------- #
# Scanner merge semantics
# --------------------------------------------------------------------------- #

class _FakeCve:
    def __init__(self):
        self.enriched_names: list[str] = []

    async def enrich_components(self, comps):
        self.enriched_names = [c.name for c in comps]
        return comps


async def test_merge_backfills_version_and_enriches_only_new():
    orch = ScanOrchestrator.__new__(ScanOrchestrator)
    orch.cve_service = _FakeCve()

    scan = SimpleNamespace(
        technology_stack=[
            TechnologyComponent(name="Node.js", version=None, category="language"),
            TechnologyComponent(name="Apache Tomcat", version=None, category="server"),
        ]
    )
    finding = SimpleNamespace(
        verification_response_snippet=(
            "SequelizeDatabaseError /app/node_modules/sequelize/lib SQLITE_ERROR "
            "Apache Tomcat/9.0.65 node:internal/process"
        ),
        evidence=None,
        detection_evidence={},
    )

    await orch._enrich_tech_from_errors(scan, [finding])

    names = {c.name for c in scan.technology_stack}
    assert {"Sequelize", "SQLite"} <= names  # newly discovered
    # Node.js was already present -> not duplicated
    assert sum(1 for c in scan.technology_stack if c.name == "Node.js") == 1
    # Tomcat existed version-less -> version back-filled from the error, not re-added
    tomcat = next(c for c in scan.technology_stack if c.name == "Apache Tomcat")
    assert tomcat.version == "9.0.65"
    assert sum(1 for c in scan.technology_stack if c.name == "Apache Tomcat") == 1
    # Only genuinely-new components were sent to CVE enrichment.
    assert "Node.js" not in orch.cve_service.enriched_names
    assert "Apache Tomcat" not in orch.cve_service.enriched_names
    assert {"Sequelize", "SQLite"} <= set(orch.cve_service.enriched_names)


async def test_merge_noop_when_no_error_text():
    orch = ScanOrchestrator.__new__(ScanOrchestrator)
    orch.cve_service = _FakeCve()
    scan = SimpleNamespace(technology_stack=[])
    finding = SimpleNamespace(verification_response_snippet=None, evidence=None, detection_evidence={})
    await orch._enrich_tech_from_errors(scan, [finding])
    assert scan.technology_stack == []
    assert orch.cve_service.enriched_names == []
