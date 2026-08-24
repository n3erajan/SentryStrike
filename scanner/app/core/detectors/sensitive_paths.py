import asyncio
import logging
import math
import re
from collections import Counter
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import httpx

from app.config import get_settings
from app.core.crawler.spa import SpaFallbackDetector
from app.core.detectors.base_detector import BaseDetector, Finding
from shared.models.vulnerability import OwaspCategory, SeverityLevel
from app.utils.http_logging import make_httpx_response_logger
from app.utils.scan_http import (
    build_httpx_evidence_snippets,
    build_observed_request_snippet,
    create_scan_client,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ContentMatch:
    """One content classification, carrying the exact text that triggered it.

    A regex hit is only as trustworthy as the substring it captured, but that
    substring used to be discarded the moment the branch returned. Every
    consumer downstream then re-derived "what was the proof?" independently:
    the snippet builder guessed with its own marker lists, and the AI
    adjudicator was handed a window that need not contain the match at all -
    so it judged pattern-match findings without ever seeing the pattern's
    output. Capturing the span once, here, is what makes those findings
    adjudicable.

    ``matched_text`` is empty for structural classifications (an autoindex, a
    known filename) where the proof is the response's shape rather than a
    captured substring.
    """

    matched: bool
    vuln_type: str = ""
    evidence: str = ""
    severity: SeverityLevel = SeverityLevel.low
    matched_text: str = ""
    match_offset: int = -1
    match_location: str = ""

    def __bool__(self) -> bool:
        return self.matched


_NO_MATCH = ContentMatch(matched=False)


class SensitivePathsDetector(BaseDetector):
    name = "sensitive_paths"

    _common_sensitive_paths = [
        "/.git/config",
        "/.git/HEAD",
        "/.git/index",
        "/.env",
        "/.env.local",
        "/.env.production",
        "/.env.development",
        "/.env.example",
        "/.env.backup",
        "/.svn/entries",
        "/.hg/requires",
        "/.htaccess",
        "/.DS_Store",
        "/phpinfo.php",
        "/info.php",
        "/config.json",
        "/config.yaml",
        "/config.yml",
        "/settings.py",
        "/local_settings.py",
        "/appsettings.json",
        "/appsettings.Development.json",
        # Ecosystem-standard dependency manifests / lockfiles.
        "/package.json",
        "/package-lock.json",
        "/yarn.lock",
        "/pnpm-lock.yaml",
        "/composer.json",
        "/composer.lock",
        "/Gemfile.lock",
        "/requirements.txt",
        "/Pipfile.lock",
        "/poetry.lock",
        "/backup.sql",
        "/database.sql",
        "/dump.sql",
        "/backup.zip",
        "/backup.tar.gz",
        "/db.sql",
        "/db.sqlite",
        "/database.sqlite",
        "/wp-config.php.bak",
        "/config.php.bak",
        "/.bash_history",
        "/.ssh/id_rsa",
        "/admin",
        "/backup",
        "/backups",
        "/data",
        "/files",
        "/ftp",
        "/server-status",
        "/WEB-INF/web.xml",
        "/Dockerfile",
        "/docker-compose.yml",
        # Debug / Metrics / Actuator endpoints
        "/debug",
        "/debug/vars",
        "/metrics",
        "/actuator",
        "/actuator/env",
        "/actuator/metrics",
        "/actuator/health",
        "/actuator/prometheus",
        "/__debug__",
        "/swagger.json",
        "/swagger/v1/swagger.json",
        "/openapi.json",
        "/api-docs",
        "/v3/api-docs",
        "/graphql",
        "/graphiql",
        "/sitemap.xml",
        "/app.js.map",
        "/main.js.map",
        "/bundle.js.map",
    ]

    _DEBUG_METRICS_PATTERNS: list[re.Pattern] = [
        re.compile(p, re.IGNORECASE)
        for p in [
            r"^#\s*HELP\s+\w+",
            r"^#\s*TYPE\s+\w+",
            r"jvm_memory_used_bytes|process_cpu_seconds_total|http_server_requests",
            r"\"activeProfiles\"|\"propertySources\"|\"systemProperties\"",
            r"\"heapUsed\"|\"rss\"|\"uptime\"|\"pid\"",
            r"debug\s*=\s*true|app_debug|environment\s*:\s*(dev|debug|local)",
            r"phpinfo\(\)|configuration file \(php\.ini\) path",
            r"apache server status|\bserver-status\b|\bscoreboard\b",
        ]
    ]

    _STACK_TRACE_PATTERNS: list[re.Pattern] = [
        re.compile(p, re.IGNORECASE)
        for p in [
            r"Traceback \(most recent call last\)",
            r"at\s+[A-Za-z0-9_$.[\]<>]+\([^)]*\.js:\d+:\d+\)",
            r"Exception in thread|java\.lang\.[A-Za-z]+Exception",
            r"System\.[A-Za-z]+Exception",
            r"Stack trace:",
            r"SQLSTATE\[[A-Z0-9]+\]|PDOException|Sequelize(Database)?Error",
        ]
    ]

    _SECRET_PATTERNS: list[re.Pattern] = [
        re.compile(p, re.IGNORECASE)
        for p in [
            r"['\"]?\b(?:api[_-]?key|secret|secret[_-]?key|client[_-]?secret|private[_-]?key)\b['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9_\-./+=]{8,}",
            # The value class is defined by exclusion, so angle brackets must be
            # excluded explicitly: without them a visible form label followed by
            # markup (``Password:<br><input``) satisfies "8+ value characters"
            # and every login page reports a leaked credential.
            r"['\"]?\b(?:password|passwd|db_password|database_password)\b['\"]?\s*[:=]\s*['\"]?[^'\"\s,;}{<>]{8,}",
            r"['\"]?\b(?:access[_-]?token|refresh[_-]?token|id[_-]?token|jwt)\b['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        ]
    ]

    # Longest matched span quoted into evidence and forwarded to the adjudicator.
    _MAX_MATCHED_TEXT_CHARS: int = 200

    @staticmethod
    def _first_pattern_match(patterns: list[re.Pattern], body: str) -> re.Match | None:
        """First hit across ``patterns``, preserving their declared priority."""
        for pattern in patterns:
            match = pattern.search(body)
            if match:
                return match
        return None

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        """Bits per character - separates real secrets from prose and markup.

        A high-entropy token looks like a key; ``Password:<br><input`` and
        ``YOUR_API_KEY_HERE`` do not. The adjudicator weighs this alongside the
        span itself.
        """
        if not text:
            return 0.0
        total = len(text)
        counts = Counter(text)
        return round(
            -sum((n / total) * math.log2(n / total) for n in counts.values()), 2
        )

    @staticmethod
    def _match_location(body: str, offset: int, matched_text: str) -> str:
        """Where a match sits, which often decides whether it is real.

        A key inside a ``<pre>``/``<code>`` block is usually documentation; one
        inside form markup is usually a field label, not a value.
        """
        if offset < 0:
            return ""
        if re.search(r"<(?:input|form|label|br|td|th)\b", matched_text, re.IGNORECASE):
            return "form_markup"
        before = body[:offset].lower()
        for opener, closer, name in (
            ("<code", "</code>", "code_block"),
            ("<pre", "</pre>", "code_block"),
            ("<script", "</script>", "script"),
            ("<!--", "-->", "comment"),
        ):
            start = before.rfind(opener)
            if start >= 0 and before.rfind(closer, start) < 0:
                return name
        if re.search(r"<[a-z/][^>]*>", matched_text, re.IGNORECASE):
            return "html_markup"
        return "body_text"

    @classmethod
    def _from_pattern(
        cls,
        match: re.Match,
        body: str,
        vuln_type: str,
        evidence: str,
        severity: SeverityLevel,
    ) -> ContentMatch:
        """Build a ContentMatch that carries the span the pattern captured."""
        matched_text = (match.group(0) or "")[: cls._MAX_MATCHED_TEXT_CHARS]
        return ContentMatch(
            matched=True,
            vuln_type=vuln_type,
            evidence=evidence,
            severity=severity,
            matched_text=matched_text,
            match_offset=match.start(),
            match_location=cls._match_location(body, match.start(), matched_text),
        )


    _SOURCE_MAP_PATTERNS: list[re.Pattern] = [
        re.compile(r'"version"\s*:\s*3', re.IGNORECASE),
        re.compile(r'"sources"\s*:\s*\[', re.IGNORECASE),
        re.compile(r'"mappings"\s*:\s*"', re.IGNORECASE),
        re.compile(r"sourceMappingURL=.*\.map", re.IGNORECASE),
    ]

    _API_DOC_PATTERNS: list[re.Pattern] = [
        re.compile(r'"openapi"\s*:\s*"3\.', re.IGNORECASE),
        re.compile(r'"swagger"\s*:\s*"2\.0"', re.IGNORECASE),
        re.compile(r'"paths"\s*:\s*\{', re.IGNORECASE),
        re.compile(r"Swagger UI|OpenAPI|api-docs", re.IGNORECASE),
        re.compile(r"__schema|IntrospectionQuery|GraphQL", re.IGNORECASE),
    ]

    _DEPENDENCY_MANIFEST_PATTERNS: list[re.Pattern] = [
        re.compile(r'"dependencies"\s*:\s*\{|\"devDependencies\"\s*:\s*\{', re.IGNORECASE),
        re.compile(r'"packages"\s*:\s*\[|\"packages-dev\"\s*:\s*\[', re.IGNORECASE),
        re.compile(r"^\s{4}[A-Za-z0-9_.-]+\s+\([0-9][^)]+\)", re.IGNORECASE | re.MULTILINE),
        re.compile(r"^[A-Za-z0-9_.-]+(?:==|>=|~=|<=)[0-9]", re.IGNORECASE | re.MULTILINE),
        re.compile(r"^# This file is automatically generated by (?:npm|yarn|pnpm|Bundler|Poetry)", re.IGNORECASE | re.MULTILINE),
    ]

    # Generic autoindex/directory-listing signatures across common servers.
    _AUTOINDEX_PATTERNS: list[re.Pattern] = [
        re.compile(r"<title>\s*Index of /", re.IGNORECASE),        # Apache/nginx
        re.compile(r"<h1>\s*Index of /", re.IGNORECASE),           # Apache/nginx
        re.compile(r"Directory listing for ", re.IGNORECASE),      # Python http.server, Tornado
        re.compile(r"\[To Parent Directory\]", re.IGNORECASE),     # IIS
        re.compile(r'<a href="\?C=[NMSD];O=[AD]"', re.IGNORECASE), # Apache column-sort links
    ]

    # Backup/temp permutations appended to discovered files.
    _BACKUP_SUFFIXES: tuple[str, ...] = (".bak", ".old", ".orig", "~", ".swp", ".save", ".zip", ".tar.gz")

    # Version-control metadata directories. Serving one over HTTP discloses the
    # full source tree and commit history, so it is classified ahead of the
    # generic autoindex branch rather than being reported as a plain listing.
    # Matched as an exact path SEGMENT: `/docs/.git-tutorial/` is an ordinary
    # directory that merely starts with the same letters.
    _VCS_DIR_NAMES: frozenset[str] = frozenset({".git", ".svn", ".hg"})

    # Repository entries that prove an autoindex really is version-control
    # storage. Matched against the listing's own hrefs (never the raw body, so
    # an HTML `<head>` cannot be mistaken for git's `HEAD`), and at least two
    # must appear, so a directory that merely happens to sit under a `.git/`
    # path cannot trip the escalation on its name alone.
    _VCS_STRUCTURE_MARKERS: frozenset[str] = frozenset({
        "objects", "refs", "head", "logs", "branches", "hooks",
        "config", "description", "index", "info", "packed-refs", "pack",
    })

    # Finding types derived from an autoindex body. One enabled autoindex yields
    # a listing for every directory the crawler subsequently walks into, so
    # these collapse to their shallowest exposed ancestor.
    _VCS_VULN_TYPE: str = "Version Control Repository Exposed"
    _LISTING_VULN_TYPES: frozenset[str] = frozenset({
        "Directory Listing Exposed",
        _VCS_VULN_TYPE,
    })

    @classmethod
    def _has_vcs_path_segment(cls, path: str) -> bool:
        """True when any path segment is exactly a VCS metadata directory."""
        return any(
            segment.lower() in cls._VCS_DIR_NAMES
            for segment in (path or "").split("/")
        )

    # Folded descendant paths quoted verbatim in the surviving finding's
    # evidence; the remainder is summarized as a count.
    _MAX_FOLDED_PATHS_SHOWN: int = 12

    @staticmethod
    def _listing_entry_names(body: str) -> set[str]:
        """Last path segment of every anchor href in a listing, lowercased."""
        names: set[str] = set()
        for href in re.findall(r'<a\s+[^>]*href=["\']?([^"\'>\s]+)', body, re.IGNORECASE):
            name = (href or "").strip().rstrip("/")
            if not name or name.startswith("?"):
                continue
            names.add(name.rsplit("/", 1)[-1].lower())
        return names

    def _looks_like_vcs_repository(self, path: str, body: str, content_type: str = "") -> bool:
        """True when an autoindex response is version-control storage.

        Demands an exact VCS path segment AND structural proof from the listing
        itself, so the escalation rests on observed repository contents rather
        than on a directory's name. A partial listing that clears the path test
        but not the marker test still escalates its tree: proof found in any
        descendant is promoted to the tree root during collapse.
        """
        if not self._has_vcs_path_segment(path):
            return False
        if not self._looks_like_autoindex(body, content_type):
            return False
        entries = self._listing_entry_names(body)
        return len(entries & self._VCS_STRUCTURE_MARKERS) >= 2

    def _looks_like_autoindex(self, body: str, content_type: str = "") -> bool:
        if content_type and not any(tok in content_type.lower() for tok in ("html", "text/plain")):
            return False
        if any(pattern.search(body) for pattern in self._AUTOINDEX_PATTERNS):
            return True
        # Generic heuristic: a page that is predominantly a list of anchor links
        # including an explicit parent-directory link is almost certainly a
        # directory index rather than an application page.
        hrefs = re.findall(r'<a\s+[^>]*href=["\']?([^"\'>\s]+)', body, re.IGNORECASE)
        if len(hrefs) >= 5 and any(h in ("../", "..") or h.rstrip("/").endswith("..") for h in hrefs):
            return True
        return False

    def _classify_content(self, path: str, body: str, content_type: str = "") -> ContentMatch:
        body_lower = body.lower()
        path_lower = path.lower()

        def structural(vuln_type: str, evidence: str, severity: SeverityLevel) -> ContentMatch:
            """Proof is the response's shape, so there is no captured span."""
            return ContentMatch(
                matched=True, vuln_type=vuln_type, evidence=evidence, severity=severity
            )

        if self._looks_like_vcs_repository(path, body, content_type):
            return structural(
                "Version Control Repository Exposed",
                "Version-control directory served over HTTP: the autoindex lists repository "
                "internals, so the full source tree and commit history are retrievable.",
                SeverityLevel.high,
            )
        if self._looks_like_autoindex(body, content_type):
            return structural("Directory Listing Exposed", "Directory listing/autoindex response exposes sibling file and directory names.", SeverityLevel.medium)
        if ".git/config" in path_lower and "[core]" in body_lower:
            return structural("Sensitive File Exposure", "Git configuration file exposed.", SeverityLevel.high)
        if ".htaccess" in path_lower and any(
            directive in body_lower
            for directive in ("rewriteengine", "rewriterule", "authtype", "require ",
                              "order ", "deny from", "allow from", "options ",
                              "<files", "<directory", "addhandler", "sethandler")
        ):
            return structural("Sensitive File Exposure", "Apache .htaccess configuration file exposed.", SeverityLevel.medium)
        if ".env" in path_lower:
            env_match = self._first_pattern_match(self._SECRET_PATTERNS, body) or re.search(
                r"\b(?:db_password|database_password|app_key|secret)\b\s*=", body, re.I
            )
            if env_match:
                return self._from_pattern(
                    env_match, body,
                    "Sensitive File Exposure",
                    "Environment file with secret-like values exposed.",
                    SeverityLevel.high,
                )
        if "phpinfo" in path_lower and "<title>phpinfo()</title>" in body_lower:
            return structural("Debug / Metrics Endpoint Exposed", "PHP configuration details (phpinfo) exposed.", SeverityLevel.medium)
        if (".sql" in path_lower or "backup" in path_lower or "dump" in path_lower) and (
            "insert into" in body_lower or "create table" in body_lower or "mysqldump" in body_lower
        ):
            return structural("Backup / Database Dump Exposed", "Database dump or backup content exposed.", SeverityLevel.high)
        if (path_lower.endswith((".zip", ".tar", ".tar.gz", ".tgz", ".bak", ".old", ".orig", ".swp", ".save", "~")) or "backup" in path_lower) and len(body) > 0:
            if "application" in content_type.lower() or "octet-stream" in content_type.lower() or "<html" not in body_lower:
                return structural("Backup / Archive File Exposed", "Backup/archive-like file content is reachable.", SeverityLevel.high)
        if ("docker" in path_lower or path_lower.endswith((".yml", ".yaml"))) and (
            "services:" in body_lower or "image:" in body_lower or "version:" in body_lower
        ):
            return structural("Sensitive File Exposure", "Docker or YAML configuration file exposed.", SeverityLevel.medium)
        if "web.xml" in path_lower and "<web-app" in body_lower:
            return structural("Sensitive File Exposure", "Java web.xml configuration file exposed.", SeverityLevel.medium)
        if self._looks_like_source_map(path, body, content_type):
            return structural("Exposed Source Map", "JavaScript source map content is reachable.", SeverityLevel.info)
        if self._looks_like_api_docs(path, body, content_type):
            # Reachable API documentation is often intentional. Promote it only
            # when separate evidence proves sensitive disclosure or unauthorized
            # access; reachability alone is an informational posture observation.
            return structural("Exposed API Documentation", "OpenAPI/Swagger/GraphQL documentation content is reachable.", SeverityLevel.info)
        if self._looks_like_dependency_manifest(path, body, content_type):
            return structural("Sensitive File Exposure", "Dependency manifest or lockfile content is reachable.", SeverityLevel.info)
        if (match := self._first_pattern_match(self._DEBUG_METRICS_PATTERNS, body)):
            return self._from_pattern(match, body, "Debug / Metrics Endpoint Exposed", "Debug, metrics, or actuator content exposed.", SeverityLevel.medium)
        if (match := self._first_pattern_match(self._STACK_TRACE_PATTERNS, body)):
            return self._from_pattern(match, body, "Verbose Stack Trace Exposure", "Verbose exception stack trace exposed.", SeverityLevel.medium)
        if (match := self._first_pattern_match(self._SECRET_PATTERNS, body)):
            return self._from_pattern(match, body, "Secret-Like Value Exposure", "Secret-like key, token, or credential value exposed.", SeverityLevel.high)

        return _NO_MATCH

    def _looks_like_source_map(self, path: str, body: str, content_type: str = "") -> bool:
        path_lower = path.lower()
        if path_lower.endswith(".map") and sum(1 for pattern in self._SOURCE_MAP_PATTERNS if pattern.search(body)) >= 2:
            return True
        if "application/json" in content_type.lower() and sum(1 for pattern in self._SOURCE_MAP_PATTERNS if pattern.search(body)) >= 3:
            return True
        return False

    def _looks_like_api_docs(self, path: str, body: str, content_type: str = "") -> bool:
        path_lower = path.lower()
        if any(token in path_lower for token in ("swagger", "openapi", "api-docs", "graphql", "graphiql")):
            return any(pattern.search(body) for pattern in self._API_DOC_PATTERNS)
        if "application/json" in content_type.lower():
            return sum(1 for pattern in self._API_DOC_PATTERNS if pattern.search(body)) >= 2
        return False

    def _looks_like_dependency_manifest(self, path: str, body: str, content_type: str = "") -> bool:
        path_lower = path.lower()
        manifest_names = (
            "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
            "composer.json", "composer.lock", "gemfile.lock", "requirements.txt",
            "pipfile.lock", "poetry.lock",
        )
        # Strip a trailing backup/temp/version suffix so a manifest exposed as a
        # backup (``package.json.bak``, ``composer.lock.old``, ``package.json~``,
        # ``requirements.txt.1``) still matches. These suffixes are universal
        # file-management conventions, not app-specific paths, and the body
        # patterns below still gate the decision on real manifest content.
        stem = path_lower.rstrip("~")
        stem = re.sub(r"\.(bak|old|orig|save|copy|swp|tmp|temp|\d+)$", "", stem)
        if not stem.endswith(manifest_names):
            return False
        return any(pattern.search(body) for pattern in self._DEPENDENCY_MANIFEST_PATTERNS)

    def _finding(
        self,
        *,
        vuln_type: str,
        severity: SeverityLevel,
        url: str,
        evidence: str,
        detection_method: str,
        proof_type: str,
        response_snippet: str | None = None,
        request_snippet: str | None = None,
        confidence_score: float = 90.0,
        anonymous_access: bool | None = None,
        match: ContentMatch | None = None,
    ) -> Finding:
        # `proof_type` here is descriptive detail for the AI evidence brief only.
        # The calibrated proof type that drives the false-positive floor and
        # ceiling is derived from `detection_method` by EvidenceGrader and
        # overwrites Evidence.proof_type during finding processing, so a value
        # passed here never reaches the calibration tables.
        detection_evidence: dict = {"proof_type": proof_type}
        # Only recorded when a credential-free re-probe actually ran and
        # succeeded. Its absence means "unproven", not "requires auth", so
        # auth-context classification falls back to its own inference.
        if anonymous_access:
            detection_evidence["anonymous_access"] = True
        # The captured span is what makes a regex hit adjudicable: the AI can
        # only rule on whether a pattern match is genuine if it is shown what
        # the pattern actually matched, where it sat, and how random it looks.
        if match is not None and match.matched_text:
            detection_evidence["matched"] = match.matched_text
            detection_evidence["match_location"] = match.match_location
            detection_evidence["entropy"] = self._shannon_entropy(match.matched_text)
        return Finding(
            category=OwaspCategory.a02,
            vuln_type=vuln_type,
            severity=severity,
            url=url,
            evidence=evidence,
            confidence_score=confidence_score,
            detection_method=detection_method,
            detection_evidence=detection_evidence,
            verified=True,
            reproducible=True,
            verification_request_snippet=request_snippet,
            verification_response_snippet=response_snippet,
        )

    def _observed_response_findings(self, kwargs: dict[str, object]) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for request in kwargs.get("requests") or []:
            url = str(getattr(request, "url", "") or "")
            body = str(getattr(request, "response_snippet", "") or "")
            if not url or not body:
                continue
            headers = getattr(request, "response_headers", {}) or {}
            content_type = str(getattr(request, "response_content_type", "") or headers.get("content-type", ""))
            match = self._classify_content(urlparse(url).path, body, content_type)
            if not match:
                continue
            key = (url, match.vuln_type)
            if key in seen:
                continue
            seen.add(key)
            request_snippet = build_observed_request_snippet(
                url=url,
                method=str(getattr(request, "method", "GET") or "GET"),
                headers=getattr(request, "request_headers", None),
                cookies=getattr(request, "request_cookies", None),
                body=getattr(request, "post_data", None),
            )
            findings.append(
                self._finding(
                    vuln_type=match.vuln_type,
                    severity=match.severity,
                    url=url,
                    evidence=f"Observed response disclosure: {match.evidence}",
                    detection_method="observed_response_content",
                    proof_type="content_verified_observed_response",
                    response_snippet=body[:500],
                    request_snippet=request_snippet,
                    match=match,
                )
            )
        return findings

    def _spa_fallback_context_findings(self, kwargs: dict[str, object]) -> list[Finding]:
        return []

    async def _confirm_anonymous_access(
        self,
        client: httpx.AsyncClient,
        target_url: str,
        classify_path: str,
        expected_vuln_type: str,
    ) -> bool:
        """Re-fetch a confirmed path with no session material.

        Every probe in this detector carries the scan session, so a ``Cookie:``
        header in the evidence records what the scanner sent, not what the
        server demanded - and downstream that header is read as proof the
        target is privilege-gated, costing a full CVSS band. One credential-free
        GET settles the question with evidence: if the same classification still
        holds, the exposure is open to anyone and the finding earns ``PR:N``.

        Callers invoke this while already holding the probe semaphore, so this
        must NOT acquire it again: ``asyncio.Semaphore`` is not reentrant, and
        re-entering deadlocks the whole detector once every permit is held by a
        task waiting for one more.

        Returns False on any error, non-200, or changed classification, so a
        failed probe leaves the existing inference in place rather than
        inventing an anonymous-access claim.
        """
        try:
            response = await client.get(target_url)
        except Exception as exc:
            logger.debug("anonymous re-probe failed for %s: %s", target_url, exc)
            return False
        if response.status_code != 200:
            return False
        matched = self._classify_content(
            classify_path,
            response.text,
            response.headers.get("content-type", ""),
        )
        return bool(matched) and matched.vuln_type == expected_vuln_type

    async def detect(self, urls: list[str], forms: list[object], **kwargs: object) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._observed_response_findings(kwargs))
        findings.extend(self._spa_fallback_context_findings(kwargs))
        root_url = kwargs.get("root_url")

        if not root_url and urls:
            parsed = urlparse(urls[0])
            root_url = f"{parsed.scheme}://{parsed.netloc}/"
        elif not root_url:
            return []
            
        if not root_url.endswith("/"):
            root_url += "/"

        # Collect unique directory prefixes from all crawled URLs so we probe
        # sensitive paths under subdirectories (e.g. /dvwa/phpinfo.php), not
        # only at the domain root.
        dirs_to_check = {"/"}
        for u in urls:
            p = urlparse(u).path
            last_slash = p.rfind("/")
            if last_slash > 0:
                dirs_to_check.add(p[:last_slash + 1])

        scan_config = kwargs.get("scan_config")
        settings = get_settings()
        semaphore = asyncio.Semaphore(5)
        is_spa = bool(kwargs.get("is_spa", False))
        spa_root_html = str(kwargs.get("spa_root_html") or "")
        spa_detector = SpaFallbackDetector()

        effective_timeout = scan_config.get_val("request_timeout_seconds", settings.request_timeout_seconds) if scan_config else settings.request_timeout_seconds
        client_kwargs: dict[str, object] = {
            "timeout": effective_timeout,
            "follow_redirects": True,
            "verify": False,  # Similar to other detectors, allow self-signed for scanning
            "event_hooks": {"response": [make_httpx_response_logger("sensitive_paths", "path_probe")]},
        }
        session_cookies = kwargs.get("session_cookies") or {}
        auth_headers = kwargs.get("auth_headers") or {}
        if session_cookies:
            client_kwargs["cookies"] = dict(session_cookies)
        if auth_headers:
            client_kwargs["headers"] = dict(auth_headers)

        # Companion client carrying no session material, used to prove that a
        # confirmed exposure is reachable anonymously. When the scan itself is
        # unauthenticated every probe was already credential-free, so the extra
        # request is skipped entirely.
        sends_credentials = bool(session_cookies or auth_headers)
        anon_client_kwargs = {
            key: value
            for key, value in client_kwargs.items()
            if key not in ("cookies", "headers")
        }

        async with create_scan_client(
            **client_kwargs,
        ) as client, create_scan_client(
            **anon_client_kwargs,
        ) as anon_client:
            if spa_root_html:
                spa_detector.configure_root(str(root_url), spa_root_html)
                is_spa = is_spa or spa_detector.root_looks_like_spa()
            elif is_spa:
                try:
                    root_response = await client.get(str(root_url))
                    if root_response.status_code == 200 and "text/html" in root_response.headers.get("content-type", "").lower():
                        spa_detector.configure_root(str(root_url), root_response.text)
                except Exception as exc:
                    logger.debug("failed to fetch SPA root shell for sensitive path filtering: %s", exc)
            
            already_checked: set[str] = set()

            # Core probe: fetch an absolute URL, suppress SPA fallbacks/soft-404s,
            # and classify by content. ``classify_path`` supplies the path hint used
            # by content classification (its own path for permutations).
            async def probe_url(target_url: str, classify_path: str) -> Finding | None:
                if target_url in already_checked:
                    return None
                already_checked.add(target_url)

                async with semaphore:
                    try:
                        response = await client.get(target_url)

                        # We only care about 200 OK responses
                        if response.status_code != 200:
                            return None

                        content_type = response.headers.get("content-type", "")
                        if is_spa and "text/html" in content_type.lower():
                            fallback_signal = spa_detector.detect(
                                target_url,
                                response.status_code,
                                content_type,
                                response.text,
                                allow_file_like_path=True,
                            )
                            if fallback_signal.is_fallback:
                                logger.debug(
                                    "ignoring SPA fallback response for sensitive path %s: %s similarity=%.3f",
                                    target_url,
                                    fallback_signal.reason,
                                    fallback_signal.similarity,
                                )
                                return None

                        body_lower = response.text.lower()

                        # Simple false positive reduction:
                        # Check if the response looks like a generic HTML 404/Soft 404 page
                        if "<html" in body_lower and ("404" in body_lower or "not found" in body_lower):
                            return None

                        match = self._classify_content(
                            classify_path,
                            response.text,
                            content_type,
                        )
                        if match:
                            anonymous_access = (
                                await self._confirm_anonymous_access(
                                    anon_client,
                                    target_url,
                                    classify_path,
                                    match.vuln_type,
                                )
                                if sends_credentials
                                else True
                            )
                            pcfr_request_snippet, pcfr_response_snippet = (
                                build_httpx_evidence_snippets(
                                    response,
                                    fallback_url=target_url,
                                    fallback_method="GET",
                                    proof_offset=match.match_offset,
                                )
                            )
                            return self._finding(
                                vuln_type=match.vuln_type,
                                severity=match.severity,
                                url=target_url,
                                evidence=(
                                    f"Accessible sensitive path with content proof: {match.evidence} "
                                    + (
                                        "Reachable with no session cookie or authorization header. "
                                        if anonymous_access
                                        else ""
                                    )
                                    + (
                                        f"Matched text ({match.match_location}): {match.matched_text!r}. "
                                        if match.matched_text
                                        else ""
                                    )
                                    + f"Snippet: {response.text[:200]}..."
                                ),
                                detection_method="path_content_fingerprint",
                                proof_type="content_verified_path_probe",
                                request_snippet=pcfr_request_snippet,
                                response_snippet=pcfr_response_snippet or response.text[:500],
                                confidence_score=95.0,
                                anonymous_access=anonymous_access,
                                match=match,
                            )
                    except Exception as e:
                        logger.debug("Error checking path %s: %s", target_url, e)
                return None

            # Helper to check a specific path under a given directory prefix
            async def check_path(base_dir: str, path: str) -> Finding | None:
                clean_path = path.lstrip('/')
                # Join base_dir (e.g. /dvwa/) with the relative path
                if base_dir == "/":
                    target_url = root_url + clean_path
                else:
                    target_url = root_url.rstrip("/") + base_dir.rstrip("/") + "/" + clean_path
                return await probe_url(target_url, path)

            focused_probe_urls = [
                str(candidate)
                for candidate in (kwargs.get("focused_probe_urls") or [])
                if str(candidate)
            ]
            if focused_probe_urls:
                root_origin = f"{urlparse(root_url).scheme}://{urlparse(root_url).netloc}"
                tasks = [
                    probe_url(candidate, urlparse(candidate).path)
                    for candidate in focused_probe_urls
                    if f"{urlparse(candidate).scheme}://{urlparse(candidate).netloc}"
                    == root_origin
                ]
            else:
                tasks = [
                    check_path(directory, path)
                    for directory in dirs_to_check
                    for path in self._common_sensitive_paths
                ]

                # Backup/temp permutations + directory probes derived from what was
                # actually crawled (no hardcoded app paths), bounded per host.
                for perm_url in self._permutation_targets(root_url, urls, kwargs):
                    classify_path = urlparse(perm_url).path
                    tasks.append(probe_url(perm_url, classify_path))

            results = await asyncio.gather(*tasks)

            for res in results:
                if res:
                    findings.append(res)

        return self._collapse_listing_trees(findings)

    @staticmethod
    def _directory_path(url: str) -> str:
        """Path of ``url`` normalized to a trailing slash for prefix matching."""
        path = urlparse(url).path or "/"
        return path if path.endswith("/") else path + "/"

    @classmethod
    def _collapse_listing_trees(cls, findings: list[Finding]) -> list[Finding]:
        """Fold descendant directory listings into their shallowest exposed ancestor.

        A single ``Options +Indexes`` produces one finding per directory the
        crawler walks into, and an autoindex body is itself a page of links, so
        the crawler keeps descending: one exposed ``.git`` tree yielded 18
        findings against DVWA. Those are one misconfiguration demonstrated 18
        times, not 18 vulnerabilities.

        Grouping is per origin and by path containment on directory boundaries
        (both sides normalized to a trailing slash), so ``/config/`` can never
        absorb ``/config2/``. Only listings actually produced are considered, so
        when a parent directory is forbidden its deepest reachable descendant
        becomes the root. The survivor keeps the ancestor's URL - the right
        place to point a reader - and carries the folded paths as evidence.

        Repository proof is promoted rather than discarded: a tree containing a
        confirmed version-control listing IS an exposed repository, even when
        the root's own listing was too partial to prove it (a truncated or
        paginated index shows only its first entries). Without this the strongest
        evidence in the tree would be folded away and the finding would report a
        browsable folder instead of a retrievable source repository.

        Non-listing findings pass through untouched, and the original ordering is
        preserved for callers that rely on it.
        """
        listings = [f for f in findings if f.vuln_type in cls._LISTING_VULN_TYPES]
        if len(listings) < 2:
            return findings

        # Shallowest first so ancestors are always chosen as roots; the path
        # tiebreak keeps the result deterministic across runs.
        ordered = sorted(
            listings,
            key=lambda f: (cls._directory_path(f.url).count("/"), cls._directory_path(f.url)),
        )

        roots: list[Finding] = []
        folded: dict[int, list[Finding]] = {}
        for finding in ordered:
            origin = urlparse(finding.url)[:2]
            path = cls._directory_path(finding.url)
            parent = next(
                (
                    root
                    for root in roots
                    if urlparse(root.url)[:2] == origin
                    and path != cls._directory_path(root.url)
                    and path.startswith(cls._directory_path(root.url))
                ),
                None,
            )
            if parent is None:
                roots.append(finding)
            else:
                folded.setdefault(id(parent), []).append(finding)

        for root in roots:
            children = folded.get(id(root), [])
            if not children:
                continue
            paths = sorted(cls._directory_path(child.url) for child in children)
            shown = paths[: cls._MAX_FOLDED_PATHS_SHOWN]
            summary = ", ".join(shown)
            if len(paths) > len(shown):
                summary += f", and {len(paths) - len(shown)} more"
            noun = "directory" if len(paths) == 1 else "directories"
            notes = [
                f"The same exposure covers {len(paths)} descendant {noun}: {summary}."
            ]

            promoted = root.vuln_type != cls._VCS_VULN_TYPE and any(
                child.vuln_type == cls._VCS_VULN_TYPE for child in children
            )
            if promoted:
                proof = next(
                    child for child in children if child.vuln_type == cls._VCS_VULN_TYPE
                )
                root.vuln_type = cls._VCS_VULN_TYPE
                root.severity = SeverityLevel.high
                notes.append(
                    f"Repository structure confirmed at {cls._directory_path(proof.url)}, "
                    f"so this tree is a version-control repository served over HTTP: "
                    f"the full source and commit history are retrievable."
                )

            root.evidence = "\n".join([root.evidence or "", *notes]).strip()
            root.detection_evidence = {
                **(root.detection_evidence or {}),
                "folded_directory_count": len(paths),
                "folded_directories": shown,
            }

        dropped = {id(f) for f in listings} - {id(r) for r in roots}
        return [f for f in findings if id(f) not in dropped]

    def _permutation_targets(
        self,
        root_url: str,
        urls: list[str],
        kwargs: dict[str, object],
    ) -> list[str]:
        """Derive backup/temp permutations and directory probes from crawled URLs.

        For every crawled file we probe ``<path>{.bak,.old,...}`` variants; for
        every containing directory we probe a trailing-slash listing. Everything
        is same-origin and bounded by ``sensitive_paths_permutation_cap``.
        """
        root_parsed = urlparse(root_url)
        root_origin = f"{root_parsed.scheme}://{root_parsed.netloc}"

        candidates: list[str] = []
        seen: set[str] = set()

        def add(candidate_url: str) -> None:
            if candidate_url in seen:
                return
            seen.add(candidate_url)
            candidates.append(candidate_url)

        # Gather crawled paths from urls + assets (both may hold reachable files).
        raw_paths: list[str] = list(urls)
        assets = kwargs.get("assets") or []
        raw_paths.extend(str(a) for a in assets)

        dirs: set[str] = set()
        for raw in raw_paths:
            parsed = urlparse(raw)
            if parsed.scheme and parsed.netloc and f"{parsed.scheme}://{parsed.netloc}" != root_origin:
                continue  # same-origin only
            path = parsed.path
            if not path or path == "/":
                continue
            base = f"{root_origin}{path}"
            last_slash = path.rfind("/")
            filename = path[last_slash + 1:] if last_slash >= 0 else path
            # File → backup/temp permutations (only for actual files, not dirs).
            if filename and "." in filename:
                for suffix in self._BACKUP_SUFFIXES:
                    add(base + suffix)
            # Containing directory → trailing-slash listing probe.
            if last_slash > 0:
                dirs.add(path[: last_slash + 1])

        for directory in dirs:
            add(f"{root_origin}{directory}")

        sc = kwargs.get("scan_config") if kwargs else None
        cap = sc.get_val("sensitive_paths_permutation_cap", int(getattr(get_settings(), "sensitive_paths_permutation_cap", 200) or 200)) if sc else int(getattr(get_settings(), "sensitive_paths_permutation_cap", 200) or 200)
        return candidates[:cap]
