import asyncio
import logging
import re
from urllib.parse import urljoin, urlparse

import httpx

from app.config import get_settings
from app.core.crawler.spa import SpaFallbackDetector
from app.core.detectors.base_detector import BaseDetector, Finding
from app.models.vulnerability import OwaspCategory, SeverityLevel
from app.utils.http_logging import make_httpx_response_logger
from app.utils.scan_http import create_scan_client

logger = logging.getLogger(__name__)


class SensitivePathsDetector(BaseDetector):
    name = "sensitive_paths"

    _common_sensitive_paths = [
        "/.git/config",
        "/.env",
        "/.env.example",
        "/.env.backup",
        "/.svn/entries",
        "/.hg/requires",
        "/phpinfo.php",
        "/info.php",
        "/backup.sql",
        "/database.sql",
        "/dump.sql",
        "/db.sqlite",
        "/wp-config.php.bak",
        "/config.php.bak",
        "/.bash_history",
        "/.ssh/id_rsa",
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
            r"server-status|apache server status|scoreboard",
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
            r"['\"]?\b(?:password|passwd|db_password|database_password)\b['\"]?\s*[:=]\s*['\"]?[^'\"\s,;}{]{8,}",
            r"['\"]?\b(?:access[_-]?token|refresh[_-]?token|id[_-]?token|jwt)\b['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        ]
    ]

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

    # Generic autoindex/directory-listing signatures across common servers.
    _AUTOINDEX_PATTERNS: list[re.Pattern] = [
        re.compile(r"<title>\s*Index of /", re.IGNORECASE),        # Apache/nginx
        re.compile(r"<h1>\s*Index of /", re.IGNORECASE),           # Apache/nginx
        re.compile(r"Directory listing for ", re.IGNORECASE),      # Python http.server, Tornado
        re.compile(r"\[To Parent Directory\]", re.IGNORECASE),     # IIS
        re.compile(r'<a href="\?C=[NMSD];O=[AD]"', re.IGNORECASE), # Apache column-sort links
    ]

    # Backup/temp permutations appended to discovered files (Task 9).
    _BACKUP_SUFFIXES: tuple[str, ...] = (".bak", ".old", ".orig", "~", ".swp", ".save", ".zip", ".tar.gz")

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

    def _classify_content(self, path: str, body: str, content_type: str = "") -> tuple[bool, str, str, SeverityLevel]:
        body_lower = body.lower()
        path_lower = path.lower()

        if self._looks_like_autoindex(body, content_type):
            return True, "Directory Listing Exposed", "Directory listing/autoindex response exposes sibling file and directory names.", SeverityLevel.medium
        if ".git/config" in path_lower and "[core]" in body_lower:
            return True, "Sensitive File Exposure", "Git configuration file exposed.", SeverityLevel.high
        if ".env" in path_lower and (
            any(pattern.search(body) for pattern in self._SECRET_PATTERNS)
            or re.search(r"\b(?:db_password|database_password|app_key|secret)\b\s*=", body, re.I)
        ):
            return True, "Sensitive File Exposure", "Environment file with secret-like values exposed.", SeverityLevel.high
        if "phpinfo" in path_lower and "<title>phpinfo()</title>" in body_lower:
            return True, "Debug / Metrics Endpoint Exposed", "PHP configuration details (phpinfo) exposed.", SeverityLevel.medium
        if (".sql" in path_lower or "backup" in path_lower or "dump" in path_lower) and (
            "insert into" in body_lower or "create table" in body_lower or "mysqldump" in body_lower
        ):
            return True, "Backup / Database Dump Exposed", "Database dump or backup content exposed.", SeverityLevel.high
        if (path_lower.endswith((".zip", ".tar", ".tar.gz", ".tgz", ".bak", ".old", ".orig", ".swp", ".save", "~")) or "backup" in path_lower) and len(body) > 0:
            if "application" in content_type.lower() or "octet-stream" in content_type.lower() or "<html" not in body_lower:
                return True, "Backup / Archive File Exposed", "Backup/archive-like file content is reachable.", SeverityLevel.high
        if ("docker" in path_lower or path_lower.endswith((".yml", ".yaml"))) and (
            "services:" in body_lower or "image:" in body_lower or "version:" in body_lower
        ):
            return True, "Sensitive File Exposure", "Docker or YAML configuration file exposed.", SeverityLevel.medium
        if "web.xml" in path_lower and "<web-app" in body_lower:
            return True, "Sensitive File Exposure", "Java web.xml configuration file exposed.", SeverityLevel.medium
        if self._looks_like_source_map(path, body, content_type):
            return True, "Exposed Source Map", "JavaScript source map content is reachable.", SeverityLevel.medium
        if self._looks_like_api_docs(path, body, content_type):
            return True, "Exposed API Documentation", "OpenAPI/Swagger/GraphQL documentation content is reachable.", SeverityLevel.medium
        if any(pattern.search(body) for pattern in self._DEBUG_METRICS_PATTERNS):
            return True, "Debug / Metrics Endpoint Exposed", "Debug, metrics, or actuator content exposed.", SeverityLevel.medium
        if any(pattern.search(body) for pattern in self._STACK_TRACE_PATTERNS):
            return True, "Verbose Stack Trace Exposure", "Verbose exception stack trace exposed.", SeverityLevel.medium
        if any(pattern.search(body) for pattern in self._SECRET_PATTERNS):
            return True, "Secret-Like Value Exposure", "Secret-like key, token, or credential value exposed.", SeverityLevel.high

        return False, "", "", SeverityLevel.low

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
    ) -> Finding:
        return Finding(
            category=OwaspCategory.a02,
            vuln_type=vuln_type,
            severity=severity,
            url=url,
            evidence=evidence,
            confidence_score=confidence_score,
            detection_method=detection_method,
            detection_evidence={"proof_type": proof_type},
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
            matched, vuln_type, evidence, severity = self._classify_content(urlparse(url).path, body, content_type)
            if not matched:
                continue
            key = (url, vuln_type)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                self._finding(
                    vuln_type=vuln_type,
                    severity=severity,
                    url=url,
                    evidence=f"Observed response disclosure: {evidence}",
                    detection_method="observed_response_content",
                    proof_type="content_verified_observed_response",
                    response_snippet=body[:500],
                )
            )
        return findings

    def _spa_fallback_context_findings(self, kwargs: dict[str, object]) -> list[Finding]:
        return []

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
        async with create_scan_client(
            timeout=effective_timeout,
            follow_redirects=True,
            verify=False,  # Similar to other detectors, allow self-signed for scanning
            event_hooks={"response": [make_httpx_response_logger("sensitive_paths", "path_probe")]},
        ) as client:
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

                        matched, vuln_type, evidence, severity = self._classify_content(
                            classify_path,
                            response.text,
                            content_type,
                        )
                        if matched:
                            return self._finding(
                                vuln_type=vuln_type,
                                severity=severity,
                                url=target_url,
                                evidence=(
                                    f"Accessible sensitive path with content proof: {evidence} "
                                    f"Snippet: {response.text[:200]}..."
                                ),
                                detection_method="path_content_fingerprint",
                                proof_type="content_verified_path_probe",
                                request_snippet=f"GET {target_url}",
                                response_snippet=response.text[:500],
                                confidence_score=95.0,
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

            tasks = [check_path(dir, path) for dir in dirs_to_check for path in self._common_sensitive_paths]

            # Backup/temp permutations + directory probes derived from what was
            # actually crawled (no hardcoded app paths), bounded per host.
            for perm_url in self._permutation_targets(root_url, urls, kwargs):
                classify_path = urlparse(perm_url).path
                tasks.append(probe_url(perm_url, classify_path))

            results = await asyncio.gather(*tasks)

            for res in results:
                if res:
                    findings.append(res)

        return findings

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
