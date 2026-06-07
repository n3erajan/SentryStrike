import asyncio
import logging
import re
from urllib.parse import urlparse

import httpx

from app.config import get_settings
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

    async def detect(self, urls: list[str], forms: list[object], **kwargs: object) -> list[Finding]:
        findings: list[Finding] = []
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

        settings = get_settings()
        semaphore = asyncio.Semaphore(5)

        async with create_scan_client(
            timeout=settings.request_timeout_seconds,
            follow_redirects=True,
            verify=False,  # Similar to other detectors, allow self-signed for scanning
            event_hooks={"response": [make_httpx_response_logger("sensitive_paths", "path_probe")]},
        ) as client:
            
            already_checked: set[str] = set()

            # Helper to check a specific path under a given directory prefix
            async def check_path(base_dir: str, path: str) -> Finding | None:
                clean_path = path.lstrip('/')
                # Join base_dir (e.g. /dvwa/) with the relative path
                if base_dir == "/":
                    target_url = root_url + clean_path
                else:
                    target_url = root_url.rstrip("/") + base_dir.rstrip("/") + "/" + clean_path

                if target_url in already_checked:
                    return None
                already_checked.add(target_url)
                
                async with semaphore:
                    try:
                        response = await client.get(target_url)
                        
                        # We only care about 200 OK responses
                        if response.status_code != 200:
                            return None
                            
                        body_lower = response.text.lower()
                        
                        # Simple false positive reduction: 
                        # Check if the response looks like a generic HTML 404/Soft 404 page
                        if "<html" in body_lower and ("404" in body_lower or "not found" in body_lower):
                            return None
                            
                        # Specific pattern matching for high confidence
                        is_sensitive = False
                        evidence = ""
                        
                        if ".git/config" in path and "[core]" in body_lower:
                            is_sensitive = True
                            evidence = "Git configuration file exposed."
                        elif ".env" in path and ("db_password" in body_lower or "app_key" in body_lower or "secret" in body_lower):
                            is_sensitive = True
                            evidence = "Environment variables exposed."
                        elif "phpinfo" in path and "<title>phpinfo()</title>" in body_lower:
                            is_sensitive = True
                            evidence = "PHP configuration details (phpinfo) exposed."
                        elif ".sql" in path and ("insert into" in body_lower or "create table" in body_lower):
                            is_sensitive = True
                            evidence = "Database dump file exposed."
                        elif ("docker" in path or "yml" in path) and ("services:" in body_lower or "image:" in body_lower or "run" in body_lower):
                             is_sensitive = True
                             evidence = "Docker configuration file exposed."
                        elif "web.xml" in path and "<web-app" in body_lower:
                            is_sensitive = True
                            evidence = "Java web.xml configuration file exposed."
                        elif any(p.search(response.text) for p in self._DEBUG_METRICS_PATTERNS):
                            is_sensitive = True
                            evidence = "Debug / metrics / actuator endpoint exposed."
                        else:
                            # If it's a 200 OK and not HTML, it's highly suspicious
                            if "<html" not in body_lower and len(response.text.strip()) > 0:
                                is_sensitive = True
                                evidence = f"Sensitive file {path} is accessible."
                        
                        if is_sensitive:
                            # Determine vuln_type based on path category
                            is_debug_or_metrics = any(
                                p.search(response.text) for p in self._DEBUG_METRICS_PATTERNS
                            )
                            vuln_type = (
                                "Debug / Metrics Endpoint Exposed"
                                if is_debug_or_metrics
                                else "Sensitive File Exposure"
                            )

                            severity = SeverityLevel.high if ".env" in path or ".sql" in path else SeverityLevel.medium

                            return Finding(
                                category=OwaspCategory.a02,
                                vuln_type=vuln_type,
                                severity=severity,
                                url=target_url,
                                evidence=f"Accessible sensitive path: {evidence} Snippet: {response.text[:200]}...",
                                confidence_score=95.0,
                                detection_method="path_bruteforce",
                                verified=True,
                            )
                    except Exception as e:
                        logger.debug("Error checking path %s: %s", target_url, e)
                return None

            tasks = [check_path(dir, path) for dir in dirs_to_check for path in self._common_sensitive_paths]
            results = await asyncio.gather(*tasks)
            
            for res in results:
                if res:
                    findings.append(res)

        return findings
