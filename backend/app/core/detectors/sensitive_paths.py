import asyncio
import logging
from urllib.parse import urljoin, urlparse

import httpx

from app.config import get_settings
from app.core.detectors.base_detector import BaseDetector, Finding
from app.models.vulnerability import OwaspCategory, SeverityLevel
from app.utils.http_logging import make_httpx_response_logger

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
    ]

    async def detect(self, urls: list[str], forms: list[object], **kwargs: object) -> list[Finding]:
        findings: list[Finding] = []
        root_url = kwargs.get("root_url")

        if not root_url and urls:
            parsed = urlparse(urls[0])
            root_url = f"{parsed.scheme}://{parsed.netloc}/"
        elif not root_url:
            return []
            
        # Phase 3: Extract the app base path for scoping checks
        app_base_path = "/"
        if urls:
            app_base_path = urlparse(urls[0]).path
            if not app_base_path.endswith("/"):
                app_base_path = app_base_path[:app_base_path.rfind("/") + 1]
            if not app_base_path:
                app_base_path = "/"
            
        # Ensure root url ends with a slash
        if not root_url.endswith("/"):
            root_url += "/"

        settings = get_settings()
        semaphore = asyncio.Semaphore(5)

        async with httpx.AsyncClient(
            timeout=settings.request_timeout_seconds,
            follow_redirects=True,
            verify=False,  # Similar to other detectors, allow self-signed for scanning
            event_hooks={"response": [make_httpx_response_logger("sensitive_paths", "path_probe")]},
        ) as client:
            
            # Helper to check a specific path
            async def check_path(path: str) -> Finding | None:
                # Remove leading slash from path to work correctly with urljoin
                clean_path = path.lstrip('/')
                target_url = urljoin(root_url, clean_path)
                
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
                        else:
                            # If it's a 200 OK and not HTML, it's highly suspicious
                            if "<html" not in body_lower and len(response.text.strip()) > 0:
                                is_sensitive = True
                                evidence = f"Sensitive file {path} is accessible."
                        
                        if is_sensitive:
                            # Phase 3: Scope Context
                            clean_target_path = "/" + clean_path
                            severity = SeverityLevel.high if ".env" in path or ".sql" in path else SeverityLevel.medium
                            
                            if app_base_path != "/" and not clean_target_path.startswith(app_base_path):
                                evidence += f" (Note: File '{clean_target_path}' is located outside the observed application base path '{app_base_path}'.)"
                                # Optional severity reduction
                                if severity == SeverityLevel.high:
                                    severity = SeverityLevel.medium
                                elif severity == SeverityLevel.medium:
                                    severity = SeverityLevel.low

                            return Finding(
                                category=OwaspCategory.a02, # Security Misconfiguration / Info Disclosure
                                vuln_type="Sensitive File Exposure",
                                severity=severity,
                                url=target_url,
                                evidence=f"Accessible sensitive path: {evidence} Snippet: {response.text[:100]}...",
                                confidence_score=95.0,
                                detection_method="path_bruteforce",
                                verified=True,
                            )
                    except Exception as e:
                        logger.debug("Error checking path %s: %s", target_url, e)
                return None

            tasks = [check_path(path) for path in self._common_sensitive_paths]
            results = await asyncio.gather(*tasks)
            
            for res in results:
                if res:
                    findings.append(res)

        return findings
