import asyncio
import json
import logging
import math
import re
from datetime import datetime, timezone
from uuid import uuid4
from urllib.parse import urlparse

from app.config import get_settings

from app.analyzers.ai_client import OllamaClient
from app.analyzers.report_generator import AiReportGenerator
from app.core.crawler.spider import WebSpider
from app.core.detectors.access_control import AccessControlDetector
from app.core.detectors.auth_detector import AuthenticationFailuresDetector
from app.core.detectors.base_detector import Finding
from app.core.detectors.crypto_failures import CryptoFailuresDetector
from app.core.detectors.exception_handler import ExceptionHandlingDetector
from app.core.detectors.security_headers import SecurityHeadersDetector
from app.core.detectors.sql_injection import SQLInjectionDetector
from app.core.detectors.supply_chain import SupplyChainDetector
from app.core.detectors.xss_detector import XSSDetector
from app.core.detectors.command_injection import CommandInjectionDetector
from app.core.detectors.file_inclusion import FileInclusionDetector
from app.core.detectors.file_upload import FileUploadDetector
from app.core.detectors.csrf_detector import CSRFDetector
from app.core.detectors.ssrf_detector import SSRFDetector
from app.core.detectors.open_redirect import OpenRedirectDetector
from app.core.detectors.sensitive_paths import SensitivePathsDetector
from app.core.verification.verification_framework import FindingDeduplicator, TestPollutionFilter


def _normalize_llm_string(value: object) -> str | None:
    """Convert an LLM result value to a string, handling lists that small models sometimes emit."""
    if value is None:
        return None
    if isinstance(value, list):
        return "\n".join(str(item) for item in value)
    return str(value)


from app.core.evidence_grader import EvidenceGrader
from app.database.repositories.scan_repository import ScanRepository
from app.integrations.cve_database import CveDatabaseService
from app.integrations.sslyze_wrapper import SslAnalyzer
from app.integrations.wappalyzer import TechnologyDetector
from app.models.scan import CrawlMode, Scan, ScanPhase, ScanStatus
from app.models.scan import AuthCoverage, DetectorCoverageMetric, EvidenceStrengthBreakdown, SpaApiCoverage
from app.models.vulnerability import (
    AuthContext,
    Evidence,
    EvidenceStrength,
    Exploitability,
    LocationInfo,
    OwaspCategory,
    ReviewStatus,
    SeverityLevel,
    Vulnerability,
    normalize_exploitability,
    AiAnalysisStatus,
)
from app.utils.cvss_calculator import CvssCalculator
from app.utils.scan_metrics import begin_request_counting, end_request_counting, snapshot_request_counts

logger = logging.getLogger(__name__)

ATTACK_SURFACE_BACKED_DETECTORS = frozenset(
    {
        "access_control",
        "injection_sql_command",
        "xss",
        "file_inclusion",
        "ssrf",
        "open_redirect",
        "file_upload",
    }
)

SPECIALIZED_INPUT_DETECTORS = frozenset(
    {
        "security_headers",
        "crypto_failures",
        "supply_chain",
        "sensitive_paths",
        "exception_handling",
        "csrf",
        "authentication_failures",
    }
)


class ScanOrchestrator:
    def __init__(self, repository: ScanRepository) -> None:
        self.repository = repository
        self.spider = WebSpider()
        self.technology_detector = TechnologyDetector()
        self.cve_service = CveDatabaseService()
        self.ssl_analyzer = SslAnalyzer()

        self.ai_client = OllamaClient()
        self.ai_report = AiReportGenerator()
        self.evidence_grader = EvidenceGrader()

        self.detectors = [
            AccessControlDetector(),
            SecurityHeadersDetector(),
            CryptoFailuresDetector(),
            SQLInjectionDetector(),
            XSSDetector(),
            AuthenticationFailuresDetector(),
            ExceptionHandlingDetector(),
            CommandInjectionDetector(),
            FileInclusionDetector(),
            CSRFDetector(),
            SSRFDetector(),
            OpenRedirectDetector(),
            FileUploadDetector(),
            SensitivePathsDetector(),
        ]
        self.supply_chain_detector = SupplyChainDetector()

        self._tasks: dict[str, asyncio.Task] = {}
        self._cancel_flags: dict[str, bool] = {}

        self._remediation_fallbacks: dict[str, str] = {
            "Cross-Site Request Forgery (CSRF)": (
                "Add CSRF tokens (synchronizer token pattern) to all state-changing forms; "
                "validate Origin/Referer headers."
            ),
            "Insecure Direct Object Reference (IDOR)": (
                "Implement object-level authorization and verify the authenticated user has "
                "permission to access the referenced resource."
            ),
            "Path Traversal / Arbitrary File Read": (
                "Canonicalize requested paths, reject traversal sequences, enforce an allowlist of readable "
                "files/directories, and ensure file access stays inside the intended document root."
            ),
            "OS Command Injection": (
                "Never pass user input to shell commands. Use parameterized APIs "
                "(e.g., subprocess with shell=False) and strict allowlists."
            ),
            "SQL Injection": (
                "Use parameterized queries / prepared statements. Never concatenate user input into SQL."
            ),
            "Reflected XSS": (
                "Apply context-aware output encoding. Use Content-Security-Policy to restrict inline scripts."
            ),
            "Stored XSS": (
                "Sanitize input on storage and apply context-aware output encoding on display. Use CSP."
            ),
            "Local File Inclusion (LFI)": (
                "Validate and whitelist allowed file paths. Never use user input directly in file operations."
            ),
            "Insecure Transport": (
                "Enforce HTTPS via HSTS with a long max-age and redirect all HTTP traffic to HTTPS."
            ),
            "Missing Security Header": (
                "Add the missing security header with appropriate directives per OWASP guidance."
            ),
            "Server-Side Request Forgery (SSRF)": (
                "Validate and whitelist allowed destination URLs/IPs and block internal/private ranges."
            ),
            "Unrestricted File Upload": (
                "Validate extension, MIME type, and content. Store uploads outside webroot and randomize names."
            ),
            "Weak File Upload Validation": (
                "Validate uploads server-side using extension allowlists, MIME checks, and file magic bytes; "
                "store files outside the webroot with randomized names and disable script execution."
            ),
            "Double Extension Bypass": (
                "Normalize filenames before validation, reject dangerous compound extensions, and enforce "
                "server-side allowlists independent of client-supplied MIME types."
            ),
            "Missing File Type Validation": (
                "Enforce server-side file type validation using allowlisted extensions and magic-byte inspection; "
                "reject unexpected content types and scan uploaded files before storage."
            ),
            "Insecure Session Cookie Attributes": (
                "Set HttpOnly, Secure, and SameSite=Strict (or Lax) on session cookies."
            ),
            "Vulnerable Component": (
                "Upgrade the affected component to a patched version, remove unsupported versions, and verify "
                "the component is no longer matched to the reported CVE."
            ),
            "Verbose Error Handling": (
                "Disable verbose errors in production, return generic error pages, and send stack traces or "
                "debug details only to protected server-side logs."
            ),
            "Credential / Config Disclosure in Response Body": (
                "Remove hardcoded credentials and configuration secrets from application responses. "
                "Use environment variables or a secrets manager, and ensure error handlers never "
                "dump configuration values in production."
            ),
            "Debug / Metrics Endpoint Exposed": (
                "Restrict access to debug, metrics, and actuator endpoints by IP allowlist, "
                "reverse-proxy rules, or authentication. Disable in production or serve on a "
                "separate administrative port."
            ),
        }

    async def queue_scan(self, scan_id: str) -> None:
        task = asyncio.create_task(self.run_scan(scan_id), name=f"scan-{scan_id}")
        self._tasks[scan_id] = task
        self._cancel_flags[scan_id] = False

    async def cancel_scan(self, scan_id: str) -> bool:
        self._cancel_flags[scan_id] = True
        task = self._tasks.get(scan_id)
        if task and not task.done():
            task.cancel()
            return True
        return False

    async def run_scan(self, scan_id: str) -> None:
        scan = await self.repository.get_by_id(scan_id)
        if scan is None:
            logger.error("scan %s not found", scan_id)
            return

        try:
            await self._set_progress(scan, 5, ScanPhase.initializing, "Starting scan")
            await self._check_cancelled(scan_id)

            await self._set_progress(scan, 10, ScanPhase.crawling, "Crawling target and discovering attack surface")
            if scan.crawl_mode == CrawlMode.single:
                logger.info("single-path scan: skipping spider discovery for %s", scan.target_url)
                crawl_result = await self.spider.fetch_single(scan.target_url)
            else:
                crawl_result = await self.spider.crawl(scan.target_url)
            scan.statistics.total_urls_crawled = len(crawl_result.urls)
            await self._set_progress(scan, 20, ScanPhase.crawling, f"Crawl complete: {len(crawl_result.urls)} URL(s) discovered")
            await self._check_cancelled(scan_id)

            await self._set_progress(scan, 25, ScanPhase.technology_detection, "Detecting technology stack and known CVEs")
            technologies = await self.technology_detector.detect(scan.target_url)
            scan.technology_stack = await self.cve_service.enrich_components(technologies)
            await self._set_progress(scan, 35, ScanPhase.technology_detection, f"Technology analysis complete: {len(scan.technology_stack)} component(s) identified")
            await self._check_cancelled(scan_id)

            await self._set_progress(scan, 40, ScanPhase.tls_analysis, "Analyzing TLS and transport security")
            ssl_result = await self.ssl_analyzer.analyze(scan.target_url)
            findings: list[Finding] = []
            if not ssl_result.get("valid", True):
                issues = ssl_result.get("issues", [])
                no_tls = any("does not support HTTPS" in i for i in issues)
                findings.append(
                    Finding(
                        category=OwaspCategory.a02 if no_tls else OwaspCategory.a04,
                        vuln_type="No TLS Configuration" if no_tls else "Weak TLS/SSL Configuration",
                        severity=SeverityLevel.high if no_tls else SeverityLevel.medium,
                        url=scan.target_url,
                        evidence="; ".join(issues) or "TLS issues detected",
                        verified=True,
                        reproducible=True,
                    )
                )

            skip_in_single_path = (SensitivePathsDetector,)
            active_detectors = [
                detector
                for detector in self.detectors
                if not isinstance(detector, (CryptoFailuresDetector, SecurityHeadersDetector))
                and not (scan.crawl_mode == CrawlMode.single and isinstance(detector, skip_in_single_path))
            ]
            detector_parallelism = max(2, get_settings().scanner_concurrency // 3)
            detector_semaphore = asyncio.Semaphore(detector_parallelism)
            session_cookies = getattr(crawl_result, "session_cookies", {})
            crawl_context = {
                "root_url": scan.target_url,
                "session_cookies": session_cookies,
                "auth_headers": getattr(crawl_result, "auth_headers", {}),
                "auth_state": getattr(crawl_result, "auth_state", "unauthenticated"),
                "is_spa": getattr(crawl_result, "is_spa", False),
                "spa_root_html": getattr(crawl_result, "spa_root_html", ""),
                "api_endpoints": getattr(crawl_result, "api_endpoints", []),
                "parameters": getattr(crawl_result, "parameters", []),
                "requests": getattr(crawl_result, "requests", []),
                "routes": getattr(crawl_result, "routes", []),
                "assets": getattr(crawl_result, "assets", []),
                "dead_routes": getattr(crawl_result, "dead_routes", []),
                "browser_available": getattr(crawl_result, "browser_available", None),
                "browser_error": getattr(crawl_result, "browser_error", None),
            }
            coverage_context = {
                **crawl_context,
                "urls": crawl_result.urls,
                "forms": crawl_result.forms,
            }
            self._update_crawl_metadata(scan, crawl_result)

            await self._set_progress(scan, 45, ScanPhase.vulnerability_detection, f"Running {len(active_detectors)} active detector(s)")
            detector_metrics: list[DetectorCoverageMetric] = []
            metric_by_detector: dict[str, DetectorCoverageMetric] = {}

            def record_metric(metric: DetectorCoverageMetric) -> DetectorCoverageMetric:
                detector_metrics.append(metric)
                metric_by_detector[metric.detector] = metric
                return metric

            async def run_detector(detector) -> tuple[object, list[Finding], DetectorCoverageMetric]:
                detector_name = self._detector_name(detector)
                async with detector_semaphore:
                    try:
                        result = await detector.detect(
                            crawl_result.urls,
                            crawl_result.forms,
                            **crawl_context,
                            technology_stack=scan.technology_stack,
                        )
                    except Exception as exc:
                        logger.warning("detector failure: %s", exc)
                        return detector, [], DetectorCoverageMetric(
                            detector=detector_name,
                            skipped_reasons={"detector_exception": 1},
                        )
                self._tag_detector_findings(result, detector_name)
                return detector, result, self._detector_metric_for_findings(
                    detector,
                    result,
                    coverage_context,
                    technology_stack=scan.technology_stack,
                )

            detector_request_counts: dict[str, int] = {}
            begin_request_counting()
            try:
                detector_results = await asyncio.gather(
                    *[run_detector(detector) for detector in active_detectors],
                    return_exceptions=True,
                )
                for result in detector_results:
                    if isinstance(result, Exception):
                        logger.warning("detector failure: %s", result)
                        record_metric(
                            DetectorCoverageMetric(
                                detector="unknown",
                                skipped_reasons={"detector_exception": 1},
                            )
                        )
                        continue
                    _, result_findings, metric = result
                    record_metric(metric)
                    findings.extend(result_findings)

                exception_detector = next((detector for detector in self.detectors if isinstance(detector, ExceptionHandlingDetector)), None)
                if exception_detector is not None:
                    observed_exception_findings = exception_detector.findings_from_observed_evidence(findings, target_url=scan.target_url)
                    self._tag_detector_findings(observed_exception_findings, self._detector_name(exception_detector))
                    if observed_exception_findings:
                        logger.info(
                            "derived %d exception-handling finding(s) from observed active-verification evidence",
                            len(observed_exception_findings),
                        )
                        metric = metric_by_detector.get(self._detector_name(exception_detector))
                        if metric is None:
                            metric = record_metric(self._detector_metric_for_findings(exception_detector, [], coverage_context))
                        self._add_findings_to_metric(metric, observed_exception_findings)
                        findings.extend(observed_exception_findings)

                auth_detector_obj = next((detector for detector in self.detectors if isinstance(detector, AuthenticationFailuresDetector)), None)
                if auth_detector_obj is not None:
                    observed_credential_findings = auth_detector_obj.findings_from_observed_evidence(findings)
                    self._tag_detector_findings(observed_credential_findings, self._detector_name(auth_detector_obj))
                    if observed_credential_findings:
                        logger.info(
                            "derived %d credential-disclosure finding(s) from observed evidence",
                            len(observed_credential_findings),
                        )
                        metric = metric_by_detector.get(self._detector_name(auth_detector_obj))
                        if metric is None:
                            metric = record_metric(self._detector_metric_for_findings(auth_detector_obj, [], coverage_context))
                        self._add_findings_to_metric(metric, observed_credential_findings)
                        findings.extend(observed_credential_findings)

                # Provide the scan root URL so site-wide detectors can avoid duplicate page-level findings.
                crypto_detector = next((detector for detector in self.detectors if isinstance(detector, CryptoFailuresDetector)), None)
                if crypto_detector is not None:
                    crypto_findings = await crypto_detector.detect(crawl_result.urls, crawl_result.forms, **crawl_context)
                    self._tag_detector_findings(crypto_findings, self._detector_name(crypto_detector))
                    record_metric(
                        self._detector_metric_for_findings(
                            crypto_detector,
                            crypto_findings,
                            coverage_context,
                            technology_stack=scan.technology_stack,
                        )
                    )
                    findings.extend(crypto_findings)

                header_detector = next((detector for detector in self.detectors if isinstance(detector, SecurityHeadersDetector)), None)
                if header_detector is not None:
                    header_findings = await header_detector.detect(crawl_result.urls, crawl_result.forms, **crawl_context)
                    self._tag_detector_findings(header_findings, self._detector_name(header_detector))
                    record_metric(
                        self._detector_metric_for_findings(
                            header_detector,
                            header_findings,
                            coverage_context,
                            technology_stack=scan.technology_stack,
                        )
                    )
                    findings.extend(header_findings)

                supply_chain_findings = await self.supply_chain_detector.detect(
                    crawl_result.urls,
                    crawl_result.forms,
                    technologies=scan.technology_stack,
                    **crawl_context,
                )
                self._tag_detector_findings(supply_chain_findings, self._detector_name(self.supply_chain_detector))
                record_metric(
                    self._detector_metric_for_findings(
                        self.supply_chain_detector,
                        supply_chain_findings,
                        coverage_context,
                        technology_stack=scan.technology_stack,
                    )
                )
                findings.extend(supply_chain_findings)
                detector_request_counts = snapshot_request_counts()
            finally:
                end_request_counting()
            self._apply_detector_request_counts(detector_metrics, detector_request_counts)

            await self._set_progress(scan, 60, ScanPhase.vulnerability_detection, f"Detector phase complete: {len(findings)} raw finding(s)")
            await self._check_cancelled(scan_id)

            # DEDUPLICATION PHASE: Merge duplicate findings from different detectors
            # Findings with same (url, parameter, vuln_type) are consolidated
            await self._set_progress(scan, 65, ScanPhase.deduplication, "Deduplicating and filtering findings")
            findings = FindingDeduplicator.deduplicate(findings)
            logger.info("deduplication complete: %d findings after merging", len(findings))

            findings = TestPollutionFilter.filter_cross_module_contamination(findings)
            logger.info(
                "test pollution filter complete: %d findings after contamination review",
                len(findings),
            )

            # CSRF finding deduplication:
            # If token_bypass verified CSRF exists for a URL, suppress weaker heuristics
            # like "Authentication Form Lacks CSRF Protection" to reduce duplicate noise.
            _csrf_confirmed_urls: set[str] = set()
            for f in findings:
                if not f.vuln_type:
                    continue
                if "csrf" not in f.vuln_type.lower():
                    continue
                if getattr(f, "detection_method", "") == "token_bypass" or getattr(f, "verified", False):
                    _csrf_confirmed_urls.add(f.url.split("?")[0])

            if _csrf_confirmed_urls:
                filtered: list[Finding] = []
                for f in findings:
                    url_key = (f.url or "").split("?")[0]
                    vt_lower = (f.vuln_type or "").lower()
                    if url_key in _csrf_confirmed_urls and "authentication form" in vt_lower and "lacks csrf" in vt_lower:
                        continue
                    if url_key in _csrf_confirmed_urls and "authentication form" in vt_lower and "may lack csrf" in vt_lower:
                        continue
                    filtered.append(f)
                findings = filtered

            # scan_mode filtering: If verified, keep only verified findings.
            #
            # IMPORTANT - heuristic passthrough:
            # Some vulnerability classes are confirmed by *observing* the HTTP response (e.g.
            # "credentials sent in a GET query string", "no CSRF token in form", "phpMyAdmin
            # is reachable").  These findings are structurally true the moment the detector
            # inspects the response - there is no active exploit payload that could flip
            # `verified=True`.  Dropping them silently would cause the scanner to miss
            # critical, real issues on targets like DVWA.
            #
            # For these classes we keep the finding but note it is heuristic-only so the
            # AI analysis phase can apply its own confidence weighting.
            HEURISTIC_PASSTHROUGH_TYPES: tuple[str, ...] = (
                # Credential / transport exposure - observable from request inspection alone
                "credentials transmitted via http get",
                "credentials via get",
                "password in get",
                # CSRF structural absence - observable from form HTML
                "authentication form may lack csrf",
                "csrf protection",
                "csrf token",
                # Exposed admin / sensitive paths require content or access-control proof.
                "phpmyadmin",
                # Security-header absence - confirmed from response headers
                "missing security header",
                "security header",
                # Session / cookie attribute issues - confirmed from Set-Cookie header
                "insecure session cookie",
                "cookie attribute",
                # Information disclosure - confirmed from response body
                "information disclosure",
                "server banner",
                "stack trace",
                "debug page",
                # TLS / transport issues already handled by sslyze (always verified=True)
                "weak tls",
                "ssl configuration",
            )

            settings = get_settings()
            scan_mode = getattr(settings, "scan_mode", "verified")
            if scan_mode == "verified":
                dropped_by_detector: dict[str, int] = {}
                kept, dropped = [], []
                for f in findings:
                    vuln_lower = f.vuln_type.lower()
                    is_verified = getattr(f, "verified", False)
                    is_low_severity = f.severity == SeverityLevel.low
                    is_heuristic_passthrough = any(
                        keyword in vuln_lower for keyword in HEURISTIC_PASSTHROUGH_TYPES
                    ) and getattr(f, "detection_method", "heuristic") == "heuristic"

                    if is_verified or is_low_severity or is_heuristic_passthrough:
                        if is_heuristic_passthrough and not is_verified:
                            # Boost confidence slightly so AI phase doesn't ignore it, but
                            # leave verified=False so the risk-score weighting in _to_vulnerability
                            # still applies a 30 % penalty - honest representation.
                            f.confidence_score = max(f.confidence_score, 0.6)
                            logger.info(
                                "verified scan mode KEPT heuristic finding (passthrough): "
                                "vuln_type=%r severity=%s url=%s",
                                f.vuln_type,
                                f.severity.value if hasattr(f.severity, "value") else f.severity,
                                f.url,
                            )
                        kept.append(f)
                    else:
                        dropped.append(f)
                        detector_name = str(getattr(f, "detector_name", "verified_mode_filter") or "verified_mode_filter")
                        dropped_by_detector[detector_name] = dropped_by_detector.get(detector_name, 0) + 1
                        logger.warning(
                            "verified scan mode DROPPED finding: vuln_type=%r severity=%s verified=%s "
                            "url=%s parameter=%s detection_method=%s confidence=%.1f",
                            f.vuln_type,
                            f.severity.value if hasattr(f.severity, "value") else f.severity,
                            getattr(f, "verified", False),
                            f.url,
                            f.parameter,
                            getattr(f, "detection_method", "unknown"),
                            getattr(f, "confidence_score", 0.0),
                        )
                findings = kept
                for detector_name, drop_count in dropped_by_detector.items():
                    metric = metric_by_detector.get(detector_name)
                    if metric is None:
                        metric = record_metric(DetectorCoverageMetric(detector=detector_name))
                    metric.dropped_findings_verified_mode += drop_count
                    metric.skipped_reasons["dropped_unverified_in_verified_mode"] = (
                        metric.skipped_reasons.get("dropped_unverified_in_verified_mode", 0) + drop_count
                    )
                logger.info("filtered findings for verified scan mode: %d findings remaining", len(findings))

            scan.report_metadata.detector_coverage = detector_metrics
            self._log_detector_coverage(detector_metrics)

            # PHASE 1: Detect all vulnerabilities
            vulnerabilities = [self._to_vulnerability(f) for f in findings]
            logger.info("phase 1 complete: detected %d vulnerabilities", len(vulnerabilities))

            # PHASE 2: Analyze all findings with AI
            logger.info("phase 2 starting: analyzing %d findings", len(vulnerabilities))
            await self._set_progress(scan, 75, ScanPhase.ai_analysis, f"Analyzing {len(vulnerabilities)} finding(s)")
            vulnerabilities = await self._analyze_all_findings(vulnerabilities, scan)

            # Phase 2.1: Sync severity from CVSS (pre-FP adjustment)
            for v in vulnerabilities:
                severity_str = CvssCalculator.get_severity(v.cvss_score)
                v.severity = SeverityLevel(severity_str)

            # Phase 2.2: Downgrade severity/CVSS for high false-positive probability findings
            self._apply_false_positive_adjustments(vulnerabilities)

            vulnerabilities = self._compute_priority_ranks(vulnerabilities)
            vulnerabilities.sort(key=lambda v: v.cvss_score, reverse=True)
            logger.info("phase 2 complete: analyzed %d findings", len(vulnerabilities))

            scan.vulnerabilities = vulnerabilities
            
            # Phase 4.4 Attack chain synthesis
            await self._set_progress(scan, 90, ScanPhase.risk_scoring, "Calculating severity, evidence strength, and risk score")
            scan.report_metadata.attack_chains = self._synthesize_attack_chains(vulnerabilities)
            scan.report_metadata.evidence_strength_breakdown = self._evidence_strength_breakdown(vulnerabilities)
            scan.statistics.total_vulnerabilities = len(vulnerabilities)
            scan.statistics.severity_breakdown.critical = len([v for v in vulnerabilities if v.severity.value == "Critical"])
            scan.statistics.severity_breakdown.high = len([v for v in vulnerabilities if v.severity.value == "High"])
            scan.statistics.severity_breakdown.medium = len([v for v in vulnerabilities if v.severity.value == "Medium"])
            scan.statistics.severity_breakdown.low = len([v for v in vulnerabilities if v.severity.value == "Low"])
            scan.statistics.severity_breakdown.info = len([v for v in vulnerabilities if v.severity.value == "Info"])

            active = [v for v in vulnerabilities if not v.is_false_positive]

            if active:
                total_weighted_score = 0.0
                total_weight = 0.0
                for v in active:
                    w = 1.0 if v.evidence.verified else 0.7
                    total_weighted_score += v.cvss_score * w
                    total_weight += w

                avg_cvss = total_weighted_score / total_weight if total_weight > 0 else 0.0

                # Volume amplification with logarithmic diminishing returns.
                # More findings → higher risk, but each additional finding adds less.
                n = len(active)
                volume_mult = 1.0 + (0.15 * math.log(n) if n > 1 else 0.0)

                scan.overall_risk_score = min(100.0, round(avg_cvss * 10 * volume_mult, 2))
            else:
                scan.overall_risk_score = 0.0

            # PHASE 3: Generate final report from analyzed findings
            logger.info("phase 3 starting: generating report")
            await self._set_progress(scan, 95, ScanPhase.report_generation, "Generating final report summary")
            report = await self.ai_report.generate(scan)
            scan.report_metadata.generated_at = datetime.now(timezone.utc)
            
            # Extract summary: handle if AI returns dict instead of string
            executive_summary = report.get("executive_summary", "")
            if isinstance(executive_summary, dict):
                # If dict, try to get 'summary' key or convert to JSON string
                executive_summary = executive_summary.get("summary", json.dumps(executive_summary))
            scan.report_metadata.summary = str(executive_summary) if executive_summary else "Report generated successfully."
            
            scan.completed_at = datetime.now(timezone.utc)
            await self._set_progress(scan, 100, ScanPhase.completed, "Scan completed", status=ScanStatus.completed)
            logger.info("phase 3 complete: scan %s finished", scan_id)
        except asyncio.CancelledError:
            scan.completed_at = datetime.now(timezone.utc)
            scan.error_message = "Scan cancelled by user"
            await self._set_progress(scan, scan.progress, ScanPhase.cancelled, "Scan cancelled by user", status=ScanStatus.cancelled)
        except Exception as exc:
            logger.exception("scan %s failed", scan_id)
            scan.error_message = str(exc)
            scan.completed_at = datetime.now(timezone.utc)
            await self._set_progress(scan, scan.progress, ScanPhase.failed, f"Scan failed: {exc}", status=ScanStatus.failed)
        finally:
            self._tasks.pop(scan_id, None)
            self._cancel_flags.pop(scan_id, None)

    def _detector_name(self, detector: object) -> str:
        return str(getattr(detector, "name", None) or detector.__class__.__name__)

    def _tag_detector_findings(self, findings: list[Finding], detector_name: str) -> None:
        for finding in findings or []:
            setattr(finding, "detector_name", detector_name)

    def _add_findings_to_metric(self, metric: DetectorCoverageMetric, findings: list[Finding]) -> None:
        metric.candidates_built += len(findings or [])
        metric.verified_findings += len([finding for finding in findings or [] if getattr(finding, "verified", False)])
        metric.unverified_findings += len([finding for finding in findings or [] if not getattr(finding, "verified", False)])
        metric.requests_sent = max(metric.requests_sent, self._request_snippet_count(findings))

    def _detector_metric_for_findings(
        self,
        detector: object,
        findings: list[Finding],
        crawl_context: dict,
        *,
        technology_stack: list[object] | None = None,
    ) -> DetectorCoverageMetric:
        detector_name = self._detector_name(detector)
        candidates_built = self._estimate_detector_candidates(
            detector_name,
            findings,
            crawl_context,
            technology_stack=technology_stack,
        )
        skipped_reasons = self._detector_skip_reasons(detector_name, candidates_built, findings, crawl_context)
        if candidates_built == 0 and not findings:
            skipped_reasons["no_candidates_built"] = 1

        settings = get_settings()
        if detector_name == "access_control" and not (
            settings.authentication_second_cookie or settings.authentication_second_header
        ):
            skipped_reasons["second_user_account_missing"] = 1
        if detector_name == "ssrf" and not settings.oast_callback_base_url:
            skipped_reasons["oast_callback_missing"] = 1

        return DetectorCoverageMetric(
            detector=detector_name,
            candidates_built=candidates_built,
            requests_sent=self._request_snippet_count(findings),
            verified_findings=len([finding for finding in findings or [] if getattr(finding, "verified", False)]),
            unverified_findings=len([finding for finding in findings or [] if not getattr(finding, "verified", False)]),
            skipped_reasons=skipped_reasons,
        )

    def _detector_skip_reasons(
        self,
        detector_name: str,
        candidates_built: int,
        findings: list[Finding],
        crawl_context: dict,
    ) -> dict[str, int]:
        skipped: dict[str, int] = {}
        forms = crawl_context.get("forms") or []
        parameters = crawl_context.get("parameters") or []
        api_endpoints = crawl_context.get("api_endpoints") or []
        requests = crawl_context.get("requests") or []
        auth_headers = crawl_context.get("auth_headers") or {}
        session_cookies = crawl_context.get("session_cookies") or {}
        browser_available = crawl_context.get("browser_available")

        replayable_body_count = len(
            [
                request
                for request in requests
                if getattr(request, "post_data", None)
            ]
        )
        if detector_name in {
            "access_control",
            "authentication_failures",
            "csrf",
        } and not (auth_headers or session_cookies):
            skipped["missing_auth_context"] = 1
        if detector_name == "csrf" and not session_cookies:
            skipped["missing_session_cookies"] = 1
        if detector_name in {
            "injection_sql_command",
            "xss",
            "file_inclusion",
            "ssrf",
            "open_redirect",
            "access_control",
        } and candidates_built == 0 and not (parameters or forms or api_endpoints or requests):
            skipped["no_replayable_attack_targets"] = 1
        if detector_name in {"xss", "authentication_failures", "access_control"} and browser_available is False:
            skipped["browser_unavailable"] = 1
        if detector_name in {"injection_sql_command", "xss", "file_inclusion"} and not replayable_body_count:
            skipped["no_replayable_request_bodies"] = 1
        if not findings and candidates_built > 0:
            skipped["no_findings_after_verification"] = 1
        return skipped

    def _estimate_detector_candidates(
        self,
        detector_name: str,
        findings: list[Finding],
        crawl_context: dict,
        *,
        technology_stack: list[object] | None = None,
    ) -> int:
        urls = crawl_context.get("urls") or []
        forms = crawl_context.get("forms") or []
        parameters = crawl_context.get("parameters") or []
        api_endpoints = crawl_context.get("api_endpoints") or []
        requests = crawl_context.get("requests") or []
        routes = crawl_context.get("routes") or []

        if detector_name in {"security_headers", "crypto_failures"}:
            return max(len(urls), len(findings or []))
        if detector_name == "supply_chain":
            return max(len(technology_stack or []), len(findings or []))
        if detector_name == "sensitive_paths":
            return max(len(urls) + len(routes) + len(api_endpoints), len(findings or []))
        if detector_name == "file_upload":
            multipart_requests = [
                request
                for request in requests
                if "multipart" in str((getattr(request, "request_headers", {}) or {}).get("content-type", "")).lower()
            ]
            return max(len(forms) + len(multipart_requests), len(findings or []))
        if detector_name in {"csrf", "authentication_failures"}:
            return max(len(forms) + len(requests), len(findings or []))
        if detector_name == "exception_handling":
            return max(len(parameters) + len(forms), len(findings or []))

        return max(len(parameters) + len(forms) + len(api_endpoints) + len(requests), len(findings or []))

    def _request_snippet_count(self, findings: list[Finding]) -> int:
        snippets = {
            getattr(finding, "verification_request_snippet", None)
            for finding in findings or []
            if getattr(finding, "verification_request_snippet", None)
        }
        return len(snippets)

    def _detector_request_aliases(self, detector_name: str) -> tuple[str, ...]:
        aliases = {
            "authentication_failures": ("authentication_failures", "auth"),
            "file_inclusion": ("file_inclusion", "lfi", "rfi"),
            "injection_sql_command": ("injection_sql_command", "sqli"),
        }
        return aliases.get(detector_name, (detector_name,))

    def _apply_detector_request_counts(
        self,
        detector_metrics: list[DetectorCoverageMetric],
        request_counts: dict[str, int],
    ) -> None:
        matched_modules: set[str] = set()
        for metric in detector_metrics:
            aliases = self._detector_request_aliases(metric.detector)
            request_total = sum(request_counts.get(alias, 0) for alias in aliases)
            if request_total:
                metric.requests_sent = max(metric.requests_sent, request_total)
                matched_modules.update(aliases)

        for module, count in request_counts.items():
            if module in matched_modules:
                continue
            detector_metrics.append(
                DetectorCoverageMetric(
                    detector=module,
                    requests_sent=count,
                    candidates_built=count,
                )
            )

    def _log_detector_coverage(self, detector_metrics: list[DetectorCoverageMetric]) -> None:
        for metric in detector_metrics:
            logger.info(
                "detector coverage: detector=%s candidates_built=%d requests_sent=%d "
                "verified_findings=%d unverified_findings=%d dropped_verified_mode=%d skipped_reasons=%s",
                metric.detector,
                metric.candidates_built,
                metric.requests_sent,
                metric.verified_findings,
                metric.unverified_findings,
                metric.dropped_findings_verified_mode,
                metric.skipped_reasons,
            )

    async def _set_progress(
        self,
        scan: Scan,
        progress: int,
        phase: ScanPhase,
        message: str,
        *,
        status: ScanStatus = ScanStatus.running,
    ) -> None:
        scan.status = status
        scan.progress = progress
        scan.current_phase = phase
        scan.phase_message = message
        scan.updated_at = datetime.now(timezone.utc)
        if status == ScanStatus.running and scan.started_at is None:
            scan.started_at = datetime.now(timezone.utc)
        if status in {ScanStatus.completed, ScanStatus.failed, ScanStatus.cancelled} and scan.completed_at is None:
            scan.completed_at = datetime.now(timezone.utc)
        await scan.save()

    async def _check_cancelled(self, scan_id: str) -> None:
        if self._cancel_flags.get(scan_id):
            raise asyncio.CancelledError

    async def _analyze_all_findings(self, vulnerabilities: list[Vulnerability], scan: 'Scan') -> list[Vulnerability]:
            """Analyze findings with AI using optimised local model constraints."""
            if not vulnerabilities:
                return vulnerabilities

            BATCH_SIZE = get_settings().ai_batch_size
            analyzed: list[Vulnerability] = []

            tech_stack_str = ", ".join(t.name for t in scan.technology_stack) if scan.technology_stack else "Unknown"

            for batch_start in range(0, len(vulnerabilities), BATCH_SIZE):
                batch = vulnerabilities[batch_start : batch_start + BATCH_SIZE]
                logger.info(
                    "Analyzing batch %d-%d of %d vulnerabilities with local LLM",
                    batch_start + 1,
                    batch_start + len(batch),
                    len(vulnerabilities),
                )

                results = []
                try:
                    if BATCH_SIZE == 1:
                        result = await self._analyze_single(batch[0], tech_stack_str)
                        results = [result]
                    else:
                        results = await self._analyze_batch(batch, tech_stack_str)
                except Exception as e:
                    logger.warning("Analysis call failed, falling back to individual processing: %s: %s", type(e).__name__, e)
                    for vuln in batch:
                        try:
                            res = await self._analyze_single(vuln, tech_stack_str)
                            results.append(res)
                        except Exception as single_e:
                            logger.warning("Single analysis failed for %s: %s", vuln.id, single_e)
                            results.append({"ai_analysis_status": "failed"})

                # Apply AI results back to each vulnerability
                for idx, (vuln, result) in enumerate(zip(batch, results), start=batch_start + 1):
                    # Pre-grade the finding deterministically BEFORE applying AI output
                    grade = self.evidence_grader.grade(vuln)
                    logger.info(
                        "Evidence grade: vuln_type=%r grade=%s fp_ceiling=%.2f reason=%r url=%s",
                        vuln.vuln_type, grade.grade, grade.fp_ceiling, grade.reason, vuln.location.url,
                    )

                    if result.get("ai_analysis_status") == "failed" or "results" in result:
                        # Guard against malformed nested batch JSON structures
                        if "results" in result and isinstance(result["results"], list) and len(result["results"]) > 0:
                            result = result["results"][0]
                        else:
                            vuln.ai_analysis.ai_analysis_status = AiAnalysisStatus.failed
                            req_snippet = (vuln.evidence.request_snippet or "").lower()
                            requires_auth = "cookie" in req_snippet or "authorization" in req_snippet
                            cvss = CvssCalculator.from_vulnerability_context(
                                vuln_type=vuln.vuln_type,
                                requires_auth=requires_auth,
                                confidence=0.8,
                                impact=0.9 if vuln.severity.value in {"Critical", "High"} else 0.5,
                            )
                            vuln.cvss_score = cvss.score
                            vuln.cvss_vector = cvss.vector
                            vuln.ai_analysis.exploitability = self._calibrate_exploitability(vuln)
                            # Even on AI failure, apply the grader ceiling
                            vuln.ai_analysis.false_positive_probability = grade.fp_ceiling
                            vuln.ai_analysis.evidence_grade = grade.grade
                            vuln.ai_analysis.evidence_grade_reason = grade.reason
                            analyzed.append(vuln)
                            continue

                    fallback = self._get_fallback_for(vuln.vuln_type, scan.technology_stack)
                    confidence = float(result.get("confidence", fallback["confidence"]))

                    # AI FP output is advisory: clamp to grader ceiling.
                    # AI can LOWER the FP probability (confirm a finding) but
                    # never RAISE it above what the evidence grade allows.
                    raw_ai_fp = float(result.get("false_positive_probability", fallback["false_positive_probability"]))
                    fp_prob = min(raw_ai_fp, grade.fp_ceiling)
                    if raw_ai_fp > grade.fp_ceiling:
                        logger.info(
                            "Clamped AI FP probability: vuln_type=%r ai_fp=%.2f -> ceiling=%.2f "
                            "grade=%s reason=%r url=%s",
                            vuln.vuln_type, raw_ai_fp, grade.fp_ceiling,
                            grade.grade, grade.reason, vuln.location.url,
                        )

                    impact = 0.9 if vuln.severity.value in {"Critical", "High"} else 0.5
                    cvss = CvssCalculator.from_vulnerability_context(
                        vuln_type=vuln.vuln_type,
                        requires_auth=False,
                        confidence=confidence,
                        impact=impact,
                    )

                    vuln.cvss_score = cvss.score
                    vuln.cvss_vector = cvss.vector
                    vuln.ai_analysis.exploitability = normalize_exploitability(
                        result.get("exploitability", fallback["exploitability"])
                    )
                    vuln.ai_analysis.business_impact = _normalize_llm_string(result.get("business_impact", fallback["business_impact"]))
                    vuln.ai_analysis.false_positive_probability = fp_prob
                    vuln.ai_analysis.false_positive_reasoning = _normalize_llm_string(result.get("false_positive_reasoning"))
                    vuln.ai_analysis.exploitability_reasoning = _normalize_llm_string(result.get("exploitability_reasoning"))
                    vuln.ai_analysis.evidence_grade = grade.grade
                    vuln.ai_analysis.evidence_grade_reason = grade.reason
                    remediation = _normalize_llm_string(result.get("remediation", fallback["remediation"]))
                    if self._remediation_is_incompatible(vuln.vuln_type, remediation):
                        logger.info(
                            "Replacing incompatible AI remediation with fallback: vuln_type=%r remediation=%r",
                            vuln.vuln_type,
                            remediation,
                        )
                        remediation = fallback["remediation"]
                    vuln.ai_analysis.remediation = remediation
                    vuln.ai_analysis.exploitability = self._calibrate_exploitability(vuln)
                    vuln.ai_analysis.ai_analysis_status = AiAnalysisStatus.success

                    analyzed.append(vuln)

            return analyzed

    async def _analyze_batch(self, batch: list[Vulnerability], tech_stack_str: str) -> list[dict]:
        vuln_descriptions = []
        for i, vuln in enumerate(batch):
            req = vuln.evidence.request_snippet or ""
            resp = vuln.evidence.response_snippet or ""
            payload = vuln.evidence.payload or ""
            auth_ctx = "requires_auth" if "cookie" in req.lower() else "unknown_auth"
            auth_ctx = vuln.auth_context.value if getattr(vuln, "auth_context", None) else auth_ctx
            evidence_strength = vuln.evidence_strength.value if getattr(vuln, "evidence_strength", None) else "possible"

            # Evidence is what the LLM must ground on. Keep it class-agnostic but
            # include request/response/payload so fp scoring can vary by finding.
            parsed = urlparse(vuln.location.url)
            app_hint = parsed.path.split("/")[-1] or parsed.path
            evidence_block = (
                "evidence_block=\n"
                f"- url={vuln.location.url}\n"
                f"- http_method={vuln.location.http_method}\n"
                f"- parameter={vuln.location.parameter or 'none'}\n"
                f"- detector_verified={vuln.evidence.verified}\n"
                f"- evidence_strength={evidence_strength}\n"
                f"- auth_context={auth_ctx}\n"
                f"- detector_confidence_score={vuln.evidence.confidence_score:.1f}/100\n"
                f"- detection_method={vuln.evidence.detection_method or 'unknown'}\n"
                f"- detection_evidence={json.dumps(vuln.evidence.detection_evidence)[:1200] if vuln.evidence.detection_evidence else '{}'}\n"
                f"- payload={payload or 'n/a'}\n"
                f"- request_snippet={req[:1600] if req else 'n/a'}\n"
                f"- response_snippet={resp[:1600] if resp else 'n/a'}\n"
            )

            vuln_descriptions.append(
                f"[{i}] type={vuln.vuln_type}; category={vuln.category.value}; "
                f"severity={vuln.severity.value}; auth_context={auth_ctx}; "
                + evidence_block
            )

        prompt = self._build_prompt(tech_stack_str, vuln_descriptions, is_batch=True)
        return await self.ai_client.generate_json_list(prompt, expected_count=len(batch))


    async def _analyze_single(self, vuln: Vulnerability, tech_stack_str: str) -> dict:
        req = vuln.evidence.request_snippet or ""
        resp = vuln.evidence.response_snippet or ""
        payload = vuln.evidence.payload or ""
        auth_ctx = "requires_auth" if "cookie" in req.lower() else "unknown_auth"
        auth_ctx = vuln.auth_context.value if getattr(vuln, "auth_context", None) else auth_ctx
        evidence_strength = vuln.evidence_strength.value if getattr(vuln, "evidence_strength", None) else "possible"

        evidence_block = (
            "evidence_block=\n"
            f"- url={vuln.location.url}\n"
            f"- http_method={vuln.location.http_method}\n"
            f"- parameter={vuln.location.parameter or 'none'}\n"
            f"- detector_verified={vuln.evidence.verified}\n"
            f"- evidence_strength={evidence_strength}\n"
            f"- auth_context={auth_ctx}\n"
            f"- detector_confidence_score={vuln.evidence.confidence_score:.1f}/100\n"
            f"- detection_method={vuln.evidence.detection_method or 'unknown'}\n"
            f"- detection_evidence={json.dumps(vuln.evidence.detection_evidence)[:1200] if vuln.evidence.detection_evidence else '{}'}\n"
            f"- payload={payload or 'n/a'}\n"
            f"- request_snippet={req[:1600] if req else 'n/a'}\n"
            f"- response_snippet={resp[:1600] if resp else 'n/a'}\n"
        )

        vuln_desc = (
            f"type={vuln.vuln_type}; category={vuln.category.value}; "
            f"severity={vuln.severity.value}; auth_context={auth_ctx}; "
            + evidence_block
        )
        prompt = self._build_prompt(tech_stack_str, [vuln_desc], is_batch=False)
        return await self.ai_client.generate_json(prompt)


    def _build_prompt(self, tech_stack_str: str, vuln_descriptions: list[str], is_batch: bool) -> str:
        """Constructs an evaluation prompt optimised for Qwen3 8B / local 8B models."""

        # KEY CHANGE 1: Role framing with explicit task decomposition
        # Small models respond better to "think step by step" with explicit phases
        role_and_task = (
            "You are a senior penetration tester writing a verified security report. "
            "For each finding, perform these steps IN ORDER before writing JSON:\n"
            "  Step 1: Read the evidence_block carefully. Identify the EXACT proof markers present.\n"
            "  Step 2: Decide if this is real or a false positive based ONLY on what is in the evidence.\n"
            "  Step 3: For pattern-match findings (e.g., Verbose Error Handling, path disclosure): "
            "determine whether the matched string is causally connected to the payload or is a "
            "genuine error condition - or if it could merely be from normal page content, reflected "
            "payload text, or navigation HTML. Do NOT accept the detector's confidence score at "
            "face value; independently reason about the plausibility of the match.\n"
            "  Step 4: Write remediation that is specific to the vuln_type AND the tech stack below.\n"
            "  Step 5: Describe business_impact in terms of what data/capability is concretely at risk.\n"
            "Output ONLY the JSON. No preamble, no explanation outside the JSON.\n\n"
        )

        # KEY CHANGE 2: Provide concrete examples of good vs bad output
        # Small models learn format from examples far better than from instructions
        output_examples = (
            "OUTPUT QUALITY RULES WITH EXAMPLES:\n"
            
            "business_impact - Reference the parameter name, URL path, and attacker capability:\n"
            "  BAD:  'An attacker can access sensitive information and compromise the server.'\n"
            "  GOOD (OS Command Injection on exec/ via ip param): "
            "'An attacker can execute arbitrary OS commands as www-data on the web server, "
            "enabling exfiltration of /etc/passwd, lateral movement to internal services, "
            "or installation of a reverse shell - full server compromise without credentials.'\n"
            "  GOOD (Stored XSS on guestbook via comment param): "
            "'Any authenticated user can inject a persistent script that steals session cookies "
            "of every visitor, enabling account takeover across all user roles including admins.'\n\n"
            
            "remediation - Name the exact function/config for the detected tech stack:\n"
            "  BAD:  'Implement input validation and use parameterized queries.'\n"
            "  GOOD (SQLi on PHP/MySQL): "
            "'Replace concatenated SQL with PDO prepared statements: "
            "$stmt = $pdo->prepare(\"SELECT * FROM users WHERE id = ?\"); $stmt->execute([$id]);'\n"
            "  GOOD (OS Command Injection on PHP): "
            "'Remove shell execution entirely. If pinging is required, use fsockopen() or a "
            "dedicated PHP network library. Never pass $_POST[\"ip\"] to exec(), system(), or shell_exec().'\n"
            "  GOOD (Reflected XSS on PHP): "
            "'Wrap all echoed user input in htmlspecialchars($value, ENT_QUOTES, \"UTF-8\") "
            "and add Content-Security-Policy: default-src \\'self\\' to the response headers.'\n\n"
            
            "exploitability_reasoning - Reference the specific evidence marker that justifies the rating:\n"
            "  BAD:  'The payload was executed successfully.'\n"
            "  GOOD: 'Response contains uid=33(www-data) confirming shell command execution with no auth required.'\n"
            "  GOOD: 'Time delta of 5.1s vs baseline 0.3s confirms SLEEP(5) was evaluated by the database.'\n\n"
        )

        verification_guardrails = (
            "FALSE POSITIVE SCORING RULES:\n"
            "The detection engine has already pre-scored false_positive_probability based on "
            "objective evidence markers. Your FP score is ADVISORY ONLY:\n"
            "- You may LOWER false_positive_probability if you see additional confirming evidence.\n"
            "- For pattern-match findings (Verbose Error Handling, path disclosure, info leakage): "
            "you MUST independently evaluate whether the matched text is causally connected to an "
            "actual error condition. If the match appears only in reflected payload text, navigation "
            "HTML, or normal page content, you may raise false_positive_probability accordingly.\n"
            "- For structural findings (missing headers, GET credentials, TLS issues, admin paths), "
            "the finding itself IS the proof - do NOT mark these as false positives.\n"
            "- Focus your analysis on remediation specificity, business_impact depth, and "
            "exploitability_reasoning quality.\n"
            "- Do NOT invent evidence. If a proof marker is absent, say so in false_positive_reasoning.\n\n"
        )

        # KEY CHANGE 3: Explicit schema with value constraints + anchoring to evidence
        schema_keys = (
            "Return a flat JSON object with EXACTLY these keys (no extras, no nesting):\n"
            "{\n"
            '  "exploitability": "Easy" | "Medium" | "Hard",\n'
            '    // Easy = unauthenticated + single HTTP request + no user interaction\n'
            '    // Medium = requires auth session OR multi-step workflow\n'
            '    // Hard = requires special server config, chaining, or privileged access\n'
            '  "exploitability_reasoning": "<1 sentence citing a specific evidence marker that justifies the rating>",\n'
            '  "business_impact": "<2 sentences: sentence 1 = what attacker gains right now; sentence 2 = worst-case escalation path>",\n'
            '  "confidence": <float 0.0-1.0>,\n'
            '    // 1.0 = proof of execution in response. 0.7 = strong indirect evidence. 0.4 = ambiguous.\n'
            '  "false_positive_probability": <float 0.0-1.0>,\n'
            '  "false_positive_reasoning": "<cite which evidence marker is present or absent>",\n'
            '  "remediation": "<specific function call or config change for the exact tech stack; include a 1-line code example if applicable>"\n'
            "}\n\n"
        )

        # KEY CHANGE 4: Pass application context to anchor business_impact
        # (url path hints at app type; parameter hints at data sensitivity)
        context_note = (
            f"Target Technology Stack: {tech_stack_str}\n"
            "Note: Treat the application as a real production target. "
            "Infer application type from URL paths and parameter names when writing business_impact "
            "(e.g. /login → credential theft risk, /exec → RCE risk, /upload → file plant risk).\n\n"
        )

        if is_batch:
            return (
                role_and_task
                + output_examples
                + context_note
                + verification_guardrails
                + "Return a JSON object with a top-level \"results\" array. "
                "Retain exact index order. Each element uses the schema above.\n\n"
                + schema_keys.replace("flat JSON object", "object in the results array")
                + "Vulnerabilities to process:\n"
                + "\n".join(vuln_descriptions)
            )
        else:
            return (
                role_and_task
                + output_examples
                + context_note
                + verification_guardrails
                + schema_keys
                + "Vulnerability to analyze:\n"
                + "\n".join(vuln_descriptions)
            )
        
    def _get_fallback_for(self, vuln_type: str, tech_stack: list['TechnologyComponent'] = None) -> dict:
        remediation = "Apply defense-in-depth controls appropriate to this vulnerability class."
        for key, value in self._remediation_fallbacks.items():
            if key.lower() in vuln_type.lower() or vuln_type.lower() in key.lower():
                remediation = value
                break
                
        # Phase 4.2 Framework-specific remediation
        stack_names = [t.name.lower() for t in (tech_stack or [])]
        if "sql injection" in vuln_type.lower():
            if "php" in stack_names:
                remediation = "Use mysqli_prepare() / PDO."
            elif "django" in stack_names:
                remediation = "Use Django ORM."
            elif "express" in stack_names or "node.js" in stack_names:
                remediation = "Use parameterized queries."
            elif "spring" in stack_names or "java" in stack_names:
                remediation = "Use PreparedStatement."
        elif "xss" in vuln_type.lower():
            if "php" in stack_names:
                remediation = "Use htmlspecialchars()."
            elif "django" in stack_names:
                remediation = "Use escape() in templates."
        elif "csrf" in vuln_type.lower():
            if "php" in stack_names:
                remediation = "Store csrf_token in session and validate on POST."
            elif "django" in stack_names:
                remediation = "Use @csrf_protect."
            elif "express" in stack_names or "node.js" in stack_names:
                remediation = "Use csurf middleware."
            elif "spring" in stack_names or "java" in stack_names:
                remediation = "Enable Spring Security CSRF protection."
        return {
            "exploitability": "Medium",
            "business_impact": f"Potential security impact from {vuln_type or 'this issue'}.",
            "confidence": 0.8,
            "false_positive_probability": 0.1,
            "remediation": remediation,
        }

    def _remediation_is_incompatible(self, vuln_type: str, remediation: object) -> bool:
        text = str(remediation or "").lower()
        vt = (vuln_type or "").lower()
        if not text:
            return True

        sql_terms = ("prepared statement", "parameterized quer", "mysqli_prepare", "pdo", "django orm", "sql")
        if ("file inclusion" in vt or "lfi" in vt or "rfi" in vt) and any(term in text for term in sql_terms):
            return True
        if ("file upload" in vt or "extension bypass" in vt or "file type validation" in vt) and any(term in text for term in sql_terms):
            return True
        if "xss" in vt and any(term in text for term in sql_terms):
            return True
        if "csrf" in vt and any(term in text for term in sql_terms):
            return True
        return False

    def _apply_false_positive_adjustments(self, vulnerabilities: list[Vulnerability]) -> None:
        """Downgrade CVSS score and severity for findings with high false-positive probability.

        Now grader-aware: the FP probability has already been clamped to the
        evidence-grade ceiling during ``_analyze_all_findings``.  This method
        only applies CVSS/severity adjustments for findings that *still* have
        elevated FP probability after clamping (i.e., Grade C/D findings where
        the AI legitimately flagged weak evidence).

        Thresholds:
          fp_prob >= 0.90  →  cap CVSS at 1.0  (Info-level)
          fp_prob >= 0.75  →  cap CVSS at 2.5  (Low-level)
          fp_prob >= 0.50  →  reduce CVSS by 40 %

        Grade A/B findings will never reach these thresholds because their
        ceiling is 0.05-0.15.
        """
        for v in vulnerabilities:
            fp_prob = v.ai_analysis.false_positive_probability
            if fp_prob is None:
                continue

            original_cvss = v.cvss_score
            original_severity = v.severity

            # --- Review status assignment ---
            if fp_prob >= 0.80:
                # Only auto-suppress if the grader grade allows it (D-grade).
                # Grade A/B findings can never reach this threshold.
                evidence_grade = getattr(v.ai_analysis, "evidence_grade", None)
                if evidence_grade in ("A", "B", "B+"):
                    # Should not happen after clamping, but guard against it
                    v.is_false_positive = False
                    v.review_status = ReviewStatus.confirmed
                    logger.warning(
                        "Grade %s finding had fp_prob=%.2f >= 0.80 - this should not happen "
                        "after clamping. Forcing confirmed. vuln_type=%r url=%s",
                        evidence_grade, fp_prob, v.vuln_type, v.location.url,
                    )
                    continue

                reasoning = (v.ai_analysis.false_positive_reasoning or "").lower()
                has_evidence_markers = any(
                    kw in reasoning
                    for kw in [
                        "no sql", "sql error", "pdoexception", "mysql", "postgres", "sqlstate",
                        "root:x", "boot loader", "file path", "system file",
                        "time", "delta", "sleep", "timing",
                        "csrf", "token", "samesite", "form",
                        "canary", "reflected", "execution", "not executed",
                        "difference", "baseline",
                    ]
                )

                if not has_evidence_markers:
                    v.is_false_positive = False
                    v.review_status = ReviewStatus.needs_review
                    logger.info(
                        "Skipping auto-FP suppression due to insufficient reasoning markers: "
                        "vuln_type=%r fp_prob=%.2f grade=%s url=%s reasoning=%r",
                        v.vuln_type, fp_prob, evidence_grade, v.location.url,
                        v.ai_analysis.false_positive_reasoning,
                    )
                    # Also skip CVSS adjustment - insufficient evidence to suppress
                    # means insufficient evidence to reduce the score.
                    continue
                else:
                    v.is_false_positive = True
                    v.review_status = ReviewStatus.needs_review
                    logger.info(
                        "Auto-suppressed as FP: vuln_type=%r fp_prob=%.2f grade=%s url=%s",
                        v.vuln_type, fp_prob, evidence_grade, v.location.url,
                    )
            elif fp_prob >= 0.50:
                v.review_status = ReviewStatus.needs_review
            else:
                v.is_false_positive = False
                v.review_status = ReviewStatus.confirmed

            # --- CVSS adjustments ---
            if fp_prob >= 0.90:
                adjusted_cvss = min(original_cvss, 1.0)
            elif fp_prob >= 0.75:
                adjusted_cvss = min(original_cvss, 2.5)
            elif fp_prob >= 0.50:
                adjusted_cvss = round(original_cvss * 0.60, 1)
            else:
                # Low false-positive probability - no CVSS adjustment needed
                continue

            adjusted_cvss = max(0.0, round(adjusted_cvss, 1))
            adjusted_severity = SeverityLevel(CvssCalculator.get_severity(adjusted_cvss))

            if adjusted_cvss != original_cvss or adjusted_severity != original_severity:
                logger.info(
                    "FP adjustment: vuln_type=%r fp_prob=%.2f grade=%s  "
                    "cvss %s -> %s  severity %s -> %s  url=%s",
                    v.vuln_type,
                    fp_prob,
                    getattr(v.ai_analysis, 'evidence_grade', '?'),
                    original_cvss,
                    adjusted_cvss,
                    original_severity.value,
                    adjusted_severity.value,
                    v.location.url,
                )
                v.cvss_score = adjusted_cvss
                v.severity = adjusted_severity

    def _effective_false_positive_probability(self, vuln: Vulnerability, fp_prob: float) -> float:
        """Constrain AI FP scoring using the evidence grader ceiling.

        This is now a lightweight wrapper: the grader does the heavy lifting.
        Kept for backward compatibility with ``_compute_priority_ranks`` which
        calls this method directly.
        """
        grade = self.evidence_grader.grade(vuln)
        return min(fp_prob, grade.fp_ceiling)

    def _compute_priority_ranks(self, vulnerabilities: list[Vulnerability]) -> list[Vulnerability]:
        exploitability_weight = {"Easy": 3.0, "Medium": 2.0, "Hard": 1.0}

        def risk_score(vuln: Vulnerability) -> float:
            exploit_value = vuln.ai_analysis.exploitability.value if vuln.ai_analysis.exploitability else "Medium"
            exploit_w = exploitability_weight.get(exploit_value, 2.0)
            raw_fp_prob = vuln.ai_analysis.false_positive_probability
            fp_prob = self._effective_false_positive_probability(vuln, raw_fp_prob) if raw_fp_prob is not None else 0.1
            fp_penalty = 1.0 - fp_prob
            return vuln.cvss_score * exploit_w * fp_penalty

        vulnerabilities.sort(key=risk_score, reverse=True)
        for rank, vuln in enumerate(vulnerabilities, start=1):
            vuln.ai_analysis.priority_rank = rank
        return vulnerabilities

    def _calibrate_exploitability(self, vuln: Vulnerability) -> Exploitability:
        vuln_type_lower = vuln.vuln_type.lower()
        severity = vuln.severity

        # Phase 4.3: Preserve AI reasoning; only override on unambiguous proof
        if severity == SeverityLevel.critical and any(
            tok in vuln_type_lower
            for tok in ["command injection", "sql injection", "file inclusion", "file upload"]
        ):
            if vuln.evidence.response_snippet and "root:" in vuln.evidence.response_snippet.lower():
                return Exploitability.easy

        if "csrf" in vuln_type_lower and "samesite" in (vuln.evidence.payload or vuln.evidence.response_snippet or "").lower():
            if vuln.ai_analysis:
                if not vuln.ai_analysis.exploitability_reasoning:
                    vuln.ai_analysis.exploitability_reasoning = "SameSite attribute provides partial protection, increasing exploitation difficulty."
            return Exploitability.hard if severity == SeverityLevel.low else Exploitability.medium

        if vuln.ai_analysis and vuln.ai_analysis.exploitability:
            return vuln.ai_analysis.exploitability

        if severity == SeverityLevel.low:
            return Exploitability.hard

        if severity == SeverityLevel.high and vuln.evidence.request_snippet:
            return Exploitability.easy

        return Exploitability.medium

    def _synthesize_attack_chains(self, vulnerabilities: list[Vulnerability]) -> list['AttackChain']:
        from uuid import uuid4
        from app.models.scan import AttackChain
        chains = []
        
        # Rule-based chains
        # 1. CSRF to Command Injection
        csrf_vulns = [v for v in vulnerabilities if "csrf" in v.vuln_type.lower()]
        cmdi_vulns = [v for v in vulnerabilities if "command injection" in v.vuln_type.lower()]
        for csrf in csrf_vulns:
            for cmdi in cmdi_vulns:
                if csrf.location.url == cmdi.location.url:
                    chains.append(AttackChain(
                        id=str(uuid4()),
                        description=f"CSRF to Command Injection chain on {csrf.location.url}. An attacker can forge a request to execute arbitrary OS commands.",
                        vulnerability_ids=[csrf.id, cmdi.id],
                        severity="Critical"
                    ))
                    
        # 2. Stored XSS + missing CSP -> session theft chain
        xss_vulns = [v for v in vulnerabilities if "stored xss" in v.vuln_type.lower()]
        csp_vulns = [v for v in vulnerabilities if "content security policy" in v.vuln_type.lower() or "csp" in v.vuln_type.lower()]
        if xss_vulns and csp_vulns:
            for xss in xss_vulns:
                chains.append(AttackChain(
                    id=str(uuid4()),
                    description=f"Stored XSS combined with missing/weak CSP on {xss.location.url} facilitates reliable session theft.",
                    vulnerability_ids=[xss.id] + [c.id for c in csp_vulns],
                    severity="High"
                ))
                
        return chains

    def _to_vulnerability(self, finding: Finding) -> Vulnerability:
        evidence_strength = self._classify_evidence_strength(finding)
        auth_context = self._classify_auth_context(finding)
        cvss_score = 0.0
        if finding.severity == SeverityLevel.critical:
            cvss_score = 9.5
        elif finding.severity == SeverityLevel.high:
            cvss_score = 8.0
        elif finding.severity == SeverityLevel.medium:
            cvss_score = 5.5
        elif finding.severity == SeverityLevel.low:
            cvss_score = 2.5
        
        # If finding is unverified, reduce score by 30% to weight verified findings more heavily
        if not getattr(finding, "verified", False):
            cvss_score = max(1.0, round(cvss_score * 0.7, 1)) if cvss_score > 0 else 0.0

        return Vulnerability(
            id=str(uuid4()),
            category=finding.category,
            vuln_type=finding.vuln_type,
            severity=finding.severity,
            cvss_score=cvss_score,
            location=LocationInfo(
                url=finding.url,
                parameter=finding.parameter,
                http_method=finding.method,
                parameter_location=(getattr(finding, "parameter_location", None) or None),
            ),
            evidence=Evidence(
                payload=finding.payload,
                request_snippet=getattr(finding, "verification_request_snippet", None),
                response_snippet=self._finding_response_snippet(finding),
                verified=getattr(finding, "verified", False),
                confidence_score=float(getattr(finding, "confidence_score", 0.0) or 0.0),
                detection_method=getattr(finding, "detection_method", None),
                detection_evidence=getattr(finding, "detection_evidence", {}) or {},
                evidence_strength=evidence_strength,
                auth_context=auth_context,
            ),
            evidence_strength=evidence_strength,
            auth_context=auth_context,
            detected_at=datetime.now(timezone.utc),
        )

    def _update_crawl_metadata(self, scan: 'Scan', crawl_result) -> None:
        auth_state = getattr(crawl_result, "auth_state", "unauthenticated")
        auth_state_value = auth_state.value if hasattr(auth_state, "value") else str(auth_state)
        has_session = bool(getattr(crawl_result, "session_cookies", {}) or {})
        has_headers = bool(getattr(crawl_result, "auth_headers", {}) or {})
        verified = auth_state_value == "authenticated_verified"
        is_spa = bool(getattr(crawl_result, "is_spa", False))
        requests = getattr(crawl_result, "requests", []) or []
        replayable_json_bodies = len(
            [
                request
                for request in requests
                if getattr(request, "post_data", None)
                and "json" in str(getattr(request, "request_headers", {}).get("content-type", "")).lower()
            ]
        )
        browser_available = getattr(crawl_result, "browser_available", None)
        browser_error = getattr(crawl_result, "browser_error", None)
        static_spa_only = is_spa and len(requests) == 0

        scan.report_metadata.spa_api_coverage = SpaApiCoverage(
            spa_detected=is_spa,
            js_assets_inspected=len(getattr(crawl_result, "assets", []) or []),
            routes_extracted=len(getattr(crawl_result, "routes", []) or []),
            api_endpoints_extracted=len(getattr(crawl_result, "api_endpoints", []) or []),
            parameters_extracted=len(getattr(crawl_result, "parameters", []) or []),
            browser_requests_observed=len(requests),
            dead_spa_fallback_routes_suppressed=len(getattr(crawl_result, "dead_routes", []) or []),
            static_spa_only=static_spa_only,
            browser_available=browser_available,
            browser_error=browser_error,
            replayable_json_bodies=replayable_json_bodies,
        )
        scan.report_metadata.auth_coverage = AuthCoverage(
            state=auth_state_value,
            authenticated_url_count=len(getattr(crawl_result, "urls", []) or []) if verified else 0,
            unauthenticated_url_count=0 if verified else len(getattr(crawl_result, "urls", []) or []),
            protected_targets_verified=1 if verified else 0,
            auth_headers_present=has_headers,
            session_cookies_present=has_session,
        )
        scan.report_metadata.coverage_warnings = self._coverage_warnings(crawl_result)

    def _coverage_warnings(self, crawl_result) -> list[str]:
        warnings: list[str] = []
        is_spa = bool(getattr(crawl_result, "is_spa", False))
        requests = getattr(crawl_result, "requests", []) or []
        forms = getattr(crawl_result, "forms", []) or []
        auth_headers = getattr(crawl_result, "auth_headers", {}) or {}
        session_cookies = getattr(crawl_result, "session_cookies", {}) or {}
        browser_available = getattr(crawl_result, "browser_available", None)
        browser_error = getattr(crawl_result, "browser_error", None)
        replayable_json_bodies = [
            request
            for request in requests
            if getattr(request, "post_data", None)
            and "json" in str(getattr(request, "request_headers", {}).get("content-type", "")).lower()
        ]
        replayable_form_bodies = [
            request
            for request in requests
            if getattr(request, "post_data", None)
            and "application/x-www-form-urlencoded" in str(
                getattr(request, "request_headers", {}).get("content-type", "")
            ).lower()
        ]
        if is_spa and not requests:
            warnings.append(
                "SPA detected, but no browser runtime requests were observed. API coverage is static extraction only."
            )
        if browser_available is False:
            warnings.append(f"Browser crawling unavailable: {browser_error or 'Playwright could not run.'}")
        if not forms:
            warnings.append("No HTML forms were discovered; form-based detector coverage was limited.")
        if not replayable_json_bodies and not replayable_form_bodies:
            warnings.append("No replayable JSON or form request bodies were observed; API body testing was limited.")
        if auth_headers and not session_cookies:
            warnings.append("Authentication was represented by headers only; cookie/session checks were limited.")
        settings = get_settings()
        if not (settings.authentication_second_cookie or settings.authentication_second_header):
            warnings.append("No second-user account configured; horizontal IDOR comparison was not tested.")
        if not settings.oast_callback_base_url:
            warnings.append("No OAST callback configured; blind SSRF was not tested.")
        return warnings

    def _evidence_strength_breakdown(self, vulnerabilities: list[Vulnerability]) -> EvidenceStrengthBreakdown:
        counts = EvidenceStrengthBreakdown()
        for vuln in vulnerabilities:
            strength = vuln.evidence_strength.value if hasattr(vuln.evidence_strength, "value") else str(vuln.evidence_strength)
            if hasattr(counts, strength):
                setattr(counts, strength, getattr(counts, strength) + 1)
        return counts

    def _classify_evidence_strength(self, finding: Finding) -> EvidenceStrength:
        vt = (finding.vuln_type or "").lower()
        method = (getattr(finding, "detection_method", "") or "").lower()
        verified = bool(getattr(finding, "verified", False))
        confidence = float(getattr(finding, "confidence_score", 0.0) or 0.0)

        informational_terms = (
            "coverage",
            "scanner limitation",
            "not tested",
            "out of scope",
            "informational",
        )
        if finding.severity == SeverityLevel.info or any(term in vt for term in informational_terms):
            return EvidenceStrength.informational

        if method == "union_based" and "sql injection" in vt:
            evidence = getattr(finding, "detection_evidence", {}) or {}
            if not evidence.get("canary_verified") and not evidence.get("version_extracted"):
                return EvidenceStrength.probable if verified else EvidenceStrength.possible

        active_terms = (
            "sql injection",
            "xss",
            "command injection",
            "file inclusion",
            "path traversal",
            "arbitrary file read",
            "ssrf",
            "file upload",
            "idor",
            "privilege escalation",
        )
        active_methods = {
            "boolean",
            "boolean_based",
            "error",
            "error_based",
            "time",
            "time_based",
            "union",
            "union_based",
            "command_output",
            "token_bypass",
            "stored_xss_execution",
            "dom_execution",
            "path_traversal",
            "file_content",
            "ssrf_callback",
            "open_redirect",
            "upload_canary",
        }
        if verified and any(term in vt for term in active_terms) and (
            confidence >= 70.0 or method in active_methods
        ):
            return EvidenceStrength.confirmed_exploit

        if "vulnerable component" in vt:
            return EvidenceStrength.probable
        if verified:
            return EvidenceStrength.confirmed_observation

        if confidence >= 50.0 or method not in {"heuristic", ""}:
            return EvidenceStrength.probable
        if finding.severity == SeverityLevel.low:
            return EvidenceStrength.informational
        return EvidenceStrength.possible

    def _classify_auth_context(self, finding: Finding) -> AuthContext:
        evidence_blob = " ".join(
            str(part or "")
            for part in (
                getattr(finding, "verification_request_snippet", None),
                getattr(finding, "evidence", None),
            )
        ).lower()
        if "authorization:" in evidence_blob or "cookie:" in evidence_blob:
            return AuthContext.authenticated
        vt = (finding.vuln_type or "").lower()
        if "csrf" in vt or "idor" in vt or "privilege escalation" in vt:
            return AuthContext.requires_user_session
        if getattr(finding, "verified", False):
            return AuthContext.unauthenticated
        return AuthContext.unknown

    def _finding_response_snippet(self, finding: Finding) -> str | None:
        evidence = self._clean_evidence_text(finding.evidence or "")
        response_snippet = (getattr(finding, "verification_response_snippet", None) or "").strip()

        if not self._should_include_response_excerpt(finding):
            return f"VERIFICATION EVIDENCE:\n{evidence}" if evidence else None

        if evidence and response_snippet:
            return f"VERIFICATION EVIDENCE:\n{evidence}\n\nRESPONSE EXCERPT:\n{response_snippet}"
        if evidence:
            return f"VERIFICATION EVIDENCE:\n{evidence}"
        return response_snippet or None

    @staticmethod
    def _clean_evidence_text(evidence: str) -> str:
        """Collapse repeated evidence fragments and format as lines."""
        parts = re.split(r"\s*[;\n]\s*", str(evidence or "").strip())
        clean_parts: list[str] = []
        seen: set[str] = set()
        for part in parts:
            normalized = " ".join(part.split())
            key = normalized.lower()
            if normalized and key not in seen:
                seen.add(key)
                clean_parts.append(normalized)
        return "\n".join(clean_parts)

    def _should_include_response_excerpt(self, finding: Finding) -> bool:
        vt = (finding.vuln_type or "").lower()
        method = (getattr(finding, "detection_method", "") or "").lower()
        response_snippet = (getattr(finding, "verification_response_snippet", None) or "").strip()

        header_metadata_terms = (
            "header", "cookie", "transport", "tls", "ssl", "https", "server banner",
            "cache-control", "hsts",
        )
        if "mixed content" not in vt and any(term in vt for term in header_metadata_terms):
            return False

        no_body_proof_terms = (
            "csrf", "brute-force", "brute force", "time-based blind",
            "boolean-based blind", "rate", "captcha bypass",
            "credentials transmitted via http get",
            "credential / token exposed",
            "authentication form lacks csrf",
            "authentication form may lack csrf",
        )
        if any(term in vt for term in no_body_proof_terms):
            return False

        body_proof_terms = (
            "xss", "command injection", "file inclusion", "path traversal",
            "arbitrary file read", "ssrf", "verbose error", "debug / metrics",
            "sensitive path", "information disclosure", "vulnerable component", "mixed content",
            "data exposure", "authorization bypass", "forced browsing",
            "access control", "idor", "privilege bypass",
        )
        if any(term in vt for term in body_proof_terms):
            return True

        if method in {
            "error_based",
            "union_based",
            "file_retrieval",
            "path_traversal_file_read",
            "stream_decoding_oracle",
            "command_output",
            "remote_include_error_oracle",
            "authorization_matrix",
            "authorization_matrix_second_user",
            "authorization_matrix_privileged_baseline",
        }:
            return True

        return bool(response_snippet) and len(response_snippet) <= 600
