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
from app.models.scan import CrawlMode, ScanStatus
from app.models.vulnerability import (
    Evidence,
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

logger = logging.getLogger(__name__)


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
            await self.repository.update_status(scan, ScanStatus.running, progress=5)
            await self._check_cancelled(scan_id)

            if scan.crawl_mode == CrawlMode.single:
                logger.info("single-path scan: skipping spider discovery for %s", scan.target_url)
                crawl_result = await self.spider.fetch_single(scan.target_url)
            else:
                crawl_result = await self.spider.crawl(scan.target_url)
            scan.statistics.total_urls_crawled = len(crawl_result.urls)
            scan.progress = 20
            await scan.save()
            await self._check_cancelled(scan_id)

            technologies = await self.technology_detector.detect(scan.target_url)
            scan.technology_stack = await self.cve_service.enrich_components(technologies)
            scan.progress = 35
            await scan.save()
            await self._check_cancelled(scan_id)

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

            async def run_detector(detector) -> list[Finding]:
                async with detector_semaphore:
                    return await detector.detect(
                        crawl_result.urls,
                        crawl_result.forms,
                        session_cookies=session_cookies,
                        technology_stack=scan.technology_stack,
                    )

            detector_results = await asyncio.gather(
                *[run_detector(detector) for detector in active_detectors],
                return_exceptions=True,
            )
            for result in detector_results:
                if isinstance(result, Exception):
                    logger.warning("detector failure: %s", result)
                    continue
                findings.extend(result)

            exception_detector = next((detector for detector in self.detectors if isinstance(detector, ExceptionHandlingDetector)), None)
            if exception_detector is not None:
                observed_exception_findings = exception_detector.findings_from_observed_evidence(findings, target_url=scan.target_url)
                if observed_exception_findings:
                    logger.info(
                        "derived %d exception-handling finding(s) from observed active-verification evidence",
                        len(observed_exception_findings),
                    )
                    findings.extend(observed_exception_findings)

            auth_detector_obj = next((detector for detector in self.detectors if isinstance(detector, AuthenticationFailuresDetector)), None)
            if auth_detector_obj is not None:
                observed_credential_findings = auth_detector_obj.findings_from_observed_evidence(findings)
                if observed_credential_findings:
                    logger.info(
                        "derived %d credential-disclosure finding(s) from observed evidence",
                        len(observed_credential_findings),
                    )
                    findings.extend(observed_credential_findings)

            # Provide the scan root URL so site-wide detectors can avoid duplicate page-level findings.
            crypto_detector = next((detector for detector in self.detectors if isinstance(detector, CryptoFailuresDetector)), None)
            if crypto_detector is not None:
                findings.extend(await crypto_detector.detect(crawl_result.urls, crawl_result.forms, root_url=scan.target_url, session_cookies=getattr(crawl_result, "session_cookies", {})))

            header_detector = next((detector for detector in self.detectors if isinstance(detector, SecurityHeadersDetector)), None)
            if header_detector is not None:
                findings.extend(await header_detector.detect(crawl_result.urls, crawl_result.forms, root_url=scan.target_url, session_cookies=getattr(crawl_result, "session_cookies", {})))

            supply_chain_findings = await self.supply_chain_detector.detect(
                crawl_result.urls,
                crawl_result.forms,
                technologies=scan.technology_stack,
                root_url=scan.target_url,
                session_cookies=getattr(crawl_result, "session_cookies", {}),
            )
            findings.extend(supply_chain_findings)

            scan.progress = 60
            await scan.save()
            await self._check_cancelled(scan_id)

            # DEDUPLICATION PHASE: Merge duplicate findings from different detectors
            # Findings with same (url, parameter, vuln_type) are consolidated
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
                # Exposed admin / sensitive paths - confirmed by HTTP 200/redirect response
                "admin / privileged endpoint",
                "admin endpoint",
                "privileged endpoint",
                "well-known admin",
                "sensitive path",
                "admin panel",
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
                logger.info("filtered findings for verified scan mode: %d findings remaining", len(findings))

            # PHASE 1: Detect all vulnerabilities
            vulnerabilities = [self._to_vulnerability(f) for f in findings]
            logger.info("phase 1 complete: detected %d vulnerabilities", len(vulnerabilities))

            # PHASE 2: Analyze all findings with AI
            logger.info("phase 2 starting: analyzing %d findings", len(vulnerabilities))
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
            scan.report_metadata.attack_chains = self._synthesize_attack_chains(vulnerabilities)
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
            report = await self.ai_report.generate(scan)
            scan.report_metadata.generated_at = datetime.now(timezone.utc)
            
            # Extract summary: handle if AI returns dict instead of string
            executive_summary = report.get("executive_summary", "")
            if isinstance(executive_summary, dict):
                # If dict, try to get 'summary' key or convert to JSON string
                executive_summary = executive_summary.get("summary", json.dumps(executive_summary))
            scan.report_metadata.summary = str(executive_summary) if executive_summary else "Report generated successfully."
            
            scan.progress = 100
            scan.status = ScanStatus.completed
            scan.completed_at = datetime.now(timezone.utc)
            await scan.save()
            logger.info("phase 3 complete: scan %s finished", scan_id)
        except asyncio.CancelledError:
            scan.status = ScanStatus.cancelled
            scan.completed_at = datetime.now(timezone.utc)
            scan.error_message = "Scan cancelled by user"
            await scan.save()
        except Exception as exc:
            logger.exception("scan %s failed", scan_id)
            scan.status = ScanStatus.failed
            scan.error_message = str(exc)
            scan.completed_at = datetime.now(timezone.utc)
            await scan.save()
        finally:
            self._tasks.pop(scan_id, None)
            self._cancel_flags.pop(scan_id, None)

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

        evidence_block = (
            "evidence_block=\n"
            f"- url={vuln.location.url}\n"
            f"- http_method={vuln.location.http_method}\n"
            f"- parameter={vuln.location.parameter or 'none'}\n"
            f"- detector_verified={vuln.evidence.verified}\n"
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
            location=LocationInfo(url=finding.url, parameter=finding.parameter, http_method=finding.method),
            evidence=Evidence(
                payload=finding.payload,
                request_snippet=getattr(finding, "verification_request_snippet", None),
                response_snippet=self._finding_response_snippet(finding),
                verified=getattr(finding, "verified", False),
                confidence_score=float(getattr(finding, "confidence_score", 0.0) or 0.0),
                detection_method=getattr(finding, "detection_method", None),
                detection_evidence=getattr(finding, "detection_evidence", {}) or {},
            ),
            detected_at=datetime.now(timezone.utc),
        )

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
        }:
            return True

        return bool(response_snippet) and len(response_snippet) <= 600