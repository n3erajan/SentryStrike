import asyncio
import json
import logging
from datetime import datetime, timezone
from uuid import uuid4

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
            "Insecure Session Cookie Attributes": (
                "Set HttpOnly, Secure, and SameSite=Strict (or Lax) on session cookies."
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
                findings.append(
                    Finding(
                        category=OwaspCategory.a04,
                        vuln_type="Weak TLS/SSL Configuration",
                        severity=SeverityLevel.medium,
                        url=scan.target_url,
                        evidence="; ".join(ssl_result.get("issues", [])) or "TLS issues detected",
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

            # scan_mode filtering: If verified, keep only verified findings.
            #
            # IMPORTANT — heuristic passthrough:
            # Some vulnerability classes are confirmed by *observing* the HTTP response (e.g.
            # "credentials sent in a GET query string", "no CSRF token in form", "phpMyAdmin
            # is reachable").  These findings are structurally true the moment the detector
            # inspects the response — there is no active exploit payload that could flip
            # `verified=True`.  Dropping them silently would cause the scanner to miss
            # critical, real issues on targets like DVWA.
            #
            # For these classes we keep the finding but note it is heuristic-only so the
            # AI analysis phase can apply its own confidence weighting.
            HEURISTIC_PASSTHROUGH_TYPES: tuple[str, ...] = (
                # Credential / transport exposure — observable from request inspection alone
                "credentials transmitted via http get",
                "credentials via get",
                "password in get",
                # CSRF structural absence — observable from form HTML
                "authentication form may lack csrf",
                "csrf protection",
                "csrf token",
                # Exposed admin / sensitive paths — confirmed by HTTP 200/redirect response
                "admin / privileged endpoint",
                "admin endpoint",
                "privileged endpoint",
                "well-known admin",
                "sensitive path",
                "admin panel",
                "phpmyadmin",
                # Security-header absence — confirmed from response headers
                "missing security header",
                "security header",
                # Session / cookie attribute issues — confirmed from Set-Cookie header
                "insecure session cookie",
                "cookie attribute",
                # Information disclosure — confirmed from response body
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
                    is_low_severity = f.severity in (SeverityLevel.info, SeverityLevel.low)
                    is_heuristic_passthrough = any(
                        keyword in vuln_lower for keyword in HEURISTIC_PASSTHROUGH_TYPES
                    ) and getattr(f, "detection_method", "heuristic") == "heuristic"

                    if is_verified or is_low_severity or is_heuristic_passthrough:
                        if is_heuristic_passthrough and not is_verified:
                            # Boost confidence slightly so AI phase doesn't ignore it, but
                            # leave verified=False so the risk-score weighting in _to_vulnerability
                            # still applies a 30 % penalty — honest representation.
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

            if vulnerabilities:
                total_weighted_score = 0.0
                total_weight = 0.0
                for v in vulnerabilities:
                    is_verified = v.evidence.request_snippet is not None
                    weight = 1.0 if is_verified else 0.5
                    total_weighted_score += v.cvss_score * weight
                    total_weight += weight
                
                scan.overall_risk_score = min(100.0, round((total_weighted_score / total_weight) * 10, 2)) if total_weight > 0 else 0.0
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
            """Analyze findings with AI using optimized local model constraints."""
            if not vulnerabilities:
                return vulnerabilities

            # REDUCED FOR 7B MODEL: Large batches cause qwen2.5-coder:7b to hallucinate validations.
            # Keeping it to 1-2 items per call preserves analytical accuracy.
            BATCH_SIZE = 1 
            analyzed: list[Vulnerability] = []
            
            tech_stack_str = ", ".join(t.name for t in scan.technology_stack) if scan.technology_stack else "Unknown"

            for batch_start in range(0, len(vulnerabilities), BATCH_SIZE):
                batch = vulnerabilities[batch_start : batch_start + BATCH_SIZE]
                logger.info(
                    "Analyzing batch %d–%d of %d vulnerabilities with local LLM",
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
                    if result.get("ai_analysis_status") == "failed" or "results" in result:
                        # Guard against malformed nested batch JSON structures
                        if "results" in result and isinstance(result["results"], list) and len(result["results"]) > 0:
                            result = result["results"][0]
                        else:
                            vuln.ai_analysis.ai_analysis_status = AiAnalysisStatus.failed
                            cvss = CvssCalculator.from_vulnerability_context(
                                vuln_type=vuln.vuln_type,
                                requires_auth=False,
                                confidence=0.8,
                                impact=0.9 if vuln.severity.value in {"Critical", "High"} else 0.5,
                            )
                            vuln.cvss_score = cvss.score
                            vuln.cvss_vector = cvss.vector
                            vuln.ai_analysis.exploitability = self._calibrate_exploitability(vuln)
                            analyzed.append(vuln)
                            continue

                    fallback = self._get_fallback_for(vuln.vuln_type, scan.technology_stack)
                    confidence = float(result.get("confidence", fallback["confidence"]))
                    
                    # Check for explicit AI override on false positives
                    fp_prob = float(result.get("false_positive_probability", fallback["false_positive_probability"]))
                    
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
                    vuln.ai_analysis.business_impact = result.get("business_impact", fallback["business_impact"])
                    vuln.ai_analysis.false_positive_probability = fp_prob
                    vuln.ai_analysis.false_positive_reasoning = result.get("false_positive_reasoning")
                    vuln.ai_analysis.exploitability_reasoning = result.get("exploitability_reasoning")
                    vuln.ai_analysis.remediation = result.get("remediation", fallback["remediation"])
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
            evidence_block = (
                "evidence_block=\n"
                f"- url={vuln.location.url}\n"
                f"- http_method={vuln.location.http_method}\n"
                f"- parameter={vuln.location.parameter or 'none'}\n"
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
            """Constructs an evaluation prompt with strict verification rules optimized for local 7B models."""
            
            # Grounding constraints designed to break the model's tendency to agree blindly
            verification_guardrails = (
                "CRITICAL VERIFICATION RULES TO PREVENT FALSE POSITIVES:\n"
                "1. For SQL Injection: The 'evidence' string MUST contain an explicit database runtime error "
                "(e.g., 'SQL syntax', 'PDOException', 'MySQL', 'PostgreSQL driver'). If the evidence merely shows "
                "the payload reflected back dynamically in standard HTML text, you MUST mark false_positive_probability = 0.95 "
                "and confidence = 0.05.\n"
                "2. For Local/Remote File Inclusion (LFI/RFI): The 'evidence' MUST show contents of system files "
                "(e.g., 'root:x:0', '[boot loader]') or file paths being evaluated. If it just reloads the base page, "
                "mark false_positive_probability = 0.90.\n"
                "3. Reflection does not equal Execution: If a payload is visible inside an HTTP response snippet but did "
                "not break out of its execution context, treat it strictly as a potential False Positive.\n"
                "4. Do not invent details: Base your reasoning solely on the verified markers present inside the 'evidence' field.\n"
            )

            schema_keys = (
                "- exploitability: 'Easy' (no auth, direct execution, public exploit), "
                "'Medium' (requires an authenticated session/multi-step workflow), or 'Hard' (requires special config or chains).\n"
                "- exploitability_reasoning: Short, objective 1-sentence statement justifying execution capability.\n"
                "- business_impact: A concrete 1-2 sentence statement detailing exactly what an attacker steals or executes. "
                "Do NOT use generic filler like 'potential security risks'.\n"
                "- confidence: float 0.0 to 1.0 (probability this finding is legitimate based strictly on the evidence).\n"
                "- false_positive_probability: float 0.0 to 1.0 (probability this is a scanner hallucination/reflection).\n"
                "- false_positive_reasoning: Explain exactly why this is real or why it appears to be a false positive reflection.\n"
                "- remediation: Framework-specific mitigation step targeting the identified Technology Stack.\n"
            )

            if is_batch:
                return (
                    "You are a critical, zero-trust application security code reviewer. Analyze each finding carefully.\n"
                    "Return a JSON object containing a top-level \"results\" key which maps to an array of objects, "
                    "retaining the exact same index order.\n\n"
                    f"Target Technology Stack: {tech_stack_str}\n\n"
                    f"{verification_guardrails}\n"
                    f"Each object in the array MUST contain these identical keys:\n{schema_keys}\n"
                    f"Vulnerabilities to process:\n" + "\n".join(vuln_descriptions)
                )
            else:
                return (
                    "You are a critical, zero-trust application security code reviewer. Analyze the finding below. "
                    "Do not trust the scanner's classification blindly; look for physical proof in the evidence.\n\n"
                    f"Target Technology Stack: {tech_stack_str}\n\n"
                    f"{verification_guardrails}\n"
                    f"Return a flat JSON object with exactly these keys:\n{schema_keys}\n"
                    f"Vulnerability Data:\n" + "\n".join(vuln_descriptions)
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

    def _apply_false_positive_adjustments(self, vulnerabilities: list[Vulnerability]) -> None:
        """Downgrade CVSS score and severity for findings with high false-positive probability.

        Thresholds (applied after AI analysis populates false_positive_probability):
          fp_prob >= 0.90  →  cap CVSS at 1.0  (Info-level)
          fp_prob >= 0.75  →  cap CVSS at 2.5  (Low-level)
          fp_prob >= 0.50  →  reduce CVSS by 40 % (one severity band down at minimum)

        After adjusting the CVSS score the severity label is re-derived via
        CvssCalculator.get_severity so that both fields stay in sync.
        """
        _SEVERITY_ORDER = [
            SeverityLevel.info,
            SeverityLevel.low,
            SeverityLevel.medium,
            SeverityLevel.high,
            SeverityLevel.critical,
        ]

        for v in vulnerabilities:
            fp_prob = v.ai_analysis.false_positive_probability
            if fp_prob is None:
                continue

            original_cvss = v.cvss_score
            original_severity = v.severity

            # --- Auto FP suppression ---
            if fp_prob >= 0.80:
                # High-confidence FP: auto-flag as false positive
                v.is_false_positive = True
                v.review_status = ReviewStatus.needs_review
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

                # If the model claims high FP but cannot reference any concrete evidence markers,
                # treat it as low confidence and do not auto-suppress.
                if not has_evidence_markers:
                    logger.info(
                        "Skipping auto-FP suppression due to insufficient reasoning markers: vuln_type=%r fp_prob=%.2f url=%s reasoning=%r",
                        v.vuln_type,
                        fp_prob,
                        v.location.url,
                        v.ai_analysis.false_positive_reasoning,
                    )
                else:
                    v.is_false_positive = True
                    v.review_status = ReviewStatus.needs_review
                    logger.info(
                        "Auto-suppressed as FP: vuln_type=%r fp_prob=%.2f url=%s",
                        v.vuln_type,
                        fp_prob,
                        v.location.url,
                    )
            elif fp_prob >= 0.50:

                # Moderate FP probability: flag for review
                v.review_status = ReviewStatus.needs_review

            # --- CVSS adjustments ---
            if fp_prob >= 0.90:
                # Almost certainly a scanner hallucination – collapse to Info
                adjusted_cvss = min(original_cvss, 1.0)
            elif fp_prob >= 0.75:
                # Very likely a false positive – cap at Low
                adjusted_cvss = min(original_cvss, 2.5)
            elif fp_prob >= 0.50:
                # Probable false positive – reduce score by 40 %
                adjusted_cvss = round(original_cvss * 0.60, 1)
            else:
                # Low false-positive probability – no CVSS adjustment needed
                continue

            adjusted_cvss = max(0.0, round(adjusted_cvss, 1))
            adjusted_severity = SeverityLevel(CvssCalculator.get_severity(adjusted_cvss))

            if adjusted_cvss != original_cvss or adjusted_severity != original_severity:
                logger.info(
                    "FP adjustment: vuln_type=%r fp_prob=%.2f  "
                    "cvss %s -> %s  severity %s -> %s  url=%s",



                    v.vuln_type,
                    fp_prob,
                    original_cvss,
                    adjusted_cvss,
                    original_severity.value,
                    adjusted_severity.value,
                    v.location.url,
                )
                v.cvss_score = adjusted_cvss
                v.severity = adjusted_severity

    def _compute_priority_ranks(self, vulnerabilities: list[Vulnerability]) -> list[Vulnerability]:
        exploitability_weight = {"Easy": 3.0, "Medium": 2.0, "Hard": 1.0}

        def risk_score(vuln: Vulnerability) -> float:
            exploit_value = vuln.ai_analysis.exploitability.value if vuln.ai_analysis.exploitability else "Medium"
            exploit_w = exploitability_weight.get(exploit_value, 2.0)
            fp_penalty = 1.0 - (vuln.ai_analysis.false_positive_probability or 0.1)
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
            return Exploitability.hard if severity in (SeverityLevel.low, SeverityLevel.info) else Exploitability.medium

        if vuln.ai_analysis and vuln.ai_analysis.exploitability:
            return vuln.ai_analysis.exploitability

        if severity in (SeverityLevel.info, SeverityLevel.low):
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
        elif finding.severity == SeverityLevel.info:
            cvss_score = 0.0
        
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
                response_snippet=getattr(finding, "verification_response_snippet", None) or finding.evidence
            ),
            detected_at=datetime.now(timezone.utc),
        )
