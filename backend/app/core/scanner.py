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
from app.core.verification.verification_framework import FindingDeduplicator
from app.database.repositories.scan_repository import ScanRepository
from app.integrations.cve_database import CveDatabaseService
from app.integrations.sslyze_wrapper import SslAnalyzer
from app.integrations.wappalyzer import TechnologyDetector
from app.models.scan import ScanStatus
from app.models.vulnerability import (
    Evidence,
    Exploitability,
    LocationInfo,
    OwaspCategory,
    SeverityLevel,
    Vulnerability,
    normalize_exploitability,
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
                        category=OwaspCategory.a02,
                        vuln_type="Weak TLS/SSL Configuration",
                        severity=SeverityLevel.medium,
                        url=scan.target_url,
                        evidence="; ".join(ssl_result.get("issues", [])) or "TLS issues detected",
                    )
                )

            detector_tasks = [
                detector.detect(crawl_result.urls, crawl_result.forms, session_cookies=getattr(crawl_result, "session_cookies", {}))
                for detector in self.detectors
                if not isinstance(detector, (CryptoFailuresDetector, SecurityHeadersDetector))
            ]
            detector_results = await asyncio.gather(*detector_tasks, return_exceptions=True)
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

            # scan_mode filtering: If verified, keep only verified findings
            settings = get_settings()
            scan_mode = getattr(settings, "scan_mode", "verified")
            if scan_mode == "verified":
                findings = [
                    f for f in findings
                    if getattr(f, "verified", False)
                    or f.severity in (SeverityLevel.info, SeverityLevel.low)
                ]
                logger.info("filtered findings for verified scan mode: %d findings remaining", len(findings))

            # PHASE 1: Detect all vulnerabilities
            vulnerabilities = [self._to_vulnerability(f) for f in findings]
            logger.info("phase 1 complete: detected %d vulnerabilities", len(vulnerabilities))

            # PHASE 2: Analyze all findings with AI
            logger.info("phase 2 starting: analyzing %d findings", len(vulnerabilities))
            vulnerabilities = await self._analyze_all_findings(vulnerabilities)
            vulnerabilities = self._compute_priority_ranks(vulnerabilities)
            vulnerabilities.sort(key=lambda v: v.cvss_score, reverse=True)
            logger.info("phase 2 complete: analyzed %d findings", len(vulnerabilities))

            scan.vulnerabilities = vulnerabilities
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

    async def _analyze_all_findings(self, vulnerabilities: list[Vulnerability]) -> list[Vulnerability]:
        """Analyze findings with AI using batched calls.

        Instead of one AI call per vulnerability, vulnerabilities are grouped
        into batches (up to ``_AI_BATCH_SIZE`` each) and each batch is sent as
        a single prompt.  This typically reduces AI calls from N to 1-2.
        """
        if not vulnerabilities:
            return vulnerabilities

        BATCH_SIZE = 10  # max vulns per AI call — keeps prompts within context limits
        analyzed: list[Vulnerability] = []

        for batch_start in range(0, len(vulnerabilities), BATCH_SIZE):
            batch = vulnerabilities[batch_start : batch_start + BATCH_SIZE]
            logger.info(
                "analyzing batch %d–%d of %d vulnerabilities",
                batch_start + 1,
                batch_start + len(batch),
                len(vulnerabilities),
            )

            # Build a single prompt listing every vulnerability in this batch
            vuln_descriptions = []
            for i, vuln in enumerate(batch):
                vuln_descriptions.append(
                    f"[{i}] type={vuln.vuln_type}; category={vuln.category.value}; "
                    f"severity={vuln.severity.value}; url={vuln.location.url}; "
                    f"evidence={vuln.evidence.response_snippet or vuln.evidence.payload or 'n/a'}"
                )

            prompt = (
                "You are a senior application security analyst. Analyze each vulnerability below and return "
                "a JSON object with key \"results\" containing an array of objects, one per vulnerability, in the "
                "SAME ORDER.\n\n"
                "Each object MUST have these keys:\n"
                "- exploitability: 'Easy' (no auth required, trivial payload, public exploit exists), "
                "'Medium' (requires valid session or multi-step attack), or 'Hard' (requires chained exploits, "
                "race conditions, or specific server config)\n"
                "- business_impact: A SPECIFIC 1-2 sentence impact statement for THIS vulnerability at THIS URL. "
                "Describe what an attacker can achieve. Do NOT use generic statements.\n"
                "- confidence: float 0-1, probability this is a real vulnerability (not a false positive)\n"
                "- false_positive_probability: float 0-1, probability this is NOT a real vulnerability\n"
                "- remediation: A SPECIFIC fix for THIS vulnerability type. For CSRF say 'add CSRF tokens'; "
                "for SQLi say 'use parameterized queries'; do NOT say 'implement HTTPS' unless it is transport.\n\n"
                "Vulnerabilities:\n" + "\n".join(vuln_descriptions)
            )

            results = await self.ai_client.generate_json_list(
                prompt,
                expected_count=len(batch),
                fallback=self._get_fallback_for(""),
            )

            # Apply AI results back to each vulnerability
            for idx, (vuln, result) in enumerate(zip(batch, results), start=batch_start + 1):
                fallback = self._get_fallback_for(vuln.vuln_type)
                confidence = float(result.get("confidence", fallback["confidence"]))
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
                vuln.ai_analysis.false_positive_probability = float(
                    result.get("false_positive_probability", fallback["false_positive_probability"])
                )
                vuln.ai_analysis.remediation = result.get("remediation", fallback["remediation"])
                vuln.ai_analysis.exploitability = self._calibrate_exploitability(vuln)

                analyzed.append(vuln)

            logger.info("batch analysis complete — %d findings processed so far", len(analyzed))

        return analyzed

    def _get_fallback_for(self, vuln_type: str) -> dict:
        remediation = "Apply defense-in-depth controls appropriate to this vulnerability class."
        for key, value in self._remediation_fallbacks.items():
            if key.lower() in vuln_type.lower() or vuln_type.lower() in key.lower():
                remediation = value
                break
        return {
            "exploitability": "Medium",
            "business_impact": f"Potential security impact from {vuln_type or 'this issue'}.",
            "confidence": 0.8,
            "false_positive_probability": 0.1,
            "remediation": remediation,
        }

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

        if severity == SeverityLevel.critical and any(
            tok in vuln_type_lower
            for tok in ["command injection", "sql injection", "file inclusion", "file upload"]
        ):
            return Exploitability.easy

        if "xss" in vuln_type_lower:
            return Exploitability.medium

        if severity in (SeverityLevel.info, SeverityLevel.low):
            return Exploitability.hard

        if severity == SeverityLevel.high and vuln.evidence.request_snippet:
            return Exploitability.easy

        return vuln.ai_analysis.exploitability or Exploitability.medium

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
