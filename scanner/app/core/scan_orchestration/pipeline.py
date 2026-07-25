import asyncio
import logging
import re
from datetime import datetime, timezone
from time import perf_counter
from urllib.parse import urlparse

from app.config import get_settings
from app.core.detectors.attack_planner import AttackPlanner
from app.core.detectors.auth_detector import AuthenticationFailuresDetector
from app.core.detectors.base_detector import Finding
from app.core.detectors.crypto_failures import CryptoFailuresDetector
from app.core.detectors.exception_handler import ExceptionHandlingDetector
from app.core.detectors.security_headers import SecurityHeadersDetector
from app.core.detectors.sensitive_paths import SensitivePathsDetector
from app.core.scan_orchestration.progress import _EtaState
from app.core.verification.verification_framework import FindingDeduplicator, TestPollutionFilter
from app.utils.cvss_calculator import CvssCalculator
from app.utils.scan_metrics import begin_request_counting, end_request_counting, snapshot_request_counts
from app.core.request_governor import begin_governor, end_governor, denied_snapshot
from shared.analysis_handoff import ensure_initial_analysis_job
from shared.finding_rollups import apply_finding_rollups
from shared.models.scan import CrawlMode, DetectorCoverageMetric, ScanPhase, ScanStatus
from shared.models.vulnerability import OwaspCategory, SeverityLevel
from shared.schemas.scan_schema import ScanConfig
from shared.verification.oast import OastClient

logger = logging.getLogger("app.core.scanner")


class PipelineMixin:
    async def _run_scan_pipeline(
        self,
        scan_id: str,
        *,
        auth_accounts: list | None = None,
        scan_config: ScanConfig | None = None,
    ) -> None:
        scan = await self.repository.get_by_id(scan_id)
        if scan is None:
            logger.error("scan %s not found", scan_id)
            return

        # Isolate mutable crawl/detector state per production scan so concurrent
        # runs cannot share cookies, auth, HTTP clients, or verifier state.
        # Injected fakes (tests/embedders) are preserved; only the default
        # self-built instances are replaced with fresh per-scan ones.
        runtime = self._build_scan_runtime()
        scan_spider = runtime.spider
        scan_detectors = runtime.detectors
        scan_supply_chain = runtime.supply_chain_detector

        try:
            self._eta_state = _EtaState()
            await self._set_phase_progress(scan, ScanPhase.initializing, 1.0, "Starting scan")
            await self._check_cancelled(scan_id)

            # The worker received these accounts in the Redis job payload. BLPOP
            # removed that payload before this method started, so they now live
            # only in this worker's memory.
            submitted_accounts = auth_accounts or []
            auth_accounts_by_role = {account.role.value: account for account in submitted_accounts}
            main_account = auth_accounts_by_role.get("main")

            await self._set_phase_progress(scan, ScanPhase.crawling, 0.0, "Crawling target and discovering attack surface")
            
            http_prior_s = self._eta_state.crawl_total_prior_s
            browser_prior_s = 0.0
            if getattr(scan_spider, "_should_run_browser", lambda x: False)(False) or (scan_config and scan_config.get_val("crawl_browser_mode", "auto") != "off"):
                browser_prior_s = float(scan_config.get_val("crawl_browser_budget_seconds", 300.0) if scan_config else 300.0)
            
            total_prior_s = http_prior_s + browser_prior_s
            if total_prior_s > 0:
                self._eta_state.crawl_http_split = http_prior_s / total_prior_s
                self._eta_state.crawl_browser_split = browser_prior_s / total_prior_s
                self._eta_state.crawl_total_prior_s = total_prior_s
                
            async def _crawl_progress_callback(fraction: float) -> None:
                await self._set_phase_progress(scan, ScanPhase.crawling, fraction, "Crawling target and discovering attack surface")

            if scan.crawl_mode == CrawlMode.single:
                logger.info("single-path scan: skipping spider discovery for %s", scan.target_url)
                crawl_result = await scan_spider.fetch_single(scan.target_url)
            else:
                crawl_result = await scan_spider.crawl(scan.target_url, auth_override=main_account, scan_config=scan_config, progress_callback=_crawl_progress_callback)

            # Keep crawl results same-origin so active probes never leave the scan target.
            target_url = scan.target_url
            
            def is_same_origin(url_a: str, url_b: str) -> bool:
                try:
                    p_a = urlparse(url_a)
                    p_b = urlparse(url_b)
                    port_a = p_a.port or (80 if p_a.scheme == "http" else 443 if p_a.scheme == "https" else None)
                    port_b = p_b.port or (80 if p_b.scheme == "http" else 443 if p_b.scheme == "https" else None)
                    return (p_a.scheme == p_b.scheme and p_a.hostname == p_b.hostname and port_a == port_b)
                except Exception:
                    return False

            crawl_result.urls = [u for u in crawl_result.urls if is_same_origin(target_url, u)]
            crawl_result.routes = [r for r in crawl_result.routes if is_same_origin(target_url, getattr(r, "url", "")) and not getattr(r, "is_dead", False)]
            crawl_result.api_endpoints = [e for e in crawl_result.api_endpoints if is_same_origin(target_url, getattr(e, "url", ""))]
            crawl_result.requests = [req for req in crawl_result.requests if is_same_origin(target_url, getattr(req, "url", ""))]
            if hasattr(crawl_result, "request_audit"):
                crawl_result.request_audit = [
                    req for req in crawl_result.request_audit
                    if is_same_origin(target_url, getattr(req, "url", ""))
                ]
            crawl_result.parameters = [p for p in crawl_result.parameters if is_same_origin(target_url, getattr(p, "url", ""))]
            # A form is in scope only when its resolved submission target is same-origin.
            # page_url resolves relative/empty actions but is not scope proof on its
            # own — otherwise a same-origin page with an off-origin action could
            # send active payloads and credentials to a third party.
            crawl_result.forms = self._scope_forms_to_origin(target_url, crawl_result.forms, is_same_origin)

            scan.statistics.total_urls_crawled = self._count_discovered_surface(crawl_result)
            self._recompute_phase_weights(crawl_result)
            await self._set_phase_progress(scan, ScanPhase.crawling, 1.0, f"Crawl complete: {scan.statistics.total_urls_crawled} URL(s) discovered")

            root_html = getattr(crawl_result, "spa_root_html", "")
            if root_html:
                match = re.search(r"<title[^>]*>(.*?)</title>", root_html, re.I | re.S)
                scan.site_title = re.sub(r"\s+", " ", match.group(1)).strip() if match else ""

            await self._check_cancelled(scan_id)

            await self._set_phase_progress(scan, ScanPhase.technology_detection, 0.0, "Detecting technology stack and known CVEs")
            technologies = await self.technology_detector.detect(
                scan.target_url,
                crawl_result=crawl_result,
                browser_available=getattr(crawl_result, "browser_available", False),
                storage_state=getattr(crawl_result, "auth_storage_state", None),
                session_cookies=getattr(crawl_result, "session_cookies", {}),
            )
            scan.technology_stack = await self.cve_service.enrich_components(technologies)
            # Back-fill component versions from ecosystem-standard manifests and
            # version-bearing headers so the supply-chain gate can emit true A03
            # findings. Best-effort: never fail the scan over version enrichment.
            try:
                await self._enrich_tech_from_manifests(scan, crawl_result)
            except Exception as exc:
                logger.debug("manifest/header version enrichment failed: %s", exc)
            await self._set_phase_progress(scan, ScanPhase.technology_detection, 1.0, f"Technology analysis complete: {len(scan.technology_stack)} component(s) identified")
            await self._check_cancelled(scan_id)

            await self._set_phase_progress(scan, ScanPhase.tls_analysis, 0.0, "Analyzing TLS and transport security")
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
            await self._set_phase_progress(scan, ScanPhase.tls_analysis, 1.0, "TLS analysis complete")

            skip_in_single_path = (SensitivePathsDetector,)
            active_detectors = [
                detector
                for detector in scan_detectors
                if not isinstance(detector, (CryptoFailuresDetector, SecurityHeadersDetector))
                and not (scan.crawl_mode == CrawlMode.single and isinstance(detector, skip_in_single_path))
            ]
            effective_concurrency = scan_config.get_val("scanner_concurrency", get_settings().scanner_concurrency) if scan_config else get_settings().scanner_concurrency
            detector_parallelism = max(2, effective_concurrency // 3)
            detector_semaphore = asyncio.Semaphore(detector_parallelism)
            session_cookies = getattr(crawl_result, "session_cookies", {})
            oast_settings = get_settings()
            crawl_context = {
                "root_url": scan.target_url,
                "session_cookies": session_cookies,
                "auth_headers": getattr(crawl_result, "auth_headers", {}),
                "auth_storage_state": getattr(crawl_result, "auth_storage_state", None),
                "auth_state": getattr(crawl_result, "auth_state", "unauthenticated"),
                "is_spa": getattr(crawl_result, "is_spa", False),
                "spa_root_html": getattr(crawl_result, "spa_root_html", ""),
                "api_endpoints": getattr(crawl_result, "api_endpoints", []),
                "parameters": getattr(crawl_result, "parameters", []),
                "requests": getattr(crawl_result, "requests", []),
                "request_audit": getattr(crawl_result, "request_audit", []),
                "request_audit_summary": getattr(crawl_result, "request_audit_summary", {}),
                "routes": getattr(crawl_result, "routes", []),
                "assets": getattr(crawl_result, "assets", []),
                "dead_routes": getattr(crawl_result, "dead_routes", []),
                "browser_available": getattr(crawl_result, "browser_available", None),
                "browser_error": getattr(crawl_result, "browser_error", None),
                "browser_forms": getattr(crawl_result, "browser_forms", []),
                "oast_client": OastClient(
                    oast_settings.oast_callback_base_url,
                    oast_settings.oast_poll_url,
                    timeout_seconds=oast_settings.request_timeout_seconds,
                ),
                "scan_config": scan_config,
            }
            # Reuse the winning login path from the main account so second/admin
            # logins don't restart the strategy cascade from scratch.
            main_replay = getattr(crawl_result, "auth_replay_state", None)
            # Expose the winning login recipe to detectors (the auth detector uses it
            # as a reliable login-flow record for default/weak-credential probing).
            crawl_context["auth_replay_state"] = main_replay
            # The scanner's OWN login identity for this scan (from the submitted
            # main account, if any). The auth detector uses it to avoid flagging
            # its own credentials as an exposed app identity. No env fallback.
            crawl_context["scanner_identity_username"] = (
                main_account.username if main_account else None
            )
            main_credentials = (
                (main_account.username, main_account.password) if main_account else None
            )
            await self._apply_submitted_account_sessions(
                scan,
                auth_accounts_by_role,
                crawl_context,
                scan_config=scan_config,
                preferred_replay=main_replay,
                primary_credentials=main_credentials,
            )
            attack_planner = AttackPlanner.from_context(
                urls=crawl_result.urls,
                forms=crawl_result.forms,
                parameters=getattr(crawl_result, "parameters", []),
                api_endpoints=getattr(crawl_result, "api_endpoints", []),
                requests=getattr(crawl_result, "requests", []),
            )
            crawl_context["attack_planner"] = attack_planner
            crawl_context["attack_targets"] = attack_planner.targets
            coverage_context = {
                **crawl_context,
                "urls": crawl_result.urls,
                "forms": crawl_result.forms,
            }
            self._update_crawl_metadata(scan, crawl_result, crawl_context)

            if getattr(crawl_result, "observed_mean_latency_ms", None) is not None:
                self._eta_state.measured_latency_ms = crawl_result.observed_mean_latency_ms
            else:
                self._eta_state.measured_latency_ms = await self._measure_target_latency_ms(scan.target_url)
            work_units, detector_prior_s = self._estimate_detector_work(
                attack_planner,
                active_detectors,
                latency_ms=self._eta_state.measured_latency_ms,
                parallelism=detector_parallelism,
                per_detector_cap=(
                    scan_config.get_val(
                        "scanner_per_detector_request_cap",
                        get_settings().scanner_per_detector_request_cap,
                    )
                    if scan_config
                    else get_settings().scanner_per_detector_request_cap
                ),
            )
            self._eta_state.detector_work_units = work_units
            self._eta_state.detector_total_work = sum(work_units.values())
            self._eta_state.detector_completed_work = 0.0
            self._eta_state.detector_total_s = detector_prior_s
            self._eta_state.detector_fraction = 0.0
            self._eta_state.detector_phase_started = perf_counter()
            logger.info(
                "detector ETA model: ~%.0fs prior (%d detectors, %.0f work-units, "
                "latency=%.0fms, parallelism=%d)",
                self._eta_state.detector_total_s,
                len(active_detectors),
                self._eta_state.detector_total_work,
                self._eta_state.measured_latency_ms,
                detector_parallelism,
            )

            await self._set_phase_progress(scan, ScanPhase.vulnerability_detection, 0.0, f"Running {len(active_detectors)} active detector(s)")
            detector_metrics: list[DetectorCoverageMetric] = []
            metric_by_detector: dict[str, DetectorCoverageMetric] = {}

            def record_metric(metric: DetectorCoverageMetric) -> DetectorCoverageMetric:
                detector_metrics.append(metric)
                metric_by_detector[metric.detector] = metric
                return metric

            async def run_detector(detector) -> tuple[object, list[Finding], DetectorCoverageMetric]:
                detector_name = self._detector_name(detector)
                async with detector_semaphore:
                    self._eta_state.detector_start_times[detector_name] = perf_counter()
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
            detector_denied_counts: dict[str, int] = {}
            begin_request_counting()
            # Activate the request-budget governor so per-detector and per-parameter
            # ceilings bound traffic during vulnerability detection.
            _governor_settings = get_settings()
            begin_governor(
                _governor_settings.scanner_per_detector_request_cap,
                _governor_settings.scanner_per_parameter_request_cap,
            )
            async def _detector_progress_ticker():
                try:
                    while True:
                        await asyncio.sleep(3.0)
                        governor_counts = denied_snapshot()
                        if governor_counts:
                            total_allowed = sum(sum(stats.values()) for source, stats in governor_counts.items() if source == "allowed")
                            total_denied = sum(sum(stats.values()) for source, stats in governor_counts.items() if source != "allowed")
                            if total_allowed > 0:
                                self._eta_state.governor_denial_rate = total_denied / max(1, total_allowed)
                                
                        req_counts = snapshot_request_counts()
                        active_work = 0.0
                        for det_name, sent_reqs in req_counts.items():
                            if det_name in self._eta_state.detector_start_times and det_name not in self._eta_state.detector_elapsed_s:
                                expected = self._eta_state.detector_expected_requests.get(det_name, 1)
                                fraction = min(1.0, max(0.0, sent_reqs / max(1, expected)))
                                active_work += fraction * self._eta_state.detector_work_units.get(det_name, 0.0)
                                
                        self._eta_state.detector_completed_work = min(
                            self._eta_state.detector_total_work,
                            self._eta_state.detector_finished_work + active_work,
                        )
                        total_work = max(self._eta_state.detector_total_work, 1e-9)
                        self._eta_state.detector_fraction = self._eta_state.detector_completed_work / total_work
                        
                        await self._set_phase_progress(
                            scan,
                            ScanPhase.vulnerability_detection,
                            self._eta_state.detector_fraction,
                            f"Detectors running... {len(findings)} raw finding(s)",
                        )
                except asyncio.CancelledError:
                    pass

            try:
                ticker_task = asyncio.create_task(_detector_progress_ticker())
                # Run detectors concurrently but consume them as they finish so
                # progress ticks on work completed (not detector headcount).
                detector_total = max(1, len(active_detectors))
                detector_done = 0
                for coro in asyncio.as_completed(
                    [run_detector(detector) for detector in active_detectors]
                ):
                    result = await coro
                    detector_done += 1
                    finished_name = "unknown"
                    if isinstance(result, Exception):
                        logger.warning("detector failure: %s", result)
                        record_metric(
                            DetectorCoverageMetric(
                                detector="unknown",
                                skipped_reasons={"detector_exception": 1},
                            )
                        )
                    else:
                        finished_detector, result_findings, metric = result
                        finished_name = metric.detector or self._detector_name(finished_detector)
                        record_metric(metric)
                        findings.extend(result_findings)
                    work = self._eta_state.detector_work_units.get(finished_name, 0.0)
                    if work <= 0 and self._eta_state.detector_total_work > 0:
                        # Unknown/exception: spread remaining average so progress moves.
                        remaining_detectors = max(1, detector_total - detector_done + 1)
                        remaining_work = max(
                            0.0,
                            self._eta_state.detector_total_work - self._eta_state.detector_completed_work,
                        )
                        work = remaining_work / remaining_detectors
                        
                    if finished_name != "unknown" and finished_name in self._eta_state.detector_start_times:
                        self._eta_state.detector_elapsed_s[finished_name] = perf_counter() - self._eta_state.detector_start_times[finished_name]
                        
                    self._eta_state.detector_finished_work += work
                    self._eta_state.detector_completed_work = min(
                        self._eta_state.detector_total_work,
                        self._eta_state.detector_finished_work,
                    )
                    total_work = max(self._eta_state.detector_total_work, 1e-9)
                    self._eta_state.detector_fraction = (
                        self._eta_state.detector_completed_work / total_work
                    )
                    await self._set_phase_progress(
                        scan,
                        ScanPhase.vulnerability_detection,
                        self._eta_state.detector_fraction,
                        f"Detectors {detector_done}/{detector_total} complete: {len(findings)} raw finding(s)",
                    )
                    
                if 'ticker_task' in locals() and not ticker_task.done():
                    ticker_task.cancel()

                exception_detector = next((detector for detector in scan_detectors if isinstance(detector, ExceptionHandlingDetector)), None)
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

                auth_detector_obj = next((detector for detector in scan_detectors if isinstance(detector, AuthenticationFailuresDetector)), None)
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

                # A10/A07 derived-evidence cross-guard: when the same source finding
                # yields both a verbose-error (A10) and a credential disclosure
                # (A07) derivation, fold the verbose-error finding into the
                # credential finding so one response body isn't counted twice.
                # Only same-source derived findings merge; independent findings stay.
                self._merge_same_source_derived_findings(findings)

                # Provide the scan root URL so site-wide detectors can avoid duplicate page-level findings.
                crypto_detector = next((detector for detector in scan_detectors if isinstance(detector, CryptoFailuresDetector)), None)
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

                header_detector = next((detector for detector in scan_detectors if isinstance(detector, SecurityHeadersDetector)), None)
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

                supply_chain_findings = await scan_supply_chain.detect(
                    crawl_result.urls,
                    crawl_result.forms,
                    technologies=scan.technology_stack,
                    **crawl_context,
                )
                self._tag_detector_findings(supply_chain_findings, self._detector_name(scan_supply_chain))
                record_metric(
                    self._detector_metric_for_findings(
                        scan_supply_chain,
                        supply_chain_findings,
                        coverage_context,
                        technology_stack=scan.technology_stack,
                    )
                )
                findings.extend(supply_chain_findings)
                detector_request_counts = snapshot_request_counts()
                detector_denied_counts = denied_snapshot()
            finally:
                end_request_counting()
                end_governor()
            self._apply_detector_request_counts(
                detector_metrics,
                detector_request_counts,
                detector_denied_counts,
                coverage_context.get("attack_planner"),
            )

            await self._set_phase_progress(
                scan,
                ScanPhase.vulnerability_detection,
                1.0,
                f"Detector phase complete: {len(findings)} raw finding(s)",
            )
            await self._check_cancelled(scan_id)

            # Enrich the technology stack from error responses the detectors just
            # triggered. Stack traces / DB errors leak the framework, ORM, DB
            # engine and language (often with versions) that header/HTML/runtime
            # fingerprinting at scan start could not see. Best-effort: never fail
            # the scan over fingerprint enrichment.
            try:
                await self._enrich_tech_from_errors(scan, findings)
            except Exception as exc:
                logger.debug("error-based technology enrichment failed: %s", exc)

            # Merge repeated proof for the same normalized route and vulnerability
            # family. Verbose-error findings also keep the HTTP method so the
            # request handler and reproducer stay distinct.
            await self._set_phase_progress(scan, ScanPhase.deduplication, 0.0, "Deduplicating and filtering findings")
            findings = FindingDeduplicator.deduplicate(findings)
            logger.info("deduplication complete: %d findings after merging", len(findings))

            findings = TestPollutionFilter.filter_cross_module_contamination(findings)
            logger.info(
                "test pollution filter complete: %d findings after contamination review",
                len(findings),
            )

            # When a URL already has token-bypass-verified CSRF, drop weaker form-level
            # heuristics (e.g. missing CSRF on an auth form) that only restate it.
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

            # In verified scan mode, keep confirmed findings and a small set of
            # observation-only classes that cannot produce active exploit proof.
            # Examples: credentials in a GET query, CSRF token absence in form HTML,
            # missing security headers, cookie-attribute issues, and stack traces.
            # These are structurally true from inspection alone; dropping them would
            # hide real issues. They stay unverified so AI analysis can weight them.
            HEURISTIC_PASSTHROUGH_TYPES: tuple[str, ...] = (
                # Credential / transport exposure (request inspection)
                "credentials transmitted via http get",
                "credentials via get",
                "password in get",
                # CSRF structural absence (form HTML)
                "authentication form may lack csrf",
                "csrf protection",
                "csrf token",
                # Exposed admin / sensitive paths (content or access-control proof)
                "phpmyadmin",
                # Security-header absence (response headers)
                "missing security header",
                "security header",
                # Session / cookie attribute issues (Set-Cookie)
                "insecure session cookie",
                "cookie attribute",
                # Information disclosure (response body)
                "information disclosure",
                "server banner",
                "stack trace",
                "debug page",
                # TLS / transport (sslyze; always verified)
                "weak tls",
                "ssl configuration",
            )

            settings = get_settings()
            scan_mode = scan_config.get_val("scan_mode", getattr(settings, "scan_mode", "verified")) if scan_config else getattr(settings, "scan_mode", "verified")
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
                            # Confidence uses a 0-100 scale. Keep the finding
                            # unverified so downstream evidence weighting still applies.
                            f.confidence_score = max(f.confidence_score, 60.0)
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
            scan.report_metadata.coverage_warnings.extend(
                self._detector_coverage_warnings(detector_metrics)
            )

            # Convert raw findings to Vulnerability models, with secrets redacted.
            redaction_secrets = self._collect_redaction_secrets(submitted_accounts)
            vulnerabilities = [
                self._to_vulnerability(f, extra_secrets=redaction_secrets) for f in findings
            ]
            await self._set_phase_progress(scan, ScanPhase.deduplication, 1.0, f"Deduplication complete: {len(vulnerabilities)} finding(s)")

            # Sync severity labels from the deterministic CVSS score.
            for v in vulnerabilities:
                severity_str = CvssCalculator.get_severity(v.cvss_score)
                v.severity = SeverityLevel(severity_str)
                grade = self.evidence_grader.grade(v)
                v.evidence.evidence_grade = grade.grade
                v.evidence.evidence_grade_reason = grade.reason
                v.evidence.proof_type = grade.proof_type

            vulnerabilities = self._compute_priority_ranks(vulnerabilities)
            vulnerabilities.sort(key=lambda v: v.cvss_score, reverse=True)
            logger.info("deterministic finding processing complete: %d findings", len(vulnerabilities))

            scan.vulnerabilities = vulnerabilities
            
            # Synthesise multi-step attack chains from individual findings.
            await self._set_phase_progress(scan, ScanPhase.risk_scoring, 0.0, "Calculating severity, evidence strength, and risk score")
            scan.report_metadata.attack_chains = self._synthesize_attack_chains(vulnerabilities)
            apply_finding_rollups(scan)
            await self._set_phase_progress(scan, ScanPhase.risk_scoring, 1.0, "Risk scoring complete")

            # Model-owned report fields remain empty until the analyzer publishes
            # a completed analysis revision.
            scan.report_metadata.generated_at = None
            scan.report_metadata.generated_by = None
            scan.report_metadata.ai_model = None
            scan.report_metadata.prompt_version = None
            scan.report_metadata.summary = None

            scan.completed_at = datetime.now(timezone.utc)
            await self._set_progress(scan, 100, ScanPhase.completed, "Scan completed", status=ScanStatus.completed)
            await self._create_analysis_handoff(scan)
            logger.info("deterministic scan %s completed", scan_id)
        except asyncio.CancelledError:
            scan.completed_at = datetime.now(timezone.utc)
            scan.error_message = "Scan cancelled by user"
            await self._set_progress(scan, scan.progress, ScanPhase.cancelled, "Scan cancelled by user", status=ScanStatus.cancelled)
        except Exception as exc:
            logger.exception("scan %s failed", scan_id)
            scan.error_message = str(exc)
            scan.completed_at = datetime.now(timezone.utc)
            await self._set_progress(scan, scan.progress, ScanPhase.failed, f"Scan failed: {exc}", status=ScanStatus.failed)

    async def _create_analysis_handoff(self, scan) -> None:
        """Create and signal revision 1 without changing completed scan status."""
        analysis_repository = getattr(self, "analysis_repository", None)
        analysis_queue = getattr(self, "analysis_queue", None)
        if analysis_repository is None or analysis_queue is None:
            logger.debug("analysis handoff is not configured for scan %s", scan.id)
            return

        try:
            await ensure_initial_analysis_job(
                scan,
                scan_repository=self.repository,
                analysis_repository=analysis_repository,
                analysis_queue=analysis_queue,
            )
        except Exception:
            # Completion is already durable. A reconciler can create/attach the
            # missing job later; post-completion handoff failure must not fail scan.
            logger.exception("failed to persist analysis handoff for scan %s", scan.id)

    def _recompute_phase_weights(self, crawl_result: object) -> None:
        if self._eta_state.phase_weights is not None:
            return
            
        from app.core.scan_orchestration.progress import PHASE_WEIGHTS
        new_weights = dict(PHASE_WEIGHTS)
        
        urls = len(getattr(crawl_result, "urls", []))
        forms = len(getattr(crawl_result, "forms", []))
        endpoints = len(getattr(crawl_result, "api_endpoints", []))
        
        surface_size = urls + forms * 2 + endpoints * 2
        if surface_size > 500:
            new_weights[ScanPhase.vulnerability_detection] = 70
            new_weights[ScanPhase.crawling] = 12
        elif surface_size < 10:
            new_weights[ScanPhase.vulnerability_detection] = 20
            new_weights[ScanPhase.crawling] = 50
            
        total = sum(new_weights.values())
        if total != 100:
            factor = 100.0 / max(1.0, total)
            new_weights = {k: round(v * factor) for k, v in new_weights.items()}
            
        self._eta_state.phase_weights = new_weights
