import logging

from app.config import get_settings
from app.core.detectors.attack_planner import AttackPlanner
from app.core.detectors.base_detector import Finding
from shared.models.scan import DetectorCoverageMetric
from shared.schemas.scan_schema import ScanConfig

logger = logging.getLogger("app.core.scanner")


ATTACK_SURFACE_BACKED_DETECTORS = frozenset(
    {
        "access_control",
        "injection_sql_command",
        "nosql_injection",
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


class DetectorExecutionMixin:
    def _detector_name(self, detector: object) -> str:
        return str(getattr(detector, "name", None) or detector.__class__.__name__)

    def _tag_detector_findings(self, findings: list[Finding], detector_name: str) -> None:
        for finding in findings or []:
            setattr(finding, "detector_name", detector_name)

    @staticmethod
    def _merge_same_source_derived_findings(findings: list[Finding]) -> None:
        """Fold same-source derived A10 (Verbose Error) findings into matching
        A07 (Credential / Config Disclosure) findings in place.

        Only findings derived from observed evidence (detection_method of
        ``observed_exception_evidence`` and ``observed_credential_disclosure``)
        that share the same source-finding key (url, parameter, source vuln
        type, source detection method) are merged. The A07 finding stays primary
        and records the verbose-error patterns as supporting evidence; the A10
        finding is dropped. Independent findings are never merged, so A10 and
        A07 findings that do not share a source stay as-is.
        """
        verbose_method = "observed_exception_evidence"
        credential_method = "observed_credential_disclosure"

        def _source_key(finding: Finding) -> tuple:
            evidence = finding.detection_evidence or {}
            return (
                finding.url or "",
                finding.parameter or "",
                str(evidence.get("source_vuln_type") or ""),
                str(evidence.get("source_detection_method") or ""),
            )

        credential_by_key: dict[tuple, Finding] = {}
        for finding in findings:
            if getattr(finding, "detection_method", None) == credential_method:
                key = _source_key(finding)
                if key not in credential_by_key:
                    credential_by_key[key] = finding

        if not credential_by_key:
            return

        merged: list[Finding] = []
        for finding in findings:
            if getattr(finding, "detection_method", None) != verbose_method:
                merged.append(finding)
                continue
            primary = credential_by_key.get(_source_key(finding))
            if primary is None:
                merged.append(finding)
                continue
            verbose_patterns = (finding.detection_evidence or {}).get("matched_patterns", [])
            primary_evidence = primary.detection_evidence or {}
            supporting = primary_evidence.get("supporting_verbose_error_patterns", [])
            for pattern in verbose_patterns:
                if pattern not in supporting:
                    supporting.append(pattern)
            primary_evidence["supporting_verbose_error_patterns"] = supporting
            if finding.evidence:
                prior = primary_evidence.get("supporting_verbose_evidence", "")
                primary_evidence["supporting_verbose_evidence"] = (
                    f"{prior}\n{finding.evidence}".strip()
                )
            primary.detection_evidence = primary_evidence
            if verbose_patterns:
                primary.evidence = (primary.evidence or "") + (
                    f" Verbose error disclosure also observed in the same response: "
                    f"{', '.join(verbose_patterns[:2])}."
                )
            # Drop the verbose-error finding; it has been folded into the
            # credential disclosure finding above.
        findings.clear()
        findings.extend(merged)

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
        planner = crawl_context.get("attack_planner")
        planner_summary: dict[str, object] = {}
        if isinstance(planner, AttackPlanner):
            # Baseline summary with zero real attempts/denies. Real governor
            # attempted/denied counts are applied post-loop in
            # _apply_detector_request_counts, which recomputes these fields; this
            # baseline deliberately never infers budget_exhausted from findings.
            planner_summary = planner.coverage_summary(
                detector_name,
                attempted_count=0,
                denied_count=0,
            )
            candidates_built = max(
                candidates_built,
                int(planner_summary.get("targets_seen", 0) or 0),
            )
        skipped_reasons = self._detector_skip_reasons(detector_name, candidates_built, findings, crawl_context)
        if candidates_built == 0 and not findings:
            skipped_reasons["no_candidates_built"] = 1

        scan_config: ScanConfig | None = crawl_context.get("scan_config")
        settings = get_settings()
        if detector_name == "access_control" and not (
            crawl_context.get("second_user_cookies") or crawl_context.get("second_user_headers")
        ):
            skipped_reasons["second_user_account_missing"] = 1
        if detector_name == "ssrf":
            oast_callback = (
                (scan_config.oast_callback_base_url if scan_config else None)
                or settings.oast_callback_base_url
            )
            oast_poll = (
                (scan_config.oast_poll_url if scan_config else None)
                or settings.oast_poll_url
            )
            if not (oast_callback and oast_poll):
                # OAST-verified blind SSRF is unavailable, but the in-band differential
                # fallback still runs (probable/unverified findings). Flag it as a
                # confidence-limiting gap rather than a hard skip.
                skipped_reasons["oast_callback_missing_inband_only"] = 1

        return DetectorCoverageMetric(
            detector=detector_name,
            candidates_built=candidates_built,
            requests_sent=self._request_snippet_count(findings),
            targets_attempted=int(planner_summary.get("targets_attempted", 0) or 0),
            requests_denied_by_governor=int(planner_summary.get("requests_denied_by_governor", 0) or 0),
            verified_findings=len([finding for finding in findings or [] if getattr(finding, "verified", False)]),
            unverified_findings=len([finding for finding in findings or [] if not getattr(finding, "verified", False)]),
            replayable_targets_seen=int(planner_summary.get("replayable_targets_seen", 0) or 0),
            replayable_targets_tested=int(planner_summary.get("replayable_targets_tested", 0) or 0),
            validated_synth_targets_tested=int(planner_summary.get("validated_synth_targets_tested", 0) or 0),
            body_targets_skipped=int(planner_summary.get("body_targets_skipped", 0) or 0),
            body_targets_skipped_by_reason=dict(
                planner_summary.get("body_targets_skipped_by_reason", {}) or {}
            ),
            skip_reason_by_risk=dict(planner_summary.get("skip_reason_by_risk", {}) or {}),
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
        request_audit_summary = crawl_context.get("request_audit_summary") or {}
        auth_headers = crawl_context.get("auth_headers") or {}
        session_cookies = crawl_context.get("session_cookies") or {}
        browser_forms = crawl_context.get("browser_forms") or []
        browser_available = crawl_context.get("browser_available")

        replayable_body_count = len(
            [
                request
                for request in requests
                if getattr(request, "post_data", None)
            ]
        )
        # Static body synthesis (Task 4) makes bodies testable even without an
        # observed request body, so only report the coverage gap when nothing —
        # observed or synthesizable — could feed a body-injection detector.
        synthesizable_body_endpoints = 0
        if not replayable_body_count and api_endpoints:
            from app.core.crawler.api_extractor import ApiExtractor

            synthesizable_body_endpoints = sum(
                1
                for endpoint in api_endpoints
                if ApiExtractor.synthesize_body_schema(endpoint)[1]
            )
        if detector_name in {
            "access_control",
            "authentication_failures",
            "csrf",
        } and not (auth_headers or session_cookies):
            skipped["missing_auth_context"] = 1
        if detector_name == "csrf" and not session_cookies and not auth_headers:
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
        if (
            detector_name in {"injection_sql_command", "xss", "file_inclusion"}
            and not replayable_body_count
            and not synthesizable_body_endpoints
        ):
            skipped["no_replayable_request_bodies"] = 1
        for reason, count in request_audit_summary.items():
            if reason in {"transport_noise", "resource_noise"}:
                continue
            if str(reason).startswith("body_") or reason in {
                "unsupported_content_type",
                "unparseable_json",
                "empty_body",
            }:
                skipped[f"browser_body_{reason}"] = int(count)
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
            browser_forms = crawl_context.get("browser_forms") or []
            return max(len(forms) + len(browser_forms) + len(requests), len(findings or []))
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
            "nosql_injection": ("nosql_injection", "nosqli"),
        }
        return aliases.get(detector_name, (detector_name,))

    def _apply_detector_request_counts(
        self,
        detector_metrics: list[DetectorCoverageMetric],
        request_counts: dict[str, int],
        denied_counts: dict[str, int] | None = None,
        planner: "AttackPlanner | None" = None,
    ) -> None:
        denied_counts = denied_counts or {}
        matched_modules: set[str] = set()
        for metric in detector_metrics:
            aliases = self._detector_request_aliases(metric.detector)
            request_total = sum(request_counts.get(alias, 0) for alias in aliases)
            denied_total = sum(denied_counts.get(alias, 0) for alias in aliases)
            metric.targets_attempted = request_total
            metric.requests_denied_by_governor = denied_total
            # Recompute the planner-derived coverage fields from the REAL
            # governor attempted/denied counts, replacing the zero-attempt
            # baseline set during the detector loop. budget_exhausted is now
            # attributed strictly from denied_total — never a finding shortfall.
            if isinstance(planner, AttackPlanner):
                summary = planner.coverage_summary(
                    metric.detector,
                    attempted_count=request_total,
                    denied_count=denied_total,
                )
                metric.replayable_targets_tested = int(summary.get("replayable_targets_tested", 0) or 0)
                metric.validated_synth_targets_tested = int(summary.get("validated_synth_targets_tested", 0) or 0)
                metric.body_targets_skipped = int(summary.get("body_targets_skipped", 0) or 0)
                metric.body_targets_skipped_by_reason = dict(summary.get("body_targets_skipped_by_reason", {}) or {})
                metric.skip_reason_by_risk = dict(summary.get("skip_reason_by_risk", {}) or {})
            if request_total:
                metric.requests_sent = max(metric.requests_sent, request_total)
                if not isinstance(planner, AttackPlanner):
                    metric.replayable_targets_tested = max(
                        metric.replayable_targets_tested,
                        min(metric.replayable_targets_seen, request_total),
                    )
                matched_modules.update(aliases)

        for module, count in request_counts.items():
            if module in matched_modules:
                continue
            detector_metrics.append(
                DetectorCoverageMetric(
                    detector=module,
                    requests_sent=count,
                    candidates_built=count,
                    targets_attempted=count,
                    requests_denied_by_governor=sum(
                        denied_counts.get(alias, 0)
                        for alias in self._detector_request_aliases(module)
                    ),
                )
            )

    def _log_detector_coverage(self, detector_metrics: list[DetectorCoverageMetric]) -> None:
        for metric in detector_metrics:
            logger.info(
                "detector coverage: detector=%s candidates_built=%d requests_sent=%d "
                "verified_findings=%d unverified_findings=%d dropped_verified_mode=%d "
                "replayable_seen=%d replayable_tested=%d body_skipped=%d "
                "body_skipped_by_reason=%s skipped_reasons=%s",
                metric.detector,
                metric.candidates_built,
                metric.requests_sent,
                metric.verified_findings,
                metric.unverified_findings,
                metric.dropped_findings_verified_mode,
                metric.replayable_targets_seen,
                metric.replayable_targets_tested,
                metric.body_targets_skipped,
                metric.body_targets_skipped_by_reason,
                metric.skipped_reasons,
            )

    def _detector_coverage_warnings(
        self, detector_metrics: list[DetectorCoverageMetric]
    ) -> list[str]:
        """Surface 0-request detectors as explicit coverage warnings.

        A detector that built candidates but sent 0 requests represents a silent
        coverage gap — either every candidate was filtered, the budget governor
        denied everything, or a structural prerequisite was missing. Each of
        these is already recorded in ``skipped_reasons``; this method lifts the
        gap to a top-level ``coverage_warning`` so an operator reading the report
        sees it without drilling into per-detector metrics. Detectors that built
        0 candidates are not warned here (no gap — there was nothing to test).
        """
        warnings: list[str] = []
        for metric in detector_metrics:
            if metric.candidates_built > 0 and metric.requests_sent == 0:
                # Prefer the most informative skip reason when available.
                reason = (
                    ", ".join(
                        f"{k}={v}" for k, v in metric.skipped_reasons.items() if v
                    )
                    or "no requests dispatched"
                )
                warnings.append(
                    f"detector '{metric.detector}' built {metric.candidates_built} "
                    f"candidate(s) but sent 0 requests ({reason}); "
                    "coverage gap — findings for this class are absent by design, "
                    "not by confirmation."
                )
        return warnings
