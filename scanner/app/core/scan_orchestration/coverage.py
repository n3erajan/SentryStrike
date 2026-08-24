from app.config import get_settings
from app.core.detectors.attack_surface import AttackSurface
from app.core.scan_orchestration.detector_execution import DETECTOR_REQUEST_ALIASES
from app.utils.scan_metrics import TestedSurfaceEntry
from shared.models.scan import (
    AuthCoverage,
    ScanCoverage,
    SpaApiCoverage,
    ProbedParameter,
    ProbedPath,
)

# Storage ceilings for the persisted inventory. The ledger itself is capped
# separately (app.utils.scan_metrics.LEDGER_MAX_ENTRIES); these bound what is
# written to the scan document and served in the JSON report. Whatever is left
# out is counted, never silently dropped.
MAX_TESTED_PATHS = 500
MAX_PARAMETERS_PER_PATH = 40

# Module labels that carry HTTP traffic but are not detectors. Paths they
# reached are real coverage of the surface (the scanner did request them), so
# they stay in the inventory; they just do not count as active testing.
NON_DETECTOR_MODULES = frozenset({"crawler"})

# Statuses that prove the target does not serve a path. A probe answered only by
# these established absence - the scanner looked, the resource was not there - so
# the path is not application surface that got tested. Everything else (2xx, 3xx,
# 401/403 protected, 405 wrong method, 5xx) means the path exists in some form.
ABSENT_STATUS_CODES = frozenset({404, 410})

# Reverse of the detector alias table: the ledger records the ``module=`` label
# a request was tagged with (e.g. "sqli"), and the report names detectors
# ("injection_sql_command"). Same detector, one canonical name.
_MODULE_TO_DETECTOR = {
    alias: detector
    for detector, aliases in DETECTOR_REQUEST_ALIASES.items()
    for alias in aliases
}


def canonical_detector(module: str) -> str:
    """Canonical detector name for a ledger ``module`` label."""
    return _MODULE_TO_DETECTOR.get(module, module)


def build_tested_surface(
    entries: list[TestedSurfaceEntry],
    *,
    totals: dict[str, int] | None = None,
    requests_denied_by_budget: int = 0,
) -> ScanCoverage:
    """Aggregate ledger entries into the report's tested-surface inventory.

    Every figure is derived from requests that actually went out - nothing here
    is estimated from discovered surface or from finding counts.

    Crucially, a path is only counted as *tested surface* when the target showed
    it exists. Path-guessing detectors (sensitive_paths in particular) probe
    thousands of candidate URLs that the app never served; counting those 404s as
    "paths reached" inflates coverage into fiction - a DVWA scan reporting 2,873
    tested paths when the app has a few dozen. Paths whose every response was
    404/410 are therefore reported separately as negative existence probes, and
    are not itemised: they establish absence, not coverage.

    Paths are ranked by how much of them was exercised (parameters, then
    requests) so that if the inventory is truncated, the best-covered surface is
    what survives, and the omitted remainder is reported as a count.
    """
    totals = totals or {}
    by_path: dict[str, dict] = {}
    for entry in entries:
        detector = canonical_detector(entry.module)
        bucket = by_path.setdefault(
            entry.path,
            {
                "methods": set(),
                "detectors": set(),
                "parameters": {},
                "requests": 0,
                "status_codes": set(),
                "no_response": 0,
            },
        )
        bucket["methods"].add(entry.method)
        bucket["detectors"].add(detector)
        bucket["requests"] += entry.requests
        bucket["status_codes"].update(entry.status_codes)
        bucket["no_response"] += entry.no_response
        if entry.parameter:
            parameter = bucket["parameters"].setdefault(
                entry.parameter, {"detectors": set(), "requests": 0}
            )
            parameter["detectors"].add(detector)
            parameter["requests"] += entry.requests

    real: dict[str, dict] = {}
    missing: dict[str, dict] = {}
    unconfirmed: dict[str, dict] = {}
    for path, bucket in by_path.items():
        statuses = bucket["status_codes"]
        if not statuses:
            # Every probe went unanswered, so existence was never established.
            unconfirmed[path] = bucket
        elif statuses <= ABSENT_STATUS_CODES:
            missing[path] = bucket
        else:
            real[path] = bucket

    detectors_exercised = sorted(
        {
            detector
            for bucket in by_path.values()
            for detector in bucket["detectors"]
            if detector not in NON_DETECTOR_MODULES
        }
    )
    paths_probed_by_detector = sum(
        1 for bucket in real.values() if bucket["detectors"] - NON_DETECTOR_MODULES
    )
    parameters_tested = len(
        {(path, name) for path, bucket in real.items() for name in bucket["parameters"]}
    )

    ranked = sorted(
        real.items(),
        key=lambda item: (-len(item[1]["parameters"]), -item[1]["requests"], item[0]),
    )
    tested_paths: list[ProbedPath] = []
    for path, bucket in ranked[:MAX_TESTED_PATHS]:
        parameters = sorted(
            bucket["parameters"].items(),
            key=lambda item: (-item[1]["requests"], item[0]),
        )
        tested_paths.append(
            ProbedPath(
                path=path,
                methods=sorted(bucket["methods"]),
                parameters=[
                    ProbedParameter(
                        name=name,
                        detectors=sorted(stats["detectors"]),
                        requests=stats["requests"],
                    )
                    for name, stats in parameters[:MAX_PARAMETERS_PER_PATH]
                ],
                detectors=sorted(bucket["detectors"]),
                requests=bucket["requests"],
                status_codes=sorted(bucket["status_codes"]),
                no_response=bucket["no_response"],
                parameters_omitted=max(0, len(parameters) - MAX_PARAMETERS_PER_PATH),
            )
        )

    return ScanCoverage(
        paths_tested=len(real),
        paths_probed_by_detector=paths_probed_by_detector,
        paths_absent=len(missing),
        paths_existence_unconfirmed=len(unconfirmed),
        requests_to_absent_paths=sum(bucket["requests"] for bucket in missing.values()),
        parameters_tested=parameters_tested,
        requests_sent=int(totals.get("total_requests", 0) or 0)
        or sum(entry.requests for entry in entries),
        requests_without_response=int(totals.get("total_no_response", 0) or 0),
        requests_denied_by_budget=max(0, int(requests_denied_by_budget)),
        detectors_exercised=detectors_exercised,
        tested_paths=tested_paths,
        tested_paths_truncated=len(real) > MAX_TESTED_PATHS,
        tested_paths_omitted=max(0, len(real) - MAX_TESTED_PATHS),
        ledger_entries_omitted=int(totals.get("omitted", 0) or 0),
        # Playwright probes bypass the HTTP ledger; nothing here itemises them.
        browser_probes_itemised=False,
    )


class CoverageMixin:
    def _capture_tested_surface(
        self, scan: 'Scan', requests_denied_by_budget: int = 0
    ) -> ScanCoverage:
        """Snapshot the tested-surface ledger onto the scan's report metadata.

        Must be called while the scan's request-counting context is still live
        (before ``end_request_counting()``), since the ledger is ContextVar-scoped
        to the run.
        """
        from app.utils.scan_metrics import snapshot_tested_surface, tested_surface_totals

        coverage = build_tested_surface(
            snapshot_tested_surface(),
            totals=tested_surface_totals(),
            requests_denied_by_budget=requests_denied_by_budget,
        )
        scan.report_metadata.tested_surface = coverage
        return coverage

    @staticmethod
    def _count_discovered_surface(crawl_result) -> int:
        """Distinct discovered URLs across the HTTP spider, SPA routes, and API endpoints.

        ``crawl_result.urls`` alone only holds the HTTP-spider seed surface - for a
        browser-crawled SPA that is often just the shell (1 URL), which badly understates
        coverage. The honest "URLs crawled" figure is the deduplicated union of the pages
        navigated (``routes``) and the API endpoints discovered (``api_endpoints``) plus
        the HTTP URLs. Same-origin/dead-route filtering has already been applied upstream.
        """
        discovered: set[str] = set()
        for url in getattr(crawl_result, "urls", []) or []:
            if url:
                discovered.add(url)
        for route in getattr(crawl_result, "routes", []) or []:
            url = getattr(route, "url", "")
            if url:
                discovered.add(url)
        for endpoint in getattr(crawl_result, "api_endpoints", []) or []:
            url = getattr(endpoint, "url", "")
            if url:
                discovered.add(url)
        return len(discovered)

    @staticmethod
    def _count_protected_targets_verified(crawl_result) -> int:
        """Distinct data endpoints the authenticated session actually reached with
        an authorized (2xx) response.

        Under a verified session every observed browser request carries the
        session, so a 2xx response to a genuine data endpoint (a JSON/data body,
        or any state-changing method) is a protected resource we confirmed
        authenticated access to. Static assets and the HTML shell are excluded so
        the figure reflects real application surface, not page chrome. Replaces the
        former hardcoded ``1`` placeholder with a truthful, framework-agnostic
        count (keyed on HTTP shape only, no app-specific paths). Returns 0 when the
        crawl observed no such responses (e.g. a static site with no XHR)."""
        from urllib.parse import urlparse

        from app.core.crawler.url_parser import is_static_asset

        verified: set[tuple[str, str]] = set()
        for observation in getattr(crawl_result, "requests", []) or []:
            status = getattr(observation, "response_status", None)
            try:
                status_int = int(status) if status is not None else 0
            except (TypeError, ValueError):
                continue
            if not (200 <= status_int < 300):
                continue
            url = str(getattr(observation, "url", "") or "")
            if not url or is_static_asset(url):
                continue
            method = str(getattr(observation, "method", "GET") or "GET").upper()
            content_type = str(getattr(observation, "response_content_type", "") or "").lower()
            is_data = "json" in content_type or method in {"POST", "PUT", "PATCH", "DELETE"}
            if not is_data:
                continue
            # Collapse query strings so ?id=1 vs ?id=2 count as one protected target.
            path_key = urlparse(url)._replace(query="", fragment="").geturl()
            verified.add((method, path_key))
        return len(verified)

    def _update_crawl_metadata(self, scan: 'Scan', crawl_result, crawl_context: dict | None = None) -> None:
        auth_state = getattr(crawl_result, "auth_state", "unauthenticated")
        auth_state_value = auth_state.value if hasattr(auth_state, "value") else str(auth_state)
        has_session = bool(getattr(crawl_result, "session_cookies", {}) or {})
        has_headers = bool(getattr(crawl_result, "auth_headers", {}) or {})
        verified = auth_state_value == "authenticated_verified"
        is_spa = bool(getattr(crawl_result, "is_spa", False))
        requests = getattr(crawl_result, "requests", []) or []
        post_bodies = len([request for request in requests if getattr(request, "post_data", None)])
        browser_forms_submitted = int(getattr(crawl_result, "browser_forms_submitted", 0) or 0)
        replayable_json_bodies = len(
            [
                request
                for request in requests
                if getattr(request, "post_data", None)
                and getattr(request, "replayable", True)
                and "json" in self._request_content_type(request)
            ]
        )
        body_target_telemetry = AttackSurface.body_target_telemetry(
            api_endpoints=getattr(crawl_result, "api_endpoints", []) or [],
            requests=requests,
        )
        browser_available = getattr(crawl_result, "browser_available", None)
        browser_error = getattr(crawl_result, "browser_error", None)
        static_spa_only = is_spa and len(requests) == 0

        # Dynamic-discovery health classification: never present a
        # dynamically-degraded SPA scan as a clean full scan.
        dynamic_status = self._classify_dynamic_status(
            is_spa=is_spa,
            browser_available=browser_available,
            browser_error=browser_error,
            browser_requests_observed=len(requests),
            browser_forms_submitted=browser_forms_submitted,
            post_bodies=post_bodies,
        )

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
            observed_json_body_targets=body_target_telemetry["observed_json_body_targets"],
            observed_form_body_targets=body_target_telemetry["observed_form_body_targets"],
            static_synth_body_targets=body_target_telemetry["static_synth_body_targets"],
            derived_update_body_targets=body_target_telemetry.get("derived_update_body_targets", 0),
            skipped_unresolved_body_targets=body_target_telemetry["skipped_unresolved_body_targets"],
            post_bodies=post_bodies,
            workflow_states_visited=int(getattr(crawl_result, "workflow_states_visited", 0) or 0),
            browser_forms_discovered=int(getattr(crawl_result, "browser_forms_discovered", 0) or 0),
            browser_forms_submitted=browser_forms_submitted,
            file_inputs_discovered=int(getattr(crawl_result, "file_inputs_discovered", 0) or 0),
            dynamic_status=dynamic_status,
        )
        # Authenticated surface actually scanned. ``crawl_result.urls`` alone holds
        # only the HTTP-spider seed surface - for a browser-crawled SPA that is
        # often just the shell (1 URL), which badly understates coverage. Use the
        # deduplicated union of pages navigated + API endpoints reached, exactly as
        # ``total_urls_crawled`` does, so the auth-coverage figure is truthful.
        scanned_surface = self._count_discovered_surface(crawl_result)
        protected_verified = self._count_protected_targets_verified(crawl_result) if verified else 0
        scan.report_metadata.auth_coverage = AuthCoverage(
            state=auth_state_value,
            authenticated_url_count=scanned_surface if verified else 0,
            unauthenticated_url_count=0 if verified else scanned_surface,
            protected_targets_verified=protected_verified,
            auth_headers_present=has_headers,
            session_cookies_present=has_session,
        )
        scan.report_metadata.coverage_warnings = self._coverage_warnings(crawl_result, dynamic_status, crawl_context)

    @staticmethod
    def _classify_dynamic_status(
        *,
        is_spa: bool,
        browser_available: bool | None,
        browser_error: str | None,
        browser_requests_observed: int,
        browser_forms_submitted: int = 0,
        post_bodies: int = 0,
    ) -> str:
        """Classify dynamic-discovery health for honest reporting.

        Only SPA targets can be "degraded" - a static site never needed the
        browser. ``dynamic_failed`` when the browser could not run at all;
        ``dynamic_partial`` when it launched but yielded nothing usable or was
        truncated; ``dynamic_ok`` otherwise.
        """
        if not is_spa:
            return "dynamic_ok"
        if not browser_available:
            return "dynamic_failed"
        if browser_requests_observed == 0 or browser_error:
            return "dynamic_partial"
        if browser_forms_submitted > 0 and post_bodies == 0:
            return "dynamic_partial"
        return "dynamic_ok"

    def _coverage_warnings(self, crawl_result, dynamic_status: str = "dynamic_ok", crawl_context: dict | None = None) -> list[str]:
        warnings: list[str] = []
        # Prominent, top-level honesty banner when dynamic discovery degraded, so
        # a browser-dependent scan is never presented as a clean full scan. The
        # browser-dependent classes (XSS/CSRF/file-upload/SSRF/IDOR) have limited
        # confidence in this state.
        if dynamic_status == "dynamic_failed":
            warnings.append(
                "DYNAMIC DISCOVERY FAILED: the target is a SPA but the browser crawl did not run, "
                "so testing fell back to static extraction only. Coverage of DOM XSS, CSRF, file "
                "upload, SSRF, and IDOR is limited and their absence is not conclusive."
            )
        elif dynamic_status == "dynamic_partial":
            warnings.append(
                "DYNAMIC DISCOVERY PARTIAL: the browser crawl launched but was truncated or observed "
                "no runtime requests, so dynamic coverage is incomplete. Findings for DOM XSS, CSRF, "
                "file upload, SSRF, and IDOR have reduced confidence."
            )
        is_spa = bool(getattr(crawl_result, "is_spa", False))
        requests = getattr(crawl_result, "requests", []) or []
        forms = getattr(crawl_result, "forms", []) or []
        auth_headers = getattr(crawl_result, "auth_headers", {}) or {}
        session_cookies = getattr(crawl_result, "session_cookies", {}) or {}
        browser_available = getattr(crawl_result, "browser_available", None)
        browser_error = getattr(crawl_result, "browser_error", None)
        browser_forms = int(getattr(crawl_result, "browser_forms_discovered", 0) or 0)
        browser_forms_submitted = int(getattr(crawl_result, "browser_forms_submitted", 0) or 0)
        file_inputs = int(getattr(crawl_result, "file_inputs_discovered", 0) or 0)
        replayable_json_bodies = [
            request
            for request in requests
            if getattr(request, "post_data", None)
            and getattr(request, "replayable", True)
            and "json" in self._request_content_type(request)
        ]
        replayable_form_bodies = [
            request
            for request in requests
            if getattr(request, "post_data", None)
            and getattr(request, "replayable", True)
            and (
                "application/x-www-form-urlencoded" in self._request_content_type(request)
                or "multipart/form-data" in self._request_content_type(request)
            )
        ]
        body_target_telemetry = AttackSurface.body_target_telemetry(
            api_endpoints=getattr(crawl_result, "api_endpoints", []) or [],
            requests=requests,
        )
        if is_spa and not requests:
            warnings.append(
                "SPA detected, but no browser runtime requests were observed. API coverage is static extraction only."
            )
        if browser_available is False:
            warnings.append(f"Browser crawling unavailable: {browser_error or 'Playwright could not run.'}")
        if not forms and not browser_forms:
            warnings.append("No HTML forms were discovered; form-based detector coverage was limited.")
        if not replayable_json_bodies and not replayable_form_bodies:
            static_count = body_target_telemetry["static_synth_body_targets"]
            if static_count:
                warnings.append(
                    "No replayable JSON or form request bodies were observed; API body testing used "
                    f"{static_count} low-confidence static synthesized body target(s)."
                )
            else:
                warnings.append("No replayable JSON or form request bodies were observed; API body testing was limited.")
        if browser_forms_submitted > 0 and not any(getattr(request, "post_data", None) for request in requests):
            warnings.append(
                "Browser submitted form/workflow actions, but no replayable POST bodies were captured; "
                "dynamic request-body coverage is degraded."
            )
        skipped_unresolved = body_target_telemetry["skipped_unresolved_body_targets"]
        if skipped_unresolved:
            warnings.append(
                f"Skipped {skipped_unresolved} static body target(s) with unresolved path placeholders; "
                "the crawler needs observed IDs or route parameters before those APIs can be safely probed."
            )
        if auth_headers and not session_cookies:
            warnings.append("Authentication was represented by headers only; cookie/session checks were limited.")
        if file_inputs == 0:
            warnings.append("No browser-visible file inputs were discovered; upload candidate coverage was limited.")
        settings = get_settings()
        ctx = crawl_context or {}
        if not (ctx.get("second_user_cookies") or ctx.get("second_user_headers")):
            warnings.append("No second-user account configured; horizontal IDOR comparison was not tested.")
        oast_callback = settings.oast_callback_base_url
        oast_poll = settings.oast_poll_url
        if not (oast_callback and oast_poll):
            warnings.append(
                "OAST callback/polling is not fully configured; blind SSRF was "
                "assessed with the in-band differential fallback only, so SSRF findings "
                "are probable/unverified. Configure OAST_CALLBACK_BASE_URL and OAST_POLL_URL "
                "for confirmed blind SSRF."
            )
        return warnings

    @staticmethod
    def _request_content_type(request) -> str:
        if getattr(request, "request_content_type", None):
            return str(request.request_content_type).lower()
        for name, value in (getattr(request, "request_headers", {}) or {}).items():
            if str(name).lower() == "content-type":
                return str(value).lower()
        return ""

