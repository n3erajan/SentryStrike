from app.config import get_settings
from app.core.detectors.attack_surface import AttackSurface
from shared.models.scan import AuthCoverage, SpaApiCoverage


class CoverageMixin:
    @staticmethod
    def _count_discovered_surface(crawl_result) -> int:
        """Distinct discovered URLs across the HTTP spider, SPA routes, and API endpoints.

        ``crawl_result.urls`` alone only holds the HTTP-spider seed surface — for a
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

        # Dynamic-discovery health classification (Task 11): never present a
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
        # only the HTTP-spider seed surface — for a browser-crawled SPA that is
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

        Only SPA targets can be "degraded" — a static site never needed the
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
        scan_config = ctx.get("scan_config")
        oast_callback = (
            (scan_config.oast_callback_base_url if scan_config else None)
            or settings.oast_callback_base_url
        )
        oast_poll = (
            (scan_config.oast_poll_url if scan_config else None)
            or settings.oast_poll_url
        )
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

