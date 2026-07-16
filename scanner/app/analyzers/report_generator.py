from datetime import datetime, timezone

from app.analyzers.ai_client import AIClient
from app.config import get_settings
from shared.models.scan import AuthCoverage, DetectorCoverageMetric, EvidenceStrengthBreakdown, Scan, SpaApiCoverage


class AiReportGenerator:
    def __init__(self) -> None:
        self.client = AIClient()

    async def generate(self, scan: Scan) -> dict:
        technologies = getattr(scan, "technology_stack", []) or []
        technology_lines = []
        for tech in technologies:
            version = getattr(tech, "version", None) or "unknown version"
            category = getattr(tech, "category", None) or "unknown"
            cves = getattr(tech, "cves", []) or []
            cve_text = ", ".join(cves) if cves else "no known CVEs found"
            technology_lines.append(f"{getattr(tech, 'name', 'Unknown')} {version} ({category}; {cve_text})")
        technologies_detected = "; ".join(technology_lines) if technology_lines else "No technologies detected."

        chains_info = ""
        if scan.report_metadata.attack_chains:
            chains_str = "; ".join(f"[{c.severity}] {c.description}" for c in scan.report_metadata.attack_chains)
            chains_info = f" Attack Chains identified: {chains_str}."

        strength = getattr(scan.report_metadata, "evidence_strength_breakdown", EvidenceStrengthBreakdown())
        spa_api = getattr(scan.report_metadata, "spa_api_coverage", SpaApiCoverage())
        auth = getattr(scan.report_metadata, "auth_coverage", AuthCoverage())
        coverage_warnings = getattr(scan.report_metadata, "coverage_warnings", []) or []
        coverage_warning_text = "; ".join(coverage_warnings) if coverage_warnings else "None."
        detector_coverage = getattr(scan.report_metadata, "detector_coverage", []) or []
        detector_coverage_text = self._detector_coverage_text(detector_coverage)
        confirmed_exploit_paths = [
            f"{v.vuln_type} at {v.location.url}"
            for v in getattr(scan, "vulnerabilities", []) or []
            if (getattr(getattr(v, "evidence_strength", ""), "value", getattr(v, "evidence_strength", "")) == "confirmed_exploit")
        ][:5]
        needs_review = [
            f"{v.vuln_type} at {v.location.url}"
            for v in getattr(scan, "vulnerabilities", []) or []
            if (getattr(getattr(v, "review_status", ""), "value", getattr(v, "review_status", "")) == "needs_review")
        ][:5]

        fallback = {
            "executive_summary": "The scan identified security weaknesses requiring remediation.",
            "technical_analysis": "Multiple findings indicate input handling and configuration risks.",
            "recommendations": "Fix critical and high findings first; add security headers; harden authentication controls; implement secure SDLC checks in CI/CD",
            "overall_risk_assessment": "Moderate to high risk depending on internet exposure.",
            "technologies_detected": technologies_detected,
            "confirmed_critical_exploit_paths": "; ".join(confirmed_exploit_paths) or "None.",
            "confirmed_observations": f"{strength.confirmed_observation} confirmed observation findings.",
            "probable_issues": f"{strength.probable} probable findings require validation.",
            "needs_review": "; ".join(needs_review) or "None.",
            "attack_chains": chains_info.strip() or "No deterministic attack chains synthesized.",
            "authenticated_coverage": f"Auth state: {auth.state}; authenticated URLs: {auth.authenticated_url_count}.",
            "spa_api_coverage": (
                f"SPA detected: {spa_api.spa_detected}; API endpoints: {spa_api.api_endpoints_extracted}; "
                f"browser requests: {spa_api.browser_requests_observed}; static SPA only: {spa_api.static_spa_only}."
            ),
            "remediation_roadmap": "Prioritize confirmed exploits, then confirmed observations, then probable and review-needed issues.",
            "scanner_limitations": (
                f"Coverage warnings: {coverage_warning_text} A06, A08, and A09 are disclosed as out of active "
                f"automated detection scope. Detector coverage: {detector_coverage_text}."
            ),
        }
        # When AI analysis is disabled, skip the LLM call and return the
        # deterministic fallback directly (no model round-trip).
        if not get_settings().ai_analysis_enabled:
            result = dict(fallback)
            result["generated_at"] = datetime.now(timezone.utc).isoformat()
            return result
        prompt = (
            "Generate a security report as strict JSON with these exact keys (all string values): "
            "executive_summary (1-2 sentences), technical_analysis (detailed findings), "
            "recommendations (comma-separated list), overall_risk_assessment (risk level + reasoning), "
            "technologies_detected (detected stack with known CVEs, if any), "
            "confirmed_critical_exploit_paths, confirmed_observations, probable_issues, "
            "needs_review, attack_chains, authenticated_coverage, spa_api_coverage, "
            "remediation_roadmap, scanner_limitations.\n"
            f"Scan target: {scan.target_url}, total vulnerabilities: {scan.statistics.total_vulnerabilities}, "
            f"risk score: {scan.overall_risk_score}. "
            f"Severity breakdown: {scan.statistics.severity_breakdown.critical} Critical, "
            f"{scan.statistics.severity_breakdown.high} High, {scan.statistics.severity_breakdown.medium} Medium. "
            f"Evidence strength distribution: confirmed_exploit={strength.confirmed_exploit}, "
            f"confirmed_observation={strength.confirmed_observation}, probable={strength.probable}, "
            f"possible={strength.possible}, informational={strength.informational}. "
            f"Authenticated coverage: state={auth.state}, authenticated_url_count={auth.authenticated_url_count}, "
            f"session_cookies_present={auth.session_cookies_present}, auth_headers_present={auth.auth_headers_present}. "
            f"SPA/API coverage: spa_detected={spa_api.spa_detected}, js_assets={spa_api.js_assets_inspected}, "
            f"routes={spa_api.routes_extracted}, api_endpoints={spa_api.api_endpoints_extracted}, "
            f"parameters={spa_api.parameters_extracted}, browser_requests={spa_api.browser_requests_observed}, "
            f"dead_spa_fallback_routes_suppressed={spa_api.dead_spa_fallback_routes_suppressed}, "
            f"static_spa_only={spa_api.static_spa_only}, browser_available={spa_api.browser_available}, "
            f"replayable_json_bodies={spa_api.replayable_json_bodies}. "
            f"Coverage warnings that must be stated before any AI summary: {coverage_warning_text}. "
            f"Detector coverage metrics: {detector_coverage_text}. "
            f"Top confirmed exploit paths: {'; '.join(confirmed_exploit_paths) or 'none'}. "
            f"Needs-review findings: {'; '.join(needs_review) or 'none'}. "
            "Limitations: A06, A08, and A09 are not actively verified by this scanner; "
            "browser crawling may be disabled; authenticated coverage is unverified unless a protected target was proven. "
            f"Technologies detected: {technologies_detected}.{chains_info}"
        )
        try:
            result = await self.client.generate_json(prompt)
        except Exception:
            result = fallback
        result.setdefault("technologies_detected", technologies_detected)
        result["generated_at"] = datetime.now(timezone.utc).isoformat()
        return result

    def _detector_coverage_text(self, metrics: list[DetectorCoverageMetric]) -> str:
        if not metrics:
            return "None."
        lines = []
        for metric in metrics[:12]:
            skipped = ", ".join(f"{reason}={count}" for reason, count in sorted(metric.skipped_reasons.items()))
            lines.append(
                f"{metric.detector}: candidates={metric.candidates_built}, requests={metric.requests_sent}, "
                f"verified={metric.verified_findings}, unverified={metric.unverified_findings}, "
                f"filtered={metric.candidates_filtered}, dropped_verified_mode={metric.dropped_findings_verified_mode}"
                + (f", skipped={skipped}" if skipped else "")
            )
        return "; ".join(lines)
