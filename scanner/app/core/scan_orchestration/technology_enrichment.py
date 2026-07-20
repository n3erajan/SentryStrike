import logging

from app.integrations import error_fingerprints
from shared.models.vulnerability import TechnologyComponent

logger = logging.getLogger("app.core.scanner")


class TechnologyEnrichmentMixin:
    async def _enrich_tech_from_errors(self, scan, findings: list) -> None:
        """Add technologies revealed by error responses to ``scan.technology_stack``.

        Harvests error/stack-trace text from the findings the detectors produced
        (source-agnostic: any finding that captured an error contributes), maps
        it to named technologies + versions via the generic error-signature table,
        merges into the existing stack (filling versions for entries that lacked
        one), CVE-enriches only the newly discovered components, and appends them.
        """
        # 1. Harvest candidate error text from finding evidence fields.
        texts: list[str] = []
        for f in findings or []:
            for attr in ("verification_response_snippet", "evidence"):
                val = getattr(f, attr, None)
                if isinstance(val, str) and val:
                    texts.append(val)
            det_ev = getattr(f, "detection_evidence", None)
            if isinstance(det_ev, dict):
                for v in det_ev.values():
                    if isinstance(v, str) and v:
                        texts.append(v)
        if not texts:
            return

        # 2. Fingerprint from error text (+ the same text through the markup engine,
        #    cheaply, in case a normal-markup pattern such as an error-page banner hits).
        discovered = list(error_fingerprints.match_error_evidence(texts))
        try:
            from app.integrations.wappalyzer_engine import Evidence as _TechEvidence, match as engine_match

            markup_hits = engine_match(_TechEvidence(html="\n".join(texts)))
            discovered.extend(markup_hits)
        except Exception as exc:
            logger.debug("markup re-match on error text failed: %s", exc)

        if not discovered:
            return

        # 3. Merge into the existing stack: skip known names, back-fill missing versions.
        existing = {c.name.lower(): c for c in (scan.technology_stack or [])}
        new_components: list[TechnologyComponent] = []
        seen_new: set[str] = set()
        for comp in discovered:
            key = comp.name.lower()
            if key in existing:
                if comp.version and not existing[key].version:
                    existing[key].version = comp.version
                continue
            if key in seen_new:
                continue
            seen_new.add(key)
            new_components.append(
                TechnologyComponent(name=comp.name, version=comp.version, category=comp.category)
            )

        if not new_components:
            return

        # 4. CVE-enrich only the newly discovered components, then append.
        try:
            enriched = await self.cve_service.enrich_components(new_components)
        except Exception as exc:
            logger.debug("CVE enrichment of error-derived components failed: %s", exc)
            enriched = new_components

        scan.technology_stack = list(scan.technology_stack or []) + enriched
        logger.info(
            "error-based tech enrichment: +%d component(s) [%s]",
            len(enriched),
            ", ".join(f"{c.name}{'/' + c.version if c.version else ''}" for c in enriched),
        )

    async def _enrich_tech_from_manifests(self, scan, crawl_result) -> None:
        """Back-fill component *versions* from manifests and version headers.

        The supply-chain gate needs a version before it can emit an A03 finding.
        Header/HTML/runtime fingerprinting names technologies but rarely versions
        them; this harvests the version-bearing surfaces most apps expose —
        ecosystem-standard package manifests/lockfiles and ``Server`` /
        ``X-Powered-By`` / ``X-AspNet-Version`` headers — via the generic
        :mod:`app.integrations.version_probe`.

        Merge semantics mirror :meth:`_enrich_tech_from_errors`: back-fill a
        missing version onto an existing component, add a genuinely-new versioned
        component, never overwrite an existing version. Unlike the error path,
        an existing component whose version *newly resolves* is re-sent to CVE
        enrichment, because the version determines which CVEs apply.
        """
        from app.integrations import version_probe
        from app.utils.scan_http import build_scan_headers, create_scan_client

        existing_names = [c.name for c in (scan.technology_stack or [])]

        # 1. Version-bearing response headers already captured during the crawl.
        header_map: dict[str, str] = {}
        for obs in getattr(crawl_result, "requests", []) or []:
            for hname, hval in (getattr(obs, "response_headers", {}) or {}).items():
                header_map.setdefault(str(hname).lower(), str(hval))
        discovered = list(version_probe.extract_header_versions(header_map))

        # 2. Ecosystem-standard manifests, bounded + only for detected ecosystems.
        try:
            auth_headers = getattr(crawl_result, "auth_headers", {}) or {}
            session_cookies = getattr(crawl_result, "session_cookies", {}) or {}
            async with create_scan_client(
                headers=build_scan_headers(auth_headers),
                cookies=session_cookies or None,
                follow_redirects=True,
            ) as client:
                discovered.extend(
                    await version_probe.probe_versions(scan.target_url, client, existing_names)
                )
        except Exception as exc:
            logger.debug("manifest version probe failed: %s", exc)

        if not discovered:
            return

        # 3. Merge: back-fill versions, collect new versioned components, and
        #    track existing components whose version newly resolved.
        existing = {c.name.lower(): c for c in (scan.technology_stack or [])}
        new_components: list[TechnologyComponent] = []
        resolved_existing: list[TechnologyComponent] = []
        seen_new: dict[str, TechnologyComponent] = {}
        for comp in discovered:
            if not comp.version:
                continue
            key = comp.name.lower()
            if key in existing:
                if not existing[key].version:
                    existing[key].version = comp.version
                    resolved_existing.append(existing[key])
                continue
            if key in seen_new:
                continue
            new = TechnologyComponent(name=comp.name, version=comp.version, category=comp.category)
            seen_new[key] = new
            new_components.append(new)

        to_enrich = resolved_existing + new_components
        if not to_enrich:
            return

        # 4. CVE-enrich everything whose version newly resolved (existing + new).
        try:
            await self.cve_service.enrich_components(to_enrich)
        except Exception as exc:
            logger.debug("CVE enrichment of manifest-derived components failed: %s", exc)

        if new_components:
            scan.technology_stack = list(scan.technology_stack or []) + new_components
        logger.info(
            "manifest/header version enrichment: %d version(s) resolved, +%d new component(s) [%s]",
            len(resolved_existing),
            len(new_components),
            ", ".join(f"{c.name}{'/' + c.version if c.version else ''}" for c in to_enrich),
        )
