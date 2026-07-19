import asyncio
from urllib.parse import urlparse
import logging

from app.core.crawler.spa import SpaFallbackDetector
from app.core.detectors.base_detector import Finding
from app.core.verification.verification_framework import HttpVerifier
from shared.models.vulnerability import OwaspCategory, SeverityLevel

from app.core.detectors.access_control.common import (
    _looks_like_login_page,
    _strip_query,
    _body_similarity,
)

logger = logging.getLogger("app.core.detectors.access_control")


class ForcedBrowsingMixin:
    async def _check_forced_browsing(
        self,
        urls: list[str],
        unauthed_verifier: HttpVerifier,
        authed_verifier: HttpVerifier,
        spa_detector: SpaFallbackDetector | None = None,
    ) -> list[Finding]:
        """
        Detect sensitive paths that are accessible without authentication.
        When an SPA detector is provided, responses that match the SPA root
        shell are treated as fallback pages and are not reported.
        """
        findings: list[Finding] = []
        semaphore = asyncio.Semaphore(self._CONCURRENCY)

        paths_to_test: set[str] = set()
        for url in urls:
            parsed = urlparse(url)
            path_lower = parsed.path.lower()
            segments = {seg for seg in path_lower.split("/") if seg}
            # A dotfile / VCS-metadata segment (``.git``, ``.env``, ``.htaccess``,
            # ``.svn``, ``.hg``, ``.ssh``, ``.DS_Store`` …) is never gated
            # functionality — it is accidental file exposure (A02 Security
            # Misconfiguration), owned by the sensitive_paths detector, which
            # confirms it by content. Skip such paths here so forced browsing
            # (A01) does not re-report the same exposure under a second OWASP
            # category. This also avoids a token collision: ``.git/config``
            # would otherwise match the legitimate ``config`` functionality token.
            if any(seg.startswith(".") for seg in segments):
                continue
            assembled = "/".join(s for s in parsed.path.split("/") if s)
            if segments.intersection(self.sensitive_path_tokens) or any(
                tok in assembled.lower() for tok in self.sensitive_path_tokens
            ):
                paths_to_test.add(_strip_query(url))

        async def _test(test_url: str) -> list[Finding]:
            local_findings: list[Finding] = []
            async with semaphore:
                try:
                    resp = await unauthed_verifier.send_request(
                        test_url, "GET", test_phase="forced_browsing"
                    )

                    if not (200 <= resp.status_code < 300):
                        return []

                    if _looks_like_login_page(resp.body):
                        return []

                    if spa_detector is not None:
                        fallback = spa_detector.detect(
                            test_url,
                            resp.status_code,
                            resp.headers.get("content-type", ""),
                            resp.body,
                            allow_file_like_path=True,
                        )
                        if fallback.is_fallback:
                            logger.debug(
                                "ignoring SPA fallback response for forced browsing "
                                "check on %s: %s similarity=%.3f",
                                test_url,
                                fallback.reason,
                                fallback.similarity,
                            )
                            return []

                    authed_resp = await authed_verifier.send_request(
                        test_url, "GET", test_phase="forced_browsing_authed_baseline"
                    )
                    if authed_resp.status_code not in (200, 201, 206):
                        return []

                    if _body_similarity(resp.body, authed_resp.body) > 0.95:
                        severity = SeverityLevel.medium
                    else:
                        severity = SeverityLevel.high

                    local_findings.append(
                        Finding(
                            category=OwaspCategory.a01,
                            vuln_type="Forced Browsing / Sensitive Directory Exposure",
                            severity=severity,
                            url=test_url,
                            evidence=(
                                f"Sensitive path accessible without authentication "
                                f"(HTTP {resp.status_code}). "
                                f"Authenticated baseline: HTTP {authed_resp.status_code}."
                            ),
                            verified=True,
                            verification_request_snippet=resp.request_snippet,
                            verification_response_snippet=resp.response_snippet,
                            reproducible=True,
                        )
                    )
                except Exception:
                    logger.exception("Forced browsing check failed for %s", test_url)
            return local_findings

        results = await asyncio.gather(*[_test(u) for u in paths_to_test])
        for r in results:
            findings.extend(r)
        return findings
