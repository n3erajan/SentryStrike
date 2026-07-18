import logging
from dataclasses import dataclass
from urllib.parse import urljoin

from app.core.crawler.account_session import provision_secondary_session, resolve_account_session
from app.core.crawler.spider import WebSpider
from app.core.detectors.access_control import AccessControlDetector
from app.core.detectors.auth_detector import AuthenticationFailuresDetector
from app.core.detectors.command_injection import CommandInjectionDetector
from app.core.detectors.crypto_failures import CryptoFailuresDetector
from app.core.detectors.csrf_detector import CSRFDetector
from app.core.detectors.exception_handler import ExceptionHandlingDetector
from app.core.detectors.file_inclusion import FileInclusionDetector
from app.core.detectors.file_upload import FileUploadDetector
from app.core.detectors.nosql_injection import NoSqlInjectionDetector
from app.core.detectors.open_redirect import OpenRedirectDetector
from app.core.detectors.security_headers import SecurityHeadersDetector
from app.core.detectors.sensitive_paths import SensitivePathsDetector
from app.core.detectors.sql_injection import SQLInjectionDetector
from app.core.detectors.ssrf_detector import SSRFDetector
from app.core.detectors.supply_chain import SupplyChainDetector
from app.core.detectors.xss_detector import XSSDetector
from shared.schemas.scan_schema import ScanConfig

logger = logging.getLogger("app.core.scanner")


@dataclass(frozen=True)
class ScanRuntime:
    spider: object
    detectors: list
    supply_chain_detector: object


class RuntimeMixin:
    def _build_scan_runtime(self) -> ScanRuntime:
        """Create isolated mutable scanner components while preserving injected fakes."""
        scan_spider = WebSpider() if type(self.spider) is WebSpider else self.spider
        default_detector_types = [type(detector) for detector in self._build_detectors()]
        configured_detector_types = [type(detector) for detector in self.detectors]
        scan_detectors = (
            self._build_detectors()
            if configured_detector_types == default_detector_types
            else self.detectors
        )
        scan_supply_chain = (
            SupplyChainDetector()
            if type(self.supply_chain_detector) is SupplyChainDetector
            else self.supply_chain_detector
        )
        return ScanRuntime(
            spider=scan_spider,
            detectors=scan_detectors,
            supply_chain_detector=scan_supply_chain,
        )

    @staticmethod
    def _build_detectors() -> list:
        """Build a fresh detector graph for one scan.

        Several detectors own mutable HTTP clients, cookies, request context, and
        verifiers. Reusing one graph across concurrent scans can cross-contaminate
        auth state or let one scan close another scan's client (Issue 1).
        """
        return [
            AccessControlDetector(),
            SecurityHeadersDetector(),
            CryptoFailuresDetector(),
            SQLInjectionDetector(),
            XSSDetector(),
            AuthenticationFailuresDetector(),
            ExceptionHandlingDetector(),
            CommandInjectionDetector(),
            NoSqlInjectionDetector(),
            FileInclusionDetector(),
            CSRFDetector(),
            SSRFDetector(),
            OpenRedirectDetector(),
            FileUploadDetector(),
            SensitivePathsDetector(),
        ]

    @staticmethod
    def _scope_forms_to_origin(target_url: str, forms: list, is_same_origin) -> list:
        """Keep only forms whose RESOLVED submission target is same-origin.

        A form's ``page_url`` locates the page it was found on; its ``action`` is
        where it submits. Scope is decided by the action ONLY — page_url just
        resolves a relative/empty action. Accepting a form because its page is
        same-origin would let a same-origin page carrying an off-origin action
        turn into an AttackTarget aimed at a third party (Issue 2). The resolved
        absolute action is written back so downstream targeting uses it verbatim.
        """
        scoped: list = []
        for form in forms:
            page_url = str(getattr(form, "page_url", "") or target_url)
            action = str(getattr(form, "action", "") or page_url)
            resolved_action = urljoin(page_url, action)
            if is_same_origin(target_url, resolved_action):
                form.action = resolved_action
                scoped.append(form)
        return scoped

    async def _apply_submitted_account_sessions(self, scan, accounts_by_role: dict, crawl_context: dict, scan_config: ScanConfig | None = None, preferred_replay=None, primary_credentials=None) -> None:
        """Resolve second/admin test accounts to live sessions and inject them.

        The access-control detector reads ``second_user_cookies``/``_headers`` and
        ``privileged_cookies``/``_headers`` from these kwargs (preferring them over
        the env-based SCAN_AUTH_* settings), so IDOR / privilege-escalation checks
        run against sessions minted from the user-submitted credentials. When no
        second identity is submitted, a throwaway one may be auto-provisioned
        (gated by ``ALLOW_SECONDARY_PROVISIONING``).
        """
        role_to_kwargs = {
            "second": ("second_user_cookies", "second_user_headers", "second_user_storage_state"),
            "admin": ("privileged_cookies", "privileged_headers", "privileged_storage_state"),
        }
        for role, (cookie_key, header_key, storage_key) in role_to_kwargs.items():
            account = accounts_by_role.get(role)
            if account is None:
                continue
            session = await resolve_account_session(
                scan.target_url,
                account,
                preferred_replay=preferred_replay,
                primary_credentials=primary_credentials,
            )
            if not session.usable:
                logger.warning("no usable session resolved for %s account on %s", role, scan.target_url)
                continue
            crawl_context[cookie_key] = session.cookies
            crawl_context[header_key] = session.headers
            # Forward the full authenticated browser blob when captured so a
            # browser-based access-control check reuses it instead of re-logging-in.
            if session.storage_state:
                crawl_context[storage_key] = session.storage_state
            logger.info(
                "injected %s account session for access-control testing (cookies=%d, headers=%d)",
                role,
                len(session.cookies),
                len(session.headers),
            )

        # When no second identity was submitted, optionally auto-provision a
        # throwaway one (gated by ALLOW_SECONDARY_PROVISIONING) so cross-identity
        # IDOR/BOLA differentials can run without operator-supplied accounts.
        already_have_second = bool(
            crawl_context.get("second_user_cookies") or crawl_context.get("second_user_headers")
        )
        allow = scan_config.get_val("allow_secondary_provisioning", None) if scan_config else None
        if not already_have_second:
            provisioned = await provision_secondary_session(scan.target_url, allow_override=allow)
            if provisioned.usable:
                crawl_context["second_user_cookies"] = provisioned.cookies
                crawl_context["second_user_headers"] = provisioned.headers
                if provisioned.storage_state:
                    crawl_context["second_user_storage_state"] = provisioned.storage_state
                logger.info(
                    "injected auto-provisioned secondary identity for access-control testing "
                    "(cookies=%d, headers=%d)",
                    len(provisioned.cookies),
                    len(provisioned.headers),
                )
