from collections.abc import Awaitable, Callable

from app.analyzers.ai_client import AIClient
from app.analyzers.report_generator import AiReportGenerator
from app.core.crawler.spider import WebSpider
from app.core.detectors.supply_chain import SupplyChainDetector
from app.core.evidence_grader import EvidenceGrader
from app.core.scan_orchestration.ai_analysis import (
    AiAnalysisMixin,
    DESCRIPTION_FALLBACKS,
    REMEDIATION_FALLBACKS,
    _normalize_llm_string,
)
from app.core.scan_orchestration.coverage import CoverageMixin
from app.core.scan_orchestration.detector_execution import (
    ATTACK_SURFACE_BACKED_DETECTORS,
    SPECIALIZED_INPUT_DETECTORS,
    DetectorExecutionMixin,
)
from app.core.scan_orchestration.finding_processing import FindingProcessingMixin
from app.core.scan_orchestration.pipeline import PipelineMixin
from app.core.scan_orchestration.progress import (
    AI_PRIOR_PER_FINDING_S,
    DETECTOR_COST_WEIGHT,
    DETECTOR_PAYLOADS_PER_TARGET,
    PHASE_WEIGHTS,
    ProgressMixin,
    _elapsed_utc_seconds,
    _EtaState,
)
from app.core.scan_orchestration.runtime import RuntimeMixin
from app.core.scan_orchestration.technology_enrichment import TechnologyEnrichmentMixin
from app.integrations.cve_database import CveDatabaseService
from app.integrations.sslyze_wrapper import SslAnalyzer
from app.integrations.wappalyzer import TechnologyDetector
from shared.database.repositories.scan_repository import ScanRepository
from shared.schemas.scan_schema import ScanConfig


async def _never_cancelled(_: str) -> bool:
    """Default cancellation checker used when no queue cancellation support exists."""
    return False


class ScanOrchestrator(
    """Top-level scan pipeline orchestrator.

    Composes all pipeline stages (crawl, detect, verify, analyze, score, report)
    via multiple mixins, each owning one phase of the scan lifecycle. A single
    ``run_scan`` call sequences these stages with progress reporting, ETA
    estimation, and cancellation support.
    """
    PipelineMixin,
    RuntimeMixin,
    DetectorExecutionMixin,
    AiAnalysisMixin,
    FindingProcessingMixin,
    CoverageMixin,
    TechnologyEnrichmentMixin,
    ProgressMixin,
):
    def __init__(
        self,
        repository: ScanRepository,
        *,
        cancellation_checker: Callable[[str], Awaitable[bool]] | None = None,
    ) -> None:
        self.repository = repository
        self._cancellation_checker = cancellation_checker or _never_cancelled
        self.spider = WebSpider()
        self.technology_detector = TechnologyDetector()
        self.cve_service = CveDatabaseService()
        self.ssl_analyzer = SslAnalyzer()

        self.ai_client = AIClient()
        self.ai_report = AiReportGenerator()
        self.evidence_grader = EvidenceGrader()

        # Default instances stay on self so tests/embedders can inject fakes. A
        # PRODUCTION run_scan replaces these with fresh per-scan instances so two
        # concurrent scans never share cookies/auth/HTTP clients/verifier state
        # (Issue 1). See _build_detectors and the isolation guard in run_scan.
        self.detectors = self._build_detectors()
        self.supply_chain_detector = SupplyChainDetector()
        self._eta_state = _EtaState()

        self._remediation_fallbacks = dict(REMEDIATION_FALLBACKS)

        # Plain-language, jargon-free explanations of what each vulnerability
        # class IS — for report readers who don't know what "IDOR" or "BOLA"
        # means. These are the FALLBACK: the AI writes a finding-specific
        # description when analysis succeeds; when it fails or omits one, the
        # matching entry here is used (see ``_description_for``). Keyed by the
        # same vuln_type strings the detectors emit; matched by substring both
        # ways, longest key first, so specific types win over generic ones.
        self._description_fallbacks = dict(DESCRIPTION_FALLBACKS)


    async def run_scan(
        self,
        scan_id: str,
        *,
        auth_accounts: list | None = None,
        scan_config: ScanConfig | None = None,
    ) -> None:
        await self._run_scan_pipeline(
            scan_id,
            auth_accounts=auth_accounts,
            scan_config=scan_config,
        )
