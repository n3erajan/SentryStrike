from collections.abc import Awaitable, Callable

from app.core.crawler.spider import WebSpider
from app.core.detectors.supply_chain import SupplyChainDetector
from app.core.evidence_grader import EvidenceGrader
from app.core.scan_orchestration.coverage import CoverageMixin
from app.core.scan_orchestration.detector_execution import (
    ATTACK_SURFACE_BACKED_DETECTORS,
    SPECIALIZED_INPUT_DETECTORS,
    DetectorExecutionMixin,
)
from app.core.scan_orchestration.finding_processing import FindingProcessingMixin
from app.core.scan_orchestration.pipeline import PipelineMixin
from app.core.scan_orchestration.progress import (
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
from shared.analysis_queue import AnalysisQueue
from shared.database.repositories.analysis_job_repository import AnalysisJobRepository
from shared.database.repositories.scan_repository import ScanRepository
from shared.schemas.scan_schema import ScanConfig


async def _never_cancelled(_: str) -> bool:
    """Default cancellation checker used when no queue cancellation support exists."""
    return False


class ScanOrchestrator(
    PipelineMixin,
    RuntimeMixin,
    DetectorExecutionMixin,
    FindingProcessingMixin,
    CoverageMixin,
    TechnologyEnrichmentMixin,
    ProgressMixin,
):
    """Top-level scan pipeline orchestrator.

    Composes all pipeline stages (crawl, detect, verify, analyze, score, report)
    via multiple mixins, each owning one phase of the scan lifecycle. A single
    ``run_scan`` call sequences these stages with progress reporting, ETA
    estimation, and cancellation support.
    """

    def __init__(
        self,
        repository: ScanRepository,
        *,
        cancellation_checker: Callable[[str], Awaitable[bool]] | None = None,
        analysis_repository: AnalysisJobRepository | None = None,
        analysis_queue: AnalysisQueue | None = None,
    ) -> None:
        self.repository = repository
        self.analysis_repository = analysis_repository
        self.analysis_queue = analysis_queue
        self._cancellation_checker = cancellation_checker or _never_cancelled
        self.spider = WebSpider()
        self.technology_detector = TechnologyDetector()
        self.cve_service = CveDatabaseService()
        self.ssl_analyzer = SslAnalyzer()

        self.evidence_grader = EvidenceGrader()

        # Default instances stay on self so tests/embedders can inject fakes. A
        # PRODUCTION run_scan replaces these with fresh per-scan instances so two
        # concurrent scans never share cookies/auth/HTTP clients/verifier state
        # (Issue 1). See _build_detectors and the isolation guard in run_scan.
        self.detectors = self._build_detectors()
        self.supply_chain_detector = SupplyChainDetector()
        self._eta_state = _EtaState()

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
