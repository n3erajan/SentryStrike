import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from time import perf_counter

from app.core.detectors.attack_planner import AttackPlanner
from app.utils.scan_http import create_scan_client
from shared.models.scan import Scan, ScanPhase, ScanStatus

logger = logging.getLogger("app.core.scanner")


# Pipeline-stage weights as a percentage of total scan time, calibrated from
# real scan durations. The sum approximates 100 %; each weight drives the
# per-stage progress bar the frontend displays.
PHASE_WEIGHTS = {
    ScanPhase.initializing: 2,
    ScanPhase.crawling: 30,
    ScanPhase.technology_detection: 6,
    ScanPhase.tls_analysis: 4,
    ScanPhase.vulnerability_detection: 52,
    ScanPhase.deduplication: 4,
    ScanPhase.risk_scoring: 2,
}

DETECTOR_PAYLOADS_PER_TARGET: dict[str, int] = {
    "injection_sql_command": 20,
    "xss": 22,
    "command_injection": 12,
    "nosql_injection": 15,
    "file_inclusion": 16,
    "ssrf": 10,
    "open_redirect": 8,
    "csrf": 4,
    "file_upload": 10,
    "access_control": 6,
    "authentication_failures": 8,
    "exception_handling": 5,
    "sensitive_paths": 2,
    "default": 10,
}

DETECTOR_COST_WEIGHT: dict[str, float] = {
    "xss": 4.0,
    "injection_sql_command": 3.5,
    "command_injection": 3.0,
    "file_upload": 3.0,
    "nosql_injection": 2.5,
    "file_inclusion": 2.5,
    "ssrf": 2.5,
    "open_redirect": 2.0,
    "authentication_failures": 2.0,
    "access_control": 2.0,
    "csrf": 1.5,
    "exception_handling": 1.2,
    "sensitive_paths": 1.0,
    "default": 1.5,
}

SHORT_PHASE_PRIOR_S: dict[ScanPhase, float] = {
    ScanPhase.technology_detection: 5.0,
    ScanPhase.tls_analysis: 3.0,
    ScanPhase.deduplication: 2.0,
    ScanPhase.risk_scoring: 2.0,
}

CRAWL_PRIOR_S = 150.0
DETECTOR_PENDING_PRIOR_S = 480.0
DEFAULT_LATENCY_MS = 200.0
DETECTOR_LATENCY_MULTIPLIER = 4.0
DETECTOR_LATENCY_FLOOR_MS = 350.0


def _elapsed_utc_seconds(started_at: datetime) -> float:
    """Return seconds since a possibly naive MongoDB UTC timestamp."""
    now = datetime.now(timezone.utc)
    if started_at.tzinfo is None:
        started_at = started_at.replace(tzinfo=timezone.utc)
    else:
        started_at = started_at.astimezone(timezone.utc)
    return (now - started_at).total_seconds()


@dataclass
class _EtaState:
    """Per-scan work-model inputs for server-side ETA (not persisted)."""

    measured_latency_ms: float = DEFAULT_LATENCY_MS
    detector_total_s: float | None = None
    detector_fraction: float = 0.0
    detector_work_units: dict[str, float] = field(default_factory=dict)
    detector_total_work: float = 0.0
    detector_completed_work: float = 0.0
    detector_phase_started: float | None = None
    ai_total_s: float | None = None
    ai_remaining_s: float | None = None
    ai_fraction: float = 0.0
    findings_count: int = 0
    phase_order: tuple[ScanPhase, ...] = field(
        default_factory=lambda: (
            ScanPhase.initializing,
            ScanPhase.crawling,
            ScanPhase.technology_detection,
            ScanPhase.tls_analysis,
            ScanPhase.vulnerability_detection,
            ScanPhase.deduplication,
            ScanPhase.risk_scoring,
        )
    )


class ProgressMixin:
    async def _set_phase_progress(
        self,
        scan: Scan,
        phase: ScanPhase,
        fraction: float,
        message: str,
        *,
        status: ScanStatus = ScanStatus.running,
    ) -> None:
        order = list(self._eta_state.phase_order)
        try:
            phase_idx = order.index(phase)
            base = sum(PHASE_WEIGHTS[p] for p in order[:phase_idx])
        except (ValueError, KeyError):
            base = scan.progress

        phase_weight = PHASE_WEIGHTS.get(phase, 0)
        pct = base + phase_weight * max(0.0, min(1.0, fraction))
        progress = max(scan.progress, round(pct))
        scan.eta_seconds = self._compute_eta_seconds(scan, phase, fraction, progress)
        await self._set_progress(scan, progress, phase, message, status=status)

    def _compute_eta_seconds(
        self,
        scan: Scan,
        phase: ScanPhase,
        fraction: float,
        progress: int,
    ) -> int | None:
        eta = self._eta_state
        clamped = max(0.0, min(1.0, fraction))
        order = list(eta.phase_order)

        try:
            phase_idx = order.index(phase)
        except ValueError:
            phase_idx = -1

        remaining = 0.0
        if phase == ScanPhase.vulnerability_detection and eta.detector_total_s is not None:
            remaining += self._detector_remaining_seconds()
        elif phase == ScanPhase.vulnerability_detection:
            remaining += DETECTOR_PENDING_PRIOR_S * (1.0 - clamped)
        elif phase == ScanPhase.ai_analysis:
            if eta.ai_remaining_s is not None:
                remaining += eta.ai_remaining_s
            else:
                ai_total = eta.ai_total_s
                if ai_total is None and eta.findings_count:
                    ai_total = eta.findings_count * AI_PRIOR_PER_FINDING_S
                if ai_total is not None:
                    remaining += ai_total * (1.0 - clamped)
                else:
                    remaining += SHORT_PHASE_PRIOR_S.get(phase, 0.0) * (1.0 - clamped)
        elif phase == ScanPhase.crawling:
            if scan.started_at and progress > 5:
                elapsed = _elapsed_utc_seconds(scan.started_at)
                return max(0, round(elapsed * (100 - progress) / progress))
            remaining += CRAWL_PRIOR_S * (1.0 - clamped)
        elif phase in SHORT_PHASE_PRIOR_S:
            remaining += SHORT_PHASE_PRIOR_S[phase] * (1.0 - clamped)

        if phase_idx >= 0:
            for future in order[phase_idx + 1 :]:
                if future == ScanPhase.vulnerability_detection:
                    remaining += eta.detector_total_s if eta.detector_total_s is not None else DETECTOR_PENDING_PRIOR_S
                elif future == ScanPhase.crawling:
                    remaining += CRAWL_PRIOR_S
                elif future == ScanPhase.ai_analysis:
                    if eta.ai_total_s is not None:
                        remaining += eta.ai_total_s
                    elif eta.findings_count:
                        remaining += eta.findings_count * AI_PRIOR_PER_FINDING_S
                    else:
                        remaining += AI_PENDING_PRIOR_S
                else:
                    remaining += SHORT_PHASE_PRIOR_S.get(future, 0.0)

        if remaining <= 0 and scan.started_at and progress > 5:
            elapsed = _elapsed_utc_seconds(scan.started_at)
            return max(0, round(elapsed * (100 - progress) / progress))
        return max(0, round(remaining)) if remaining > 0 else None

    def _detector_remaining_seconds(self) -> float:
        eta = self._eta_state
        prior_total = float(eta.detector_total_s or 0.0)
        total_work = eta.detector_total_work
        completed = min(eta.detector_completed_work, total_work)
        remaining_work = max(0.0, total_work - completed)

        if total_work <= 0:
            return max(0.0, prior_total * (1.0 - eta.detector_fraction))

        prior_remaining = prior_total * (remaining_work / total_work)
        if remaining_work <= 0:
            return 0.0

        if completed > 0 and eta.detector_phase_started is not None:
            elapsed = max(0.001, perf_counter() - eta.detector_phase_started)
            pace_remaining = remaining_work * (elapsed / completed)
            return max(prior_remaining, pace_remaining)
        return prior_remaining

    def _estimate_detector_work(
        self,
        attack_planner: AttackPlanner,
        active_detectors: list,
        *,
        latency_ms: float,
        parallelism: int,
        per_detector_cap: int,
    ) -> tuple[dict[str, float], float]:
        work_units: dict[str, float] = {}
        for detector in active_detectors:
            name = self._detector_name(detector)
            targets = len(attack_planner.targets_for(name))
            payloads = DETECTOR_PAYLOADS_PER_TARGET.get(name, DETECTOR_PAYLOADS_PER_TARGET["default"])
            weight = DETECTOR_COST_WEIGHT.get(name, DETECTOR_COST_WEIGHT["default"])
            raw_requests = min(max(0, targets) * max(1, payloads), max(1, per_detector_cap))
            work_units[name] = max(float(raw_requests), 1.0) * weight

        effective_latency_ms = max(
            DETECTOR_LATENCY_FLOOR_MS,
            max(20.0, latency_ms) * DETECTOR_LATENCY_MULTIPLIER,
        )
        effective_parallelism = max(1, parallelism)
        total_units = sum(work_units.values())
        prior_s = (total_units * (effective_latency_ms / 1000.0)) / effective_parallelism
        return work_units, prior_s

    def _estimate_detector_seconds(
        self,
        attack_planner: AttackPlanner,
        active_detectors: list,
        *,
        latency_ms: float,
        concurrency: int,
        per_detector_cap: int,
    ) -> float:
        _, prior_s = self._estimate_detector_work(
            attack_planner,
            active_detectors,
            latency_ms=latency_ms,
            parallelism=concurrency,
            per_detector_cap=per_detector_cap,
        )
        return prior_s

    async def _measure_target_latency_ms(self, url: str) -> float:
        try:
            async with create_scan_client() as client:
                started = perf_counter()
                await client.get(url)
                return max(20.0, (perf_counter() - started) * 1000.0)
        except Exception as exc:
            logger.debug(
                "latency probe failed for %s: %s - using prior %.0fms",
                url,
                exc,
                DEFAULT_LATENCY_MS,
            )
            return DEFAULT_LATENCY_MS

    async def _set_progress(
        self,
        scan: Scan,
        progress: int,
        phase: ScanPhase,
        message: str,
        *,
        status: ScanStatus = ScanStatus.running,
    ) -> None:
        scan.status = status
        scan.progress = progress
        scan.current_phase = phase
        scan.phase_message = message
        scan.updated_at = datetime.now(timezone.utc)
        if status == ScanStatus.running and scan.started_at is None:
            scan.started_at = datetime.now(timezone.utc)
        if status in {ScanStatus.completed, ScanStatus.failed, ScanStatus.cancelled}:
            if scan.completed_at is None:
                scan.completed_at = datetime.now(timezone.utc)
            scan.eta_seconds = 0
        await scan.save()

    async def _check_cancelled(self, scan_id: str) -> None:
        if await self._cancellation_checker(scan_id):
            raise asyncio.CancelledError
