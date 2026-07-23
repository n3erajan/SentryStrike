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

SINGLE_PAGE_PHASE_WEIGHTS = {
    ScanPhase.initializing: 5,
    ScanPhase.crawling: 5,
    ScanPhase.technology_detection: 10,
    ScanPhase.tls_analysis: 5,
    ScanPhase.vulnerability_detection: 60,
    ScanPhase.deduplication: 10,
    ScanPhase.risk_scoring: 5,
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
    crawl_http_split: float = 1.0
    crawl_browser_split: float = 0.0
    crawl_total_prior_s: float = CRAWL_PRIOR_S
    eta_smooth_s: float | None = None
    phase_weights: dict | None = None
    governor_denial_rate: float = 0.0
    detector_elapsed_s: dict[str, float] = field(default_factory=dict)
    detector_start_times: dict[str, float] = field(default_factory=dict)
    detector_expected_requests: dict[str, int] = field(default_factory=dict)
    detector_finished_work: float = 0.0
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
        from shared.models.scan import CrawlMode
        order = list(self._eta_state.phase_order)
        if self._eta_state.phase_weights is not None:
            weights = self._eta_state.phase_weights
        else:
            weights = SINGLE_PAGE_PHASE_WEIGHTS if scan.crawl_mode == CrawlMode.single else PHASE_WEIGHTS
        try:
            phase_idx = order.index(phase)
            base = sum(weights[p] for p in order[:phase_idx])
        except (ValueError, KeyError):
            base = scan.progress

        phase_weight = weights.get(phase, 0)
        pct = base + phase_weight * max(0.0, min(1.0, fraction))
        progress = min(100, max(scan.progress, round(pct)))
        
        computed_eta = self._compute_eta_seconds(scan, phase, fraction, progress)
        if computed_eta is not None:
            if self._eta_state.eta_smooth_s is None:
                smoothed = float(computed_eta)
            else:
                alpha = 0.35
                smoothed = alpha * float(computed_eta) + (1.0 - alpha) * self._eta_state.eta_smooth_s
                if smoothed > self._eta_state.eta_smooth_s + 60.0:
                    smoothed = self._eta_state.eta_smooth_s + 60.0
            
            self._eta_state.eta_smooth_s = max(0.0, smoothed)
            scan.eta_seconds = round(self._eta_state.eta_smooth_s)
        else:
            scan.eta_seconds = None

        await self._set_progress(scan, progress, phase, message, status=status)

    def _compute_eta_seconds(
        self,
        scan: Scan,
        phase: ScanPhase,
        fraction: float,
        progress: int,
    ) -> int | None:
        from shared.models.scan import CrawlMode
        eta = self._eta_state
        clamped = max(0.0, min(1.0, fraction))
        order = list(eta.phase_order)

        try:
            phase_idx = order.index(phase)
        except ValueError:
            phase_idx = -1

        detector_prior_s = 60.0 if scan.crawl_mode == CrawlMode.single else DETECTOR_PENDING_PRIOR_S
        crawl_prior_s = 10.0 if scan.crawl_mode == CrawlMode.single else eta.crawl_total_prior_s

        remaining = 0.0
        if phase == ScanPhase.vulnerability_detection and eta.detector_total_s is not None:
            remaining += self._detector_remaining_seconds()
        elif phase == ScanPhase.vulnerability_detection:
            remaining += detector_prior_s * (1.0 - clamped)
        elif phase == ScanPhase.crawling:
            if scan.started_at and progress > 5:
                elapsed = _elapsed_utc_seconds(scan.started_at)
                return max(0, round(elapsed * (100 - progress) / progress))
            remaining += crawl_prior_s * (1.0 - clamped)
        elif phase in SHORT_PHASE_PRIOR_S:
            remaining += SHORT_PHASE_PRIOR_S[phase] * (1.0 - clamped)

        if phase_idx >= 0:
            for future in order[phase_idx + 1 :]:
                if future == ScanPhase.vulnerability_detection:
                    remaining += eta.detector_total_s if eta.detector_total_s is not None else detector_prior_s
                elif future == ScanPhase.crawling:
                    remaining += crawl_prior_s
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
        denial_inflation = 1.0 + (eta.governor_denial_rate * 0.5)

        if total_work <= 0:
            return max(0.0, prior_total * (1.0 - eta.detector_fraction) * denial_inflation)

        if remaining_work <= 0:
            return 0.0

        observed_mean_pace = 0.0
        if eta.detector_elapsed_s:
            finished_time = sum(eta.detector_elapsed_s.values())
            finished_work = sum(eta.detector_work_units.get(name, 0.0) for name in eta.detector_elapsed_s)
            if finished_work > 0:
                observed_mean_pace = finished_time / finished_work
        
        prior_pace = prior_total / total_work if total_work > 0 else 0.0
        pace_factor = (observed_mean_pace / prior_pace) if (observed_mean_pace > 0 and prior_pace > 0) else 1.0
        # Clamp pace_factor between 0.2 and 5.0 so ETA doesn't swing wildly
        pace_factor = max(0.2, min(5.0, pace_factor))
        
        base_remaining = 0.0
        for name, work in eta.detector_work_units.items():
            if name not in eta.detector_elapsed_s:
                prior_s_for_name = prior_total * (work / total_work) if total_work > 0 else 0.0
                base_remaining += prior_s_for_name * pace_factor

        if completed > 0 and eta.detector_phase_started is not None:
            elapsed = max(0.001, perf_counter() - eta.detector_phase_started)
            live_pace = elapsed / completed
            # Clamp live_pace to a maximum of 5x the prior_pace to prevent huge spikes
            # from sparse ticker updates early in the run
            if prior_pace > 0:
                live_pace = min(live_pace, prior_pace * 5.0)
            pace_remaining = remaining_work * live_pace
            # Blend the live pace and base remaining to avoid the max() spike
            if eta.detector_elapsed_s:
                # If we have finished detectors, trust the pace_factor more
                base_remaining = (base_remaining * 0.7) + (pace_remaining * 0.3)
            else:
                # If none finished, rely on the live pace but capped
                base_remaining = pace_remaining
            
        return max(0.0, base_remaining * denial_inflation)

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
            if hasattr(self, "_eta_state"):
                self._eta_state.detector_expected_requests[name] = max(int(raw_requests), 1)
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
