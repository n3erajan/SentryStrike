from __future__ import annotations

from dataclasses import dataclass

from app.core.crawler.models import ApiEndpoint, ParameterCandidate, ParameterLocation, RequestObservation
from app.core.detectors.attack_surface import AttackSurface, AttackTarget


BODY_RELEVANT_DETECTORS = frozenset(
    {
        "access_control",
        "command_injection",
        "csrf",
        "file_inclusion",
        "file_upload",
        "injection_sql_command",
        "nosql_injection",
        "ssrf",
        "xss",
    }
)

MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
BODY_LOCATIONS = frozenset(
    {ParameterLocation.form, ParameterLocation.json_body, ParameterLocation.graphql_variable}
)


@dataclass(frozen=True)
class PlannedAttackTarget:
    target: AttackTarget
    score: int
    risk: str
    reasons: tuple[str, ...]


class AttackPlanner:
    """Rank detector targets using observed replayability and body quality."""

    def __init__(self, targets: list[AttackTarget]) -> None:
        self._targets = targets
        self._planned = [self._plan_target(target) for target in targets]
        self._planned.sort(key=lambda item: item.score, reverse=True)

    @classmethod
    def from_context(
        cls,
        *,
        urls: list[str],
        forms: list[object],
        parameters: list[ParameterCandidate] | None = None,
        api_endpoints: list[ApiEndpoint] | None = None,
        requests: list[RequestObservation] | None = None,
    ) -> "AttackPlanner":
        return cls(
            AttackSurface.build(
                urls,
                forms,
                parameters=parameters,
                api_endpoints=api_endpoints,
                requests=requests,
            )
        )

    @property
    def targets(self) -> list[AttackTarget]:
        return [planned.target for planned in self._planned]

    def targets_for(self, detector_name: str) -> list[AttackTarget]:
        return [planned.target for planned in self.planned_for(detector_name)]

    def planned_for(self, detector_name: str) -> list[PlannedAttackTarget]:
        detector_name = detector_name.lower()
        planned = [item for item in self._planned if self._relevant(item.target, detector_name)]
        return sorted(
            planned,
            key=lambda item: self._score_for_detector(item, detector_name),
            reverse=True,
        )

    def coverage_summary(
        self,
        detector_name: str,
        attempted_count: int = 0,
        denied_count: int = 0,
    ) -> dict[str, object]:
        """Summarise coverage from *real* attempted/denied counts, not finding count.

        ``attempted_count`` is the number of requests the detector actually issued
        (governor-admitted); ``denied_count`` is the number the governor refused at
        the budget ceiling. A body target counts as skipped only when it was not
        reached, and ``budget_exhausted`` is attributed strictly up to the real
        ``denied_count`` — never inferred from a shortfall in findings. A detector
        that ran fully and found nothing therefore reports ``budget_exhausted == 0``.
        """
        attempted = max(0, int(attempted_count))
        denied = max(0, int(denied_count))
        planned = self.planned_for(detector_name)
        replayable = [item for item in planned if item.target.replayable]
        synth = [item for item in planned if item.target.source_confidence == "static_synth"]
        body_targets = [item for item in planned if item.target.location in BODY_LOCATIONS]
        tested_body = min(attempted, len(body_targets))
        skipped = max(0, len(body_targets) - tested_body)
        risk_counts: dict[str, int] = {}
        skipped_items = sorted(body_targets, key=lambda entry: entry.score, reverse=True)[tested_body:]
        skip_buckets: dict[str, int] = {}
        budget_remaining = denied
        for item in skipped_items:
            risk_counts[item.risk] = risk_counts.get(item.risk, 0) + 1
            target = item.target
            if target.source_confidence == "static_synth" and not target.replayable:
                reason = "static_synth_not_validated"
            elif not target.replayable:
                reason = "non_replayable"
            elif budget_remaining > 0:
                # A genuinely testable target the governor refused at the ceiling.
                reason = "budget_exhausted"
                budget_remaining -= 1
            else:
                # Testable but never attempted for reasons other than the budget
                # ceiling (e.g. the detector matched no candidate of this kind).
                reason = "no_candidates_matched"
            skip_buckets[reason] = skip_buckets.get(reason, 0) + 1
        return {
            "targets_seen": len(planned),
            "targets_attempted": attempted,
            "requests_denied_by_governor": denied,
            "replayable_targets_seen": len(replayable),
            "replayable_targets_tested": min(attempted, len(replayable)),
            "validated_synth_targets_tested": min(attempted, len(synth)),
            "body_targets_skipped": skipped,
            "body_targets_skipped_by_reason": skip_buckets,
            "skip_reason_by_risk": risk_counts,
        }

    def _plan_target(self, target: AttackTarget) -> PlannedAttackTarget:
        score = 0
        reasons: list[str] = []
        if target.replayable:
            score += 40
            reasons.append("replayable")
        if target.method.upper() in MUTATING_METHODS:
            score += 20
            reasons.append("mutating")
        if target.location in BODY_LOCATIONS:
            score += 20
            reasons.append("body")
        if target.headers or target.cookies:
            score += 10
            reasons.append("authenticated_context")
        if target.body_schema:
            score += min(10, len(target.body_schema))
            reasons.append("body_schema")
        if target.security_relevance:
            score += 8
            reasons.append("security_relevant_parameter")
        if target.source_confidence == "static_synth":
            score -= 10
            reasons.append("static_synth")
        risk = "high" if score >= 75 else "medium" if score >= 45 else "low"
        return PlannedAttackTarget(target=target, score=score, risk=risk, reasons=tuple(reasons))

    def _score_for_detector(self, planned: PlannedAttackTarget, detector_name: str) -> int:
        score = planned.score
        target = planned.target
        if detector_name in BODY_RELEVANT_DETECTORS and target.location in BODY_LOCATIONS:
            score += 25
        if detector_name == "file_upload" and "multipart/form-data" in str(target.content_type or "").lower():
            score += 40
        if detector_name == "csrf" and target.method.upper() in MUTATING_METHODS and target.replayable:
            score += 35
        if detector_name == "access_control" and (
            target.method.upper() in MUTATING_METHODS or "id" in target.parameter.lower()
        ):
            score += 20
        return score

    @staticmethod
    def _relevant(target: AttackTarget, detector_name: str) -> bool:
        if detector_name == "file_upload":
            return "multipart/form-data" in str(target.content_type or "").lower()
        if detector_name == "csrf":
            return target.method.upper() in MUTATING_METHODS and target.replayable
        if detector_name in BODY_RELEVANT_DETECTORS:
            return target.location in BODY_LOCATIONS or bool(target.security_relevance)
        return True
