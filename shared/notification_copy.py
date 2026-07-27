"""Consistent, user-facing copy for durable notifications."""

from dataclasses import dataclass


@dataclass(frozen=True)
class NotificationCopy:
    title: str
    message: str


def _value(value: object) -> str:
    return str(getattr(value, "value", value)).strip()


def _actor(full_name: str | None) -> str:
    name = " ".join((full_name or "").split())
    return name or "A team member"


def _label(value: object) -> str:
    raw = _value(value)
    overrides = {
        "in_progress": "In progress",
        "fixed_pending_verification": "Fix ready for verification",
        "verified_fixed": "Fix verified",
        "wont_fix": "Risk accepted",
        "not_reproduced": "Not reproduced",
    }
    return overrides.get(raw, raw.replace("_", " ").capitalize())


def scan_terminal_copy(status: object, target: str) -> NotificationCopy:
    state = _value(status)
    copy = {
        "completed": NotificationCopy(
            "Scan completed",
            f"The security scan for {target} completed successfully. "
            "Your results are ready to review.",
        ),
        "failed": NotificationCopy(
            "Scan unsuccessful",
            f"The security scan for {target} could not be completed. "
            "Review the scan details before trying again.",
        ),
        "cancelled": NotificationCopy(
            "Scan cancelled",
            f"The security scan for {target} was cancelled.",
        ),
    }
    return copy[state]


def scan_start_failed_copy(target: str) -> NotificationCopy:
    return NotificationCopy(
        "Scan could not start",
        f"The security scan for {target} could not be started. Please try again.",
    )


def analysis_terminal_copy(completed: bool) -> NotificationCopy:
    if completed:
        return NotificationCopy(
            "Analysis ready",
            "The analysis and PDF report are ready to review.",
        )
    return NotificationCopy(
        "Analysis needs attention",
        "The automated analysis could not be completed. Your scan findings are "
        "still available, and a workspace owner, admin, or analyst can try again.",
    )


def finding_review_copy(
    *, actor_name: str | None, finding_type: str, false_positive: bool
) -> NotificationCopy:
    actor = _actor(actor_name)
    if false_positive:
        return NotificationCopy(
            "Finding marked as false positive",
            f"{actor} marked {finding_type} as a false positive.",
        )
    return NotificationCopy(
        "Finding restored",
        f"{actor} restored {finding_type} as an active finding.",
    )


def finding_assigned_copy(finding_type: str) -> NotificationCopy:
    return NotificationCopy(
        "Finding assigned to you",
        f"{finding_type} has been assigned to you for review.",
    )


def finding_comment_copy(*, actor_name: str | None, finding_type: str) -> NotificationCopy:
    return NotificationCopy(
        "New comment on a finding",
        f"{_actor(actor_name)} commented on {finding_type}.",
    )


def remediation_copy(
    *, actor_name: str | None, finding_type: str, status: object
) -> NotificationCopy:
    return NotificationCopy(
        "Remediation updated",
        f"{_actor(actor_name)} changed {finding_type} to “{_label(status)}”.",
    )


def role_change_copy(
    *, actor_name: str | None, previous_role: object, new_role: object
) -> NotificationCopy:
    return NotificationCopy(
        "Your workspace role changed",
        f"{_actor(actor_name)} changed your workspace role from "
        f"{_label(previous_role)} to {_label(new_role)}.",
    )


def reverification_copy(*, outcome: object | None, finding_type: str) -> NotificationCopy:
    state = _value(outcome) if outcome is not None else "failed"
    copy = {
        "reproduced": NotificationCopy(
            "Finding still detected",
            f"Re-verification confirmed that {finding_type} is still present.",
        ),
        "not_reproduced": NotificationCopy(
            "Finding not detected",
            f"Re-verification did not reproduce {finding_type}. "
            "Review the evidence before changing its status.",
        ),
        "inconclusive": NotificationCopy(
            "Re-verification inconclusive",
            f"Re-verification could not determine whether {finding_type} is still "
            "present. Review the collected evidence.",
        ),
        "failed": NotificationCopy(
            "Re-verification unsuccessful",
            "The finding could not be re-verified. Review the job details before trying again.",
        ),
    }
    return copy[state]
