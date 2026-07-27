from shared.models.reverification import ReverificationOutcome
from shared.models.scan import ScanStatus
from shared.models.vulnerability import RemediationStatus
from shared.notification_copy import (
    analysis_terminal_copy,
    finding_comment_copy,
    finding_review_copy,
    remediation_copy,
    reverification_copy,
    role_change_copy,
    scan_terminal_copy,
)


def test_scan_and_analysis_copy_is_user_facing() -> None:
    scan = scan_terminal_copy(ScanStatus.completed, "https://example.com")
    failure = analysis_terminal_copy(False)

    assert scan.title == "Scan completed"
    assert scan.message == (
        "The security scan for https://example.com completed successfully. "
        "Your results are ready to review."
    )
    assert failure.title == "Analysis needs attention"
    assert "deterministic" not in failure.message.lower()
    assert "workspace owner, admin, or analyst" in failure.message


def test_collaboration_copy_uses_display_name_instead_of_email() -> None:
    review = finding_review_copy(
        actor_name="  Avery   Chen ",
        finding_type="SQL injection",
        false_positive=True,
    )
    comment = finding_comment_copy(
        actor_name="Avery Chen",
        finding_type="SQL injection",
    )

    assert review.message == "Avery Chen marked SQL injection as a false positive."
    assert comment.message == "Avery Chen commented on SQL injection."
    assert "@" not in review.message + comment.message


def test_workflow_values_are_presented_as_professional_labels() -> None:
    remediation = remediation_copy(
        actor_name="Avery Chen",
        finding_type="SQL injection",
        status=RemediationStatus.wont_fix,
    )
    role = role_change_copy(
        actor_name="Morgan Lee",
        previous_role="developer",
        new_role="analyst",
    )

    assert remediation.message == "Avery Chen changed SQL injection to “Risk accepted”."
    assert "wont fix" not in remediation.message.lower()
    assert role.message == (
        "Morgan Lee changed your workspace role from Developer to Analyst."
    )


def test_reverification_copy_explains_each_outcome() -> None:
    reproduced = reverification_copy(
        outcome=ReverificationOutcome.reproduced,
        finding_type="Cross-site scripting",
    )
    not_reproduced = reverification_copy(
        outcome=ReverificationOutcome.not_reproduced,
        finding_type="Cross-site scripting",
    )
    failed = reverification_copy(
        outcome=None,
        finding_type="Cross-site scripting",
    )

    assert reproduced.title == "Finding still detected"
    assert not_reproduced.title == "Finding not detected"
    assert failed.title == "Re-verification unsuccessful"
