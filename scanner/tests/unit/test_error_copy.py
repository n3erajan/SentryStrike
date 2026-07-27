from app.core.scan_orchestration.pipeline import public_scan_failure


class TargetUnreachableError(RuntimeError):
    pass


def test_target_failure_is_actionable_without_exposing_exception_text():
    secret = "connection failed with token=super-secret"

    message = public_scan_failure(TargetUnreachableError(secret))

    assert message == (
        "We couldn't connect to the target. Confirm that it is reachable "
        "from the scanner, then try again."
    )
    assert secret not in message


def test_unexpected_scan_failure_uses_safe_generic_copy():
    secret = "redis password=super-secret at /app/worker.py:44"

    message = public_scan_failure(RuntimeError(secret))

    assert message == "The scan stopped before it could finish. Please try again."
    assert secret not in message
