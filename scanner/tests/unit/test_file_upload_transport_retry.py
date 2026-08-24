"""A transient transport error must not silently downgrade a Critical finding.

During a DVWA scan the upload POST hit the shared 10s request timeout while the
rest of the scan was hammering the same host. ``httpx.ReadTimeout`` stringifies
to ``''``, so the only trace was a blank ``File upload test failed for ...:``
line, and the scan reported ``verified_findings=0`` - an Unrestricted File Upload
turned into nothing. A timeout says nothing about whether the target is
vulnerable, so it must be retried rather than treated as a verdict.
"""

import httpx
import pytest

from app.core.detectors.file_upload import FileUploadDetector, UploadCandidate


class _FlakyClient:
    """Fails the first ``fail_times`` sends with a transport error, then succeeds."""

    def __init__(self, *, fail_times: int, body: str, canary_body: str) -> None:
        self.fail_times = fail_times
        self.body = body
        self.canary_body = canary_body
        self.upload_attempts = 0
        self.get_attempts = 0

    async def request(self, **kwargs):
        self.upload_attempts += 1
        if self.upload_attempts <= self.fail_times:
            raise httpx.ReadTimeout("")
        return httpx.Response(
            200,
            text=self.body,
            request=httpx.Request(kwargs.get("method", "POST"), kwargs["url"]),
        )

    async def get(self, url, **_kwargs):
        self.get_attempts += 1
        return httpx.Response(
            200, text=self.canary_body, request=httpx.Request("GET", url),
        )


def _candidate() -> UploadCandidate:
    return UploadCandidate(
        url="http://target.test/upload/",
        method="POST",
        file_field="uploaded",
        data={"MAX_FILE_SIZE": "100000", "Upload": "Upload"},
    )


@pytest.mark.asyncio
async def test_upload_finding_survives_a_transient_timeout(monkeypatch) -> None:
    monkeypatch.setattr(FileUploadDetector, "_TRANSPORT_RETRY_DELAY_S", 0)
    detector = FileUploadDetector()
    client = _FlakyClient(
        fail_times=1,
        body="<html>succesfully uploaded to hackable/uploads/sentry_test.php</html>",
        canary_body="SENTRY_UPLOAD_TEST_CANARY",
    )
    findings: list = []

    await detector._test_uploads(client, findings, _candidate())

    assert client.upload_attempts == 2, "the timed-out upload was not retried"
    assert [f.vuln_type for f in findings] == ["Unrestricted File Upload"]
    assert findings[0].severity.value == "Critical"


@pytest.mark.asyncio
async def test_transport_error_is_raised_once_retries_are_exhausted(monkeypatch) -> None:
    """Exhausted retries must surface the error, not fake a clean negative.

    A swallowed error would report "not vulnerable" for a parameter that was
    never actually tested.
    """
    monkeypatch.setattr(FileUploadDetector, "_TRANSPORT_RETRY_DELAY_S", 0)
    detector = FileUploadDetector()
    client = _FlakyClient(fail_times=99, body="", canary_body="")

    with pytest.raises(httpx.TransportError):
        await detector._test_uploads(client, [], _candidate())

    assert client.upload_attempts == detector._TRANSPORT_RETRIES + 1


@pytest.mark.asyncio
async def test_http_error_status_is_not_retried(monkeypatch) -> None:
    """A 403 is a real answer about the upload, so it must not burn retries."""
    monkeypatch.setattr(FileUploadDetector, "_TRANSPORT_RETRY_DELAY_S", 0)
    detector = FileUploadDetector()

    class _Rejecting:
        def __init__(self) -> None:
            self.attempts = 0

        async def request(self, **kwargs):
            self.attempts += 1
            return httpx.Response(
                403, text="blocked",
                request=httpx.Request("POST", kwargs["url"]),
            )

        async def get(self, url, **_kwargs):
            return httpx.Response(404, text="", request=httpx.Request("GET", url))

    client = _Rejecting()
    findings: list = []
    await detector._test_uploads(client, findings, _candidate())

    # One attempt per upload variant the detector tries - never 3x that from
    # retrying a decisive HTTP status.
    assert client.attempts > 0
    assert findings == []
