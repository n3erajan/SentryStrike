"""Detectors record the structured proof markers their proof type needs.

Without these, the grader's evidence brief has no discriminator and the AI
adjudicator judges on raw response bytes alone - the Cause C failure from the
DVWA report, where RFI and default-credentials findings shipped with empty
detection_evidence and were dismissed. These tests lock the evidence contract
each detector must emit; the grader-side consumption is covered in
test_evidence_grader.py.
"""
from __future__ import annotations

from app.core.detectors.authentication.form_auth import FormAuthProbeMixin
from app.core.detectors.file_inclusion import FileInclusionDetector


class TestRfiContentEvidence:
    def test_records_remote_target_fingerprint_and_matched_tokens(self):
        ev = FileInclusionDetector._rfi_content_evidence(
            remote_target="http://example.com/",
            fingerprint="Remote include of example.com - content fingerprint",
            matched_tokens=["example domain", "iana.org/domains/example"],
        )
        assert ev["remote_target"] == "http://example.com/"
        assert ev["fingerprint"] == "Remote include of example.com - content fingerprint"
        assert ev["matched"] is True
        assert "example domain" in ev["matched_tokens"]

    def test_matched_is_false_when_no_tokens_present(self):
        ev = FileInclusionDetector._rfi_content_evidence(
            remote_target="http://example.com/", fingerprint="x", matched_tokens=[],
        )
        assert ev["matched"] is False


class TestDefaultCredentialsEvidence:
    def test_records_credential_pair_statuses_and_post_auth_signal(self):
        ev = FormAuthProbeMixin._default_credentials_evidence(
            username="admin", password="admin",
            baseline_status=200, authed_status=200,
            body_delta_bytes=1234, post_auth_language=True,
        )
        assert ev["credential_pair"] == "admin/admin"
        assert ev["baseline_status"] == 200
        assert ev["authed_status"] == 200
        assert ev["body_delta_bytes"] == 1234
        assert "post-auth" in ev["post_auth_signal"].lower()

    def test_post_auth_signal_still_records_the_differential_without_language(self):
        ev = FormAuthProbeMixin._default_credentials_evidence(
            username="admin", password="password",
            baseline_status=200, authed_status=302,
            body_delta_bytes=5000, post_auth_language=False,
        )
        signal = ev["post_auth_signal"].lower()
        # The status/size differential is still surfaced even without language.
        assert "302" in signal and "5000" in signal
        assert "post-auth language" not in signal
