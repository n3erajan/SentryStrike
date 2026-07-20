import copy
import time

from app.core.detectors.base_detector import Finding
from app.utils.scan_http import build_observed_request_snippet
from shared.models.vulnerability import SeverityLevel


class ApiWorkflowMixin:
    async def _test_api_single_request_control(
        self,
        record: dict,
        *,
        session_cookies: dict,
        auth_headers: dict,
        flow_type: str,
    ) -> list[Finding]:
        from app.core.verification.verification_framework import HttpVerifier

        fields = record["fields"]
        body = copy.deepcopy(record["body"])
        headers = {**record["headers"], **auth_headers, "Content-Type": "application/json"}
        vuln_type = ""
        parameter = None
        severity = SeverityLevel.high
        evidence = ""
        detection_method = ""

        if flow_type == "password_reset":
            if not fields.get("new_password") or fields.get("token") or fields.get("mfa_code"):
                return []
            parameter = fields.get("new_password")
            self._set_body_path(body, parameter, f"SentryStrikeResetCheck{int(time.time())}!")
            vuln_type = "Password Reset API May Not Enforce Reset Token"
            severity = SeverityLevel.critical
            evidence = (
                "Replayable password-reset API body sets a new password without any token, code, nonce, "
                "or signature field. The endpoint accepted the safe verification request without a token error."
            )
            detection_method = "api_reset_token_enforcement_probe"
        elif flow_type == "password_change":
            # SAFETY: change-password enforcement is now tested exclusively by
            # _test_change_password_current_bypass, which runs against a freshly
            # provisioned DISPOSABLE account. The previous probe here fired the
            # change on the user's REAL scan session, which would actually rotate
            # (and thereby lock out / invalidate) the account under test. Delegated
            # away so we never mutate the real account's password.
            return []
        elif flow_type == "mfa":
            if fields.get("mfa_code") or fields.get("token"):
                return []
            parameter = fields.get("username") or "mfa"
            vuln_type = "MFA API Flow Missing Verification Code Parameter"
            evidence = (
                "Replayable MFA/verification API request was accepted even though the JSON body contains no "
                "OTP, verification code, token, or signed challenge field."
            )
            detection_method = "api_mfa_missing_code_probe"
        else:
            return []

        verifier = HttpVerifier(cookies=session_cookies)
        verifier.set_request_context(module="auth", parameter=str(parameter))
        try:
            resp = await verifier.send_request(
                record["url"],
                record["method"],
                None,
                None,
                headers=headers,
                json_body=body,
                test_phase=detection_method,
                parameter=str(parameter),
            )
        finally:
            await verifier.close()

        body_lower = (getattr(resp, "body", "") or "").lower()
        rejection_terms = {
            "invalid", "required", "missing", "token", "code", "otp", "current password",
            "old password", "unauthorized", "forbidden", "csrf", "mfa",
        }
        success_terms = {"success", "updated", "changed", "reset", "ok", "verified"}
        accepted = 200 <= getattr(resp, "status_code", 0) < 400
        rejected = any(term in body_lower for term in rejection_terms)
        explicit_success = any(term in body_lower for term in success_terms)
        if not accepted or rejected or not explicit_success:
            return []

        return [
            self._finding(
                vuln_type=vuln_type,
                url=record["url"],
                method=record["method"],
                parameter=str(parameter),
                severity=severity,
                evidence=evidence,
                verified=True,
                detection_method=detection_method,
                confidence_score=85.0,
                verification_request_snippet=getattr(resp, "request_snippet", None),
                verification_response_snippet=getattr(resp, "response_snippet", None),
                detection_evidence={"flow_type": flow_type, "source": record["source"]},
            )
        ]

    async def _test_api_auth_workflows(
        self,
        kwargs: dict[str, object],
        session_cookies: dict,
    ) -> list[Finding]:
        findings: list[Finding] = []
        auth_headers = dict(kwargs.get("auth_headers") or {})
        for record in self._api_records(kwargs):
            flow_type = self._api_flow_type(record)
            if flow_type == "login":
                findings.extend(await self._test_api_login_rate_limit(record, session_cookies))
                findings.extend(await self._test_api_default_credentials(record, kwargs, session_cookies))
            elif flow_type in {"password_reset", "password_change", "mfa"}:
                findings.extend(
                    await self._test_api_single_request_control(
                        record,
                        session_cookies=session_cookies,
                        auth_headers=auth_headers,
                        flow_type=flow_type,
                    )
                )
            # Weak-recovery is a property of the fields, not the flow label: a reset
            # endpoint that also carries a new-password field is classified as
            # "password_change" above, so run this structural check on every record
            # and let its own field guards scope it to genuine recovery flows.
            findings.extend(self._security_question_recovery_findings(record))
        return findings

    def _security_question_recovery_findings(self, record: dict) -> list[Finding]:
        """Flag a password-reset flow that recovers accounts via a security question.

        Structural weakness (OWASP A07): security questions are low-entropy,
        often answerable from public/social data, and non-revocable. When a reset
        flow sets a new password gated only on a security-answer field — with no
        unguessable, single-use token/OTP/signed challenge — the recovery channel
        is the weakest link. This is a design finding (the fields are observed),
        not an exploit attempt; confidence is moderate and no answer is guessed.
        """
        fields = record["fields"]
        if not fields.get("security_answer"):
            return []
        # Scope to a genuine RECOVERY flow (not registration, which also collects a
        # security answer): either the body sets a new password, or the endpoint is
        # a reset/recovery path. Both are universal recovery signals.
        url_lower = str(record["url"]).lower()
        is_recovery = bool(fields.get("new_password")) or self._url_contains(url_lower, self.reset_tokens)
        if not is_recovery:
            return []
        # A genuine unguessable factor (token/OTP/signed challenge) alongside the
        # security answer is defence-in-depth, not security-question-only recovery.
        if fields.get("token") or fields.get("mfa_code"):
            return []
        # This is a structural finding over an OBSERVED reset request; reconstruct
        # the request snippet from the recorded url/method/headers/body so the
        # report shows the exact request the weakness was found in.
        request_snippet = build_observed_request_snippet(
            url=record["url"],
            method=record["method"],
            headers=record.get("headers"),
            body=record.get("body"),
        )
        return [
            self._finding(
                vuln_type="Password Reset Relies on Security Question (Weak Recovery)",
                url=record["url"],
                method=record["method"],
                parameter=str(fields.get("security_answer")),
                severity=SeverityLevel.medium,
                evidence=(
                    "The password-reset flow sets a new password gated only on a security-answer "
                    "field, with no unguessable token, OTP, or signed challenge. Security questions "
                    "are low-entropy and frequently answerable from public data, making this recovery "
                    "channel a weak link for account takeover."
                ),
                verified=True,
                detection_method="security_question_recovery_pattern",
                confidence_score=65.0,
                verification_request_snippet=request_snippet,
                detection_evidence={
                    "security_answer_field": fields.get("security_answer"),
                    "new_password_field": fields.get("new_password"),
                    "source": record["source"],
                },
            )
        ]

    # ---------------------------------------------------------------------------
    # JWT/session token checks
    # ---------------------------------------------------------------------------
