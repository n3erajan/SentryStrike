import statistics

from app.core.detectors.base_detector import Finding
from shared.models.vulnerability import OwaspCategory, SeverityLevel


class AuthCommonMixin:
    def _path_hits(self, path_tokens: set[str], token_set: set[str]) -> bool:
        return bool(path_tokens.intersection(token_set))

    def _url_contains(self, lowered_url: str, token_set: set[str]) -> bool:
        return any(tok in lowered_url for tok in token_set)

    def _sensitive_query_params(self, query_params: list[tuple[str, str]], lowered_url: str) -> set[str]:
        credential_params = {"password", "passwd", "pass", "pwd", "secret", "api_key", "apikey", "private_key"}
        contextual_params = self._sensitive_get_params - credential_params
        auth_context = self._url_contains(
            lowered_url,
            self.login_tokens
            | self.reset_tokens
            | self.api_auth_tokens
            | self.mfa_tokens
            | {"oauth", "authorize", "callback", "session"},
        )

        leaked: set[str] = set()
        for key, value in query_params:
            key_lower = key.lower()
            value = value or ""
            if key_lower in credential_params and value:
                leaked.add(key_lower)
                continue
            if key_lower not in contextual_params or not value:
                continue
            value_lower = value.lower()
            looks_secret = (
                len(value) >= 16
                or value_lower.count(".") == 2
                or any(ch.isdigit() for ch in value) and any(ch.isalpha() for ch in value) and len(value) >= 8
            )
            if auth_context or looks_secret:
                leaked.add(key_lower)
        return leaked

    def _finding(
        self,
        vuln_type: str,
        url: str,
        evidence: str,
        severity: SeverityLevel,
        method: str | None = None,
        parameter: str | None = None,
        payload: str | None = None,
        verified: bool = False,
        detection_method: str = "heuristic",
        confidence_score: float = 0.0,
        category: OwaspCategory = OwaspCategory.a07,
        verification_request_snippet: str | None = None,
        verification_response_snippet: str | None = None,
        detection_evidence: dict | None = None,
    ) -> Finding:
        kwargs: dict = dict(
            category=category,
            vuln_type=vuln_type,
            severity=severity,
            url=url,
            evidence=evidence,
            verified=verified,
            detection_method=detection_method,
            confidence_score=confidence_score,
            verification_request_snippet=verification_request_snippet,
            verification_response_snippet=verification_response_snippet,
        )
        if detection_evidence is not None:
            kwargs["detection_evidence"] = detection_evidence
        if method is not None:
            kwargs["method"] = method
        if parameter is not None:
            kwargs["parameter"] = parameter
        if payload is not None:
            kwargs["payload"] = payload
        return Finding(**kwargs)

    def _rate_limit_signals_present(self, responses: list[object]) -> bool:
        for response in responses:
            if getattr(response, "status_code", 0) in {401, 403, 423, 429}:
                body_lower = (getattr(response, "body", "") or "").lower()
                if getattr(response, "status_code", 0) in {423, 429}:
                    return True
                if any(term in body_lower for term in self._rate_limit_terms):
                    return True
            body_lower = (getattr(response, "body", "") or "").lower()
            if any(term in body_lower for term in self._rate_limit_terms):
                return True
        return False

    @staticmethod
    def _response_signature(response: object) -> tuple:
        body = getattr(response, "body", "") or ""
        return (
            getattr(response, "status_code", 0),
            len(body),
        )

    def _burst_responses_stable(self, burst_results: list[dict]) -> bool:
        """Return True when burst responses show no server-side protection signal.

        Stability is assessed on two axes that actually indicate a control is
        present:

        1. **Status-code diversity** - any non-2xx code (401, 403, 423, 429,
           302 to a lockout page, etc.) in *any* burst means the server reacted.
        2. **Body-length divergence** - a consistent shift in response size
           (e.g. an error page replacing the login form) is a real signal.

        Timing alone is intentionally *not* used as a stability gate.  A server
        that simply slows down under concurrent load looks identical to one that
        is rate-limiting by delay, and on low-spec targets (like DVWA on a VM)
        the final large burst routinely inflates mean latency by 500-1500 ms
        with no actual protection in place.  Timing *trends* are therefore only
        used as a *supporting* signal when body/status changes are also present,
        not as an independent disqualifier.
        """
        responses = [r for result in burst_results for r in result["responses"]]
        if not responses:
            return False

        # --- 1. Status-code check -------------------------------------------
        # A protection control announces itself either as an explicit throttle
        # status (423 Locked / 429 Too Many Requests) or as a *transition* away
        # from the rejection baseline mid-burst (e.g. a 401 that flips to a
        # 302-lockout / 200-challenge, or a 200 login page replaced by an error
        # page). Soft signals (rate-limit/challenge terms) are already screened by
        # _rate_limit_signals_present before this method runs.
        #
        # A UNIFORM non-2xx code is NOT a control — it is the normal rejection
        # baseline. Most correct JSON APIs answer an invalid login with a steady
        # 401/403; the previous "must be 2xx" gate misread that as the server
        # reacting, so those APIs could never be flagged for missing brute-force
        # protection. We therefore key on throttle status + status *stability*,
        # not on the absolute 2xx range.
        statuses = [getattr(r, "status_code", 0) for r in responses]
        if any(code in {423, 429} for code in statuses):
            return False
        if len(set(statuses)) > 1:
            return False

        # --- 2. Body-length stability ----------------------------------------
        # A consistent change in response body size across bursts indicates the
        # server started returning a different page (e.g. lockout notice).
        # We use a per-burst mean rather than a global mean so a single slow
        # request in the last burst doesn't skew the calculation.
        body_lengths = [len(getattr(r, "body", "") or "") for r in responses]
        mean_length = statistics.mean(body_lengths) if body_lengths else 0
        tolerance = max(200, mean_length * 0.15)
        if any(abs(length - mean_length) > tolerance for length in body_lengths):
            return False

        return True

    # ---------------------------------------------------------------------------
    # Main detect method
    # ---------------------------------------------------------------------------
