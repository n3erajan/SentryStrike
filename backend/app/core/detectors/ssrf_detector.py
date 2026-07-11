import asyncio
import logging
import re

from app.config import get_settings
from app.core.detectors.base_detector import BaseDetector, Finding
from app.core.detectors.attack_surface import AttackSurface, AttackTarget
from app.core.detectors.param_selection import SSRF_NAME_TOKENS, ssrf_candidate
from app.core.verification.oast import OastClient
from app.core.verification.response_analyzer import is_dead_baseline
from app.core.verification.verification_framework import HttpVerifier
from app.models.vulnerability import OwaspCategory, SeverityLevel
from app.utils.scan_http import build_scan_headers

logger = logging.getLogger(__name__)


class SSRFDetector(BaseDetector):
    name = "ssrf"

    # Name half of the name-OR-value selection (see param_selection).
    ssrf_param_tokens = SSRF_NAME_TOKENS

    # SSRF verification payloads
    SSRF_PAYLOADS = [
        ("http://127.0.0.1:80/", r"Sentry Strike|Apache|nginx|IIS|html|doctype", "Localhost HTTP fetch"),
        ("http://169.254.169.254/latest/meta-data/", r"ami-id|instance-id|security-groups", "AWS/Cloud Metadata fetch"),
    ]

    # In-band fallback probes (used only when OAST is not configured and content
    # reflection did not fire). Internal targets are expected to behave
    # differently from the external control if the server actually fetches them.
    # Ports are varied to reduce coincidental collisions; no app-specific values.
    INBAND_INTERNAL_TARGETS = [
        ("http://127.0.0.1:9/", "loopback discard port"),
        ("http://169.254.169.254/latest/meta-data/", "link-local cloud metadata"),
    ]
    # Routable external control host that should resolve but is dedicated to this
    # scanner (never a real service), so a well-behaved app treats it uniformly.
    INBAND_CONTROL_TARGET = "http://control.sentrystrike.invalid/"
    # Number of repetitions per target to average out timing noise.
    INBAND_REPETITIONS = 2

    @staticmethod
    def _inband_differential(
        control_samples: list[tuple[int, int, float]],
        internal_samples: list[tuple[int, int, float]],
        timing_delta_ms: float,
    ) -> str | None:
        """Return a human-readable reason if internal vs control differ robustly.

        Each sample is ``(status_code, body_length, response_time_ms)``. A
        difference is only reported when it is *consistent* across repetitions,
        to keep noisy in-band signals from producing false positives. Returns
        ``None`` when the two target classes are indistinguishable.
        """
        if not control_samples or not internal_samples:
            return None

        def avg(samples: list[tuple[int, int, float]], idx: int) -> float:
            return sum(s[idx] for s in samples) / len(samples)

        control_status = {s[0] for s in control_samples}
        internal_status = {s[0] for s in internal_samples}
        # Consistent status divergence (each side agrees with itself, disagree cross).
        if (
            len(control_status) == 1
            and len(internal_status) == 1
            and control_status != internal_status
        ):
            return (
                f"internal target consistently returned HTTP {internal_status.pop()} "
                f"vs external control HTTP {control_status.pop()}"
            )

        # Consistent, substantial timing delta (e.g. internal target hangs/refuses).
        control_time = avg(control_samples, 2)
        internal_time = avg(internal_samples, 2)
        if abs(internal_time - control_time) >= timing_delta_ms:
            direction = "slower" if internal_time > control_time else "faster"
            return (
                f"internal target responded {abs(internal_time - control_time):.0f}ms "
                f"{direction} than the external control (avg {internal_time:.0f}ms vs {control_time:.0f}ms)"
            )

        # Consistent, large body-length divergence.
        control_len = avg(control_samples, 1)
        internal_len = avg(internal_samples, 1)
        if control_len and internal_len and abs(internal_len - control_len) / max(control_len, internal_len) >= 0.5:
            return (
                f"internal target response body length ({internal_len:.0f}) diverged "
                f"substantially from the external control ({control_len:.0f})"
            )
        return None

    async def _probe_inband(self, cand: AttackTarget, verifier, build_request, timing_delta_ms: float) -> Finding | None:
        """In-band SSRF heuristic: internal targets vs external control differential.

        Sends the candidate's sink pointed at internal targets and an external
        control host, repeated to smooth timing noise, then reports a PROBABLE
        (unverified) finding when a robust, consistent differential appears.
        """
        async def sample(value: str):
            url, params, data, json_body, headers, cookies = build_request(cand, value)
            resp = await verifier.send_request(
                url,
                cand.method,
                params,
                data,
                headers=headers,
                cookies=cookies,
                json_body=json_body,
                test_phase="ssrf_inband",
                payload=value,
            )
            triple = (
                resp.status_code,
                len(resp.body or ""),
                float(getattr(resp, "response_time_ms", 0.0) or 0.0),
            )
            return triple, resp

        control_samples: list[tuple[int, int, float]] = []
        for _ in range(self.INBAND_REPETITIONS):
            triple, _resp = await sample(self.INBAND_CONTROL_TARGET)
            control_samples.append(triple)

        for target, desc in self.INBAND_INTERNAL_TARGETS:
            internal_samples: list[tuple[int, int, float]] = []
            last_resp = None
            for _ in range(self.INBAND_REPETITIONS):
                triple, last_resp = await sample(target)
                internal_samples.append(triple)

            reason = self._inband_differential(
                control_samples, internal_samples, timing_delta_ms
            )
            if reason:
                return Finding(
                    category=OwaspCategory.a01,
                    vuln_type="Server-Side Request Forgery (SSRF) - Probable",
                    severity=SeverityLevel.medium,
                    url=cand.url,
                    parameter=cand.parameter,
                    method=cand.method,
                    payload=target,
                    evidence=(
                        f"Probable SSRF via in-band differential ({desc}): {reason}. "
                        "Unverified heuristic — configure an OAST callback "
                        "(OAST_CALLBACK_BASE_URL) to confirm blind SSRF."
                    ),
                    confidence_score=50.0,
                    detection_method="ssrf_inband_differential",
                    reproducible=False,
                    verified=False,
                    verification_request_snippet=getattr(last_resp, "request_snippet", None),
                    verification_response_snippet=getattr(last_resp, "response_snippet", None),
                    detection_evidence={
                        "proof_type": "inband_differential",
                        "control_target": self.INBAND_CONTROL_TARGET,
                    },
                )
        return None

    async def detect(self, urls: list[str], forms: list[object], **kwargs: object) -> list[Finding]:
        findings: list[Finding] = []
        session_cookies = kwargs.get("session_cookies") or {}
        auth_headers = kwargs.get("auth_headers")
        scan_config = kwargs.get("scan_config")
        settings = get_settings()
        oast_callback = scan_config.get_val("oast_callback_base_url", settings.oast_callback_base_url) if scan_config else settings.oast_callback_base_url
        oast_poll = scan_config.get_val("oast_poll_url", settings.oast_poll_url) if scan_config else settings.oast_poll_url
        ssrf_timing_delta = scan_config.get_val("ssrf_inband_timing_delta_ms", settings.ssrf_inband_timing_delta_ms) if scan_config else settings.ssrf_inband_timing_delta_ms
        oast = kwargs.get("oast_client")
        if not isinstance(oast, OastClient):
            oast = OastClient(
                oast_callback,
                oast_poll,
                timeout_seconds=settings.request_timeout_seconds,
            )

        # Build the surface unfiltered, then select on name-OR-value so params
        # whose value looks like a URL qualify even with a generic name.
        planner = kwargs.get("attack_planner")
        surface = (
            planner.targets_for(self.name)
            if planner is not None and hasattr(planner, "targets_for")
            else AttackSurface.build(
                urls,
                forms,
                parameters=kwargs.get("parameters") or [],
                api_endpoints=kwargs.get("api_endpoints") or [],
                requests=kwargs.get("requests") or [],
            )
        )
        candidates = [
            candidate for candidate in surface
            if ssrf_candidate(candidate.parameter, candidate.value)
        ]

        if not candidates:
            return []

        # 2. Active Verification
        semaphore = asyncio.Semaphore(4)
        verifier = HttpVerifier(cookies=session_cookies, headers=build_scan_headers(auth_headers))
        verifier.set_request_context(module="ssrf")

        def build_request(cand: AttackTarget, value: str):
            prepared = cand.build_request(value)
            return (
                prepared.url,
                prepared.params,
                prepared.data,
                prepared.json_body,
                prepared.headers,
                prepared.cookies,
            )

        async def verify_candidate(cand: AttackTarget) -> list[Finding]:
            cand_findings = []

            async with semaphore:
                verifier.set_request_context(parameter=cand.parameter)
                try:
                    # Retrieve baseline first
                    baseline_url, baseline_params, baseline_data, baseline_json, baseline_headers, baseline_cookies = build_request(
                        cand, str(cand.value or "")
                    )
                    baseline = await verifier.send_request(
                        baseline_url,
                        cand.method,
                        baseline_params,
                        baseline_data,
                        headers=baseline_headers,
                        cookies=baseline_cookies,
                        json_body=baseline_json,
                        test_phase="baseline",
                    )

                    # Dead-baseline abort: 401/403/404/405 to the plain baseline
                    # means the sink is unreachable/unauthorized as sent, so the
                    # reflection/OAST/in-band probes cannot yield a differential —
                    # skip rather than spend the SSRF payload budget on 4xx noise.
                    if is_dead_baseline(baseline):
                        return cand_findings

                    for payload, regex_pattern, desc in self.SSRF_PAYLOADS:
                        # Make sure baseline doesn't already trigger the signature
                        if baseline.status_code == 200 and re.search(regex_pattern, baseline.body, re.I):
                            continue

                        injected_url, injected_params, injected_data, injected_json, injected_headers, injected_cookies = build_request(
                            cand, payload
                        )
                        injected = await verifier.send_request(
                            injected_url,
                            cand.method,
                            injected_params,
                            injected_data,
                            headers=injected_headers,
                            cookies=injected_cookies,
                            json_body=injected_json,
                            test_phase="ssrf_injection", payload=payload,
                        )

                        # Check if internal content successfully loaded into the response
                        if injected.status_code == 200 and re.search(regex_pattern, injected.body, re.I):
                            cand_findings.append(
                                Finding(
                                    category=OwaspCategory.a01,
                                    vuln_type="Server-Side Request Forgery (SSRF)",
                                    severity=SeverityLevel.high,
                                    url=cand.url,
                                    parameter=cand.parameter,
                                    method=cand.method,
                                    payload=payload,
                                    evidence=f"SSRF verified via payload '{payload}' ({desc}). Response contains internal host signature.",
                                    confidence_score=95.0,
                                    detection_method="ssrf_reflection",
                                    reproducible=True,
                                    verified=True,
                                    verification_request_snippet=injected.request_snippet,
                                    verification_response_snippet=injected.response_snippet,
                                )
                            )
                            break

                    if not cand_findings and oast.enabled:
                        callback_url, interaction_id = oast.new_callback_url("ssrf")
                        (
                            callback_req_url,
                            callback_params,
                            callback_data,
                            callback_json,
                            callback_headers,
                            callback_cookies,
                        ) = build_request(cand, callback_url)
                        callback_response = await verifier.send_request(
                            callback_req_url,
                            cand.method,
                            callback_params,
                            callback_data,
                            headers=callback_headers,
                            cookies=callback_cookies,
                            json_body=callback_json,
                            test_phase="ssrf_blind_oast",
                            payload=callback_url,
                        )
                        await asyncio.sleep(0.2)
                        interactions = await oast.poll(interaction_id)
                        if interactions:
                            cand_findings.append(
                                Finding(
                                    category=OwaspCategory.a01,
                                    vuln_type="Blind Server-Side Request Forgery (SSRF)",
                                    severity=SeverityLevel.high,
                                    url=cand.url,
                                    parameter=cand.parameter,
                                    method=cand.method,
                                    payload=callback_url,
                                    evidence=(
                                        "Blind SSRF verified through an out-of-band callback interaction "
                                        f"for interaction id '{interaction_id}'."
                                    ),
                                    confidence_score=95.0,
                                    detection_method="ssrf_oast_callback",
                                    reproducible=True,
                                    verified=True,
                                    verification_request_snippet=callback_response.request_snippet,
                                    verification_response_snippet=callback_response.response_snippet,
                                    detection_evidence={
                                        "interaction_id": interaction_id,
                                        "interaction_count": len(interactions),
                                    },
                                )
                            )

                    # In-band fallback: when OAST is unavailable and nothing was
                    # confirmed, look for a robust differential between internal
                    # targets and an external control. Reported as PROBABLE only —
                    # never verified — because in-band signals are inherently noisy.
                    if not cand_findings and not oast.enabled:
                        inband = await self._probe_inband(cand, verifier, build_request, ssrf_timing_delta)
                        if inband:
                            cand_findings.append(inband)
                except Exception as e:
                    logger.error("SSRF verification failed for %s param %s: %s", cand.url, cand.parameter, e)
            return cand_findings

        tasks = [verify_candidate(c) for c in candidates]
        results = await asyncio.gather(*tasks)
        for res in results:
            findings.extend(res)

        await verifier.close()
        return findings
