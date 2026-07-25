"""Shared helpers for detector/verifier-backed re-verification strategies."""

from __future__ import annotations

from typing import Any

from app.core.crawler.models import ParameterLocation
from app.core.detectors.attack_surface import AttackTarget
from app.core.detectors.base_detector import Finding
from shared.models.reverification import ReverificationEvidence, ReverificationOutcome
from shared.models.vulnerability import VerificationTarget


def _normalize(value: str | None) -> str:
    return (value or "").strip().lower()


def finding_matches(
    finding: Finding,
    *,
    url: str,
    vuln_type: str | None,
    parameter: str | None,
) -> bool:
    if _normalize(finding.url) != _normalize(url):
        # Allow path-only drift when the detector rewrites query strings.
        if _normalize(finding.url).split("?", 1)[0] != _normalize(url).split("?", 1)[0]:
            return False
    if parameter and finding.parameter and _normalize(finding.parameter) != _normalize(parameter):
        return False
    if not vuln_type:
        return True
    expected = _normalize(vuln_type)
    actual = _normalize(finding.vuln_type)
    return expected == actual or expected in actual or actual in expected


def match_findings(
    findings: list[Finding],
    *,
    url: str,
    vuln_type: str | None,
    parameter: str | None,
) -> list[Finding]:
    return [
        finding
        for finding in findings
        if finding_matches(finding, url=url, vuln_type=vuln_type, parameter=parameter)
    ]


def outcome_from_matches(
    matches: list[Finding],
    *,
    url: str,
    method: str,
) -> tuple[ReverificationOutcome, list[ReverificationEvidence]]:
    if matches:
        top = matches[0]
        return (
            ReverificationOutcome.reproduced,
            [
                ReverificationEvidence(
                    request_url=top.url or url,
                    request_method=(top.method or method or "GET").upper(),
                    reason=(
                        f"Detector re-confirmed '{top.vuln_type}'"
                        + (f" on parameter '{top.parameter}'." if top.parameter else ".")
                    ),
                    response_snippet=(top.verification_response_snippet or top.evidence or "")[:2000]
                    or None,
                    proof_matched=True,
                )
            ],
        )
    return (
        ReverificationOutcome.not_reproduced,
        [
            ReverificationEvidence(
                request_url=url,
                request_method=(method or "GET").upper(),
                reason="Scoped detector run did not re-confirm the original finding.",
                proof_matched=False,
            )
        ],
    )


def inconclusive(
    *,
    url: str,
    method: str,
    reason: str,
) -> tuple[ReverificationOutcome, list[ReverificationEvidence]]:
    return (
        ReverificationOutcome.inconclusive,
        [
            ReverificationEvidence(
                request_url=url,
                request_method=(method or "GET").upper(),
                reason=reason,
            )
        ],
    )


def _parse_location(raw: str | None) -> ParameterLocation:
    value = (raw or "query").strip().lower()
    aliases = {
        "json": ParameterLocation.json_body,
        "json_body": ParameterLocation.json_body,
        "body_json": ParameterLocation.json_body,
        "form": ParameterLocation.form,
        "form_body": ParameterLocation.form,
        "body": ParameterLocation.form,
        "data": ParameterLocation.form,
        "path": ParameterLocation.path,
        "path_segment": ParameterLocation.path,
        "query": ParameterLocation.query,
        "header": ParameterLocation.header,
        "cookie": ParameterLocation.cookie,
        "graphql_variable": ParameterLocation.graphql_variable,
    }
    return aliases.get(value, ParameterLocation.query)


def attack_target_snapshot(target: AttackTarget) -> dict[str, Any]:
    """Serialize AttackTarget fields safe to persist on a finding."""
    form_inputs = None
    if target.form_inputs:
        form_inputs = []
        for item in target.form_inputs:
            if isinstance(item, dict):
                form_inputs.append(
                    {
                        "name": str(item.get("name") or ""),
                        "input_type": str(item.get("input_type") or item.get("type") or "text"),
                        "value": str(item.get("value") or ""),
                    }
                )
            else:
                form_inputs.append(
                    {
                        "name": str(getattr(item, "name", "") or ""),
                        "input_type": str(
                            getattr(item, "input_type", None)
                            or getattr(item, "type", None)
                            or "text"
                        ),
                        "value": str(getattr(item, "value", "") or ""),
                    }
                )
    template: dict[str, Any] = {
        "parameter_location": (
            target.location.value if isinstance(target.location, ParameterLocation) else str(target.location)
        ),
        "baseline_value": str(target.value or ""),
        "content_type": target.content_type,
        "form_inputs": form_inputs,
        "json_template": target.json_template,
    }
    if target.json_template is not None:
        template["json_body"] = target.json_template
    return {"request_template": template, "parameter_location": template["parameter_location"]}


def rebuild_attack_target(target: VerificationTarget) -> AttackTarget:
    template = target.request_template if isinstance(target.request_template, dict) else {}
    location = _parse_location(
        target.parameter_location or template.get("parameter_location")
    )
    form_inputs = template.get("form_inputs")
    json_template = template.get("json_template")
    if json_template is None:
        json_template = template.get("json_body")
    content_type = template.get("content_type")
    baseline = template.get("baseline_value")
    if baseline is None:
        baseline = ""
    headers = {}
    raw_headers = template.get("headers")
    if isinstance(raw_headers, dict):
        # Drop redacted auth carriers; live session overrides auth anyway.
        for key, value in raw_headers.items():
            key_l = str(key).lower()
            if key_l in {"authorization", "cookie"}:
                continue
            if value is None or "[REDACTED]" in str(value):
                continue
            headers[str(key)] = str(value)
    return AttackTarget(
        url=target.url,
        parameter=target.parameter or "",
        method=(target.method or "GET").upper(),
        value=baseline,
        location=location,
        form_inputs=form_inputs,
        content_type=str(content_type) if content_type else None,
        json_template=json_template,
        headers=headers,
    )


def attach_attack_target_metadata(finding: Finding, target: AttackTarget) -> Finding:
    snapshot = attack_target_snapshot(target)
    evidence = dict(finding.detection_evidence or {})
    evidence.update(snapshot)
    finding.detection_evidence = evidence
    location = snapshot.get("parameter_location")
    if location:
        setattr(finding, "parameter_location", location)
    return finding
