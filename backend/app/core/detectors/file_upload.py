import logging
import re
from urllib.parse import urljoin, urlparse

import httpx

from app.config import get_settings
from app.core.detectors.base_detector import BaseDetector, Finding
from app.core.verification.verification_framework import FormPayloadBuilder
from app.models.vulnerability import OwaspCategory, SeverityLevel
from app.utils.http_logging import make_httpx_response_logger

logger = logging.getLogger(__name__)


class FileUploadDetector(BaseDetector):
    name = "file_upload"

    _upload_paths = [
        "uploads/",
        "files/",
        "upload/",
        "file/",
        "userfiles/",
        "static/uploads/",
        "content/uploads/",
        "hackable/uploads/",
        "../uploads/",
        "../hackable/uploads/",
        "../../hackable/uploads/"
    ]

    _error_terms = [
        "invalid",
        "not allowed",
        "rejected",
        "forbidden",
        "denied",
        "failed",
        "unsupported",
        "not permitted",
        "error",
    ]

    async def detect(self, urls: list[str], forms: list[object], **kwargs: object) -> list[Finding]:
        findings: list[Finding] = []
        session_cookies = kwargs.get("session_cookies") or {}
        settings = get_settings()

        candidates = []
        for form in forms:
            form_url = getattr(form, "action", getattr(form, "page_url", ""))
            form_method = getattr(form, "method", "POST").upper()
            raw_inputs = list(getattr(form, "inputs", []))
            file_inputs = [inp for inp in raw_inputs if getattr(inp, "input_type", "").lower() == "file"]
            if file_inputs:
                candidates.append((form_url, form_method, raw_inputs, file_inputs[0].name))

        if not candidates:
            return []

        async with httpx.AsyncClient(
            timeout=settings.request_timeout_seconds,
            follow_redirects=True,
            headers={"User-Agent": "SentryStrikeScanner/1.0"},
            cookies=session_cookies,
            event_hooks={"response": [make_httpx_response_logger("file_upload", "upload_test")]},
        ) as client:
            for form_url, method, raw_inputs, file_field in candidates:
                try:
                    await self._test_uploads(client, findings, form_url, method, raw_inputs, file_field)
                except Exception as exc:
                    logger.error("File upload test failed for %s: %s", form_url, exc)

        return findings

    async def _test_uploads(
        self,
        client: httpx.AsyncClient,
        findings: list[Finding],
        form_url: str,
        method: str,
        raw_inputs: list,
        file_field: str,
    ) -> None:
        php_name = "sentry_test.php"
        php_content = b'<?php echo "SENTRY_UPLOAD_TEST_CANARY"; ?>'
        txt_name = "sentry_test.txt"
        txt_content = b"SENTRY_UPLOAD_TEST_CANARY"

        accepted, response = await self._send_upload(
            client,
            form_url,
            method,
            raw_inputs,
            file_field,
            php_name,
            php_content,
            "application/x-php",
        )

        if accepted:
            candidate_urls = self._extract_candidate_urls(response, form_url, php_name)
            for path in self._upload_paths:
                candidate_urls.append(urljoin(form_url, path + php_name))

            accessible_url = await self._find_canary(client, candidate_urls, "SENTRY_UPLOAD_TEST_CANARY")
            if accessible_url:
                findings.append(
                    Finding(
                        category=OwaspCategory.a04,
                        vuln_type="Unrestricted File Upload",
                        severity=SeverityLevel.critical,
                        url=form_url,
                        parameter=file_field,
                        method=method,
                        payload=php_name,
                        evidence=(
                            "Executable file upload accepted and accessible. "
                            f"Canary found at {accessible_url}."
                        ),
                        confidence_score=95.0,
                        detection_method="file_upload_execution",
                        reproducible=True,
                        verified=True,
                    )
                )
                return

        accepted, response = await self._send_upload(
            client,
            form_url,
            method,
            raw_inputs,
            file_field,
            php_name,
            php_content,
            "image/jpeg",
        )
        if accepted:
            candidate_urls = self._extract_candidate_urls(response, form_url, php_name)
            for path in self._upload_paths:
                candidate_urls.append(urljoin(form_url, path + php_name))

            accessible_url = await self._find_canary(client, candidate_urls, "SENTRY_UPLOAD_TEST_CANARY")
            if accessible_url:
                findings.append(
                    Finding(
                        category=OwaspCategory.a04,
                        vuln_type="Weak File Upload Validation",
                        severity=SeverityLevel.critical,
                        url=form_url,
                        parameter=file_field,
                        method=method,
                        payload=php_name,
                        evidence=f"Dangerous extension accepted with spoofed image content-type. Canary executed at {accessible_url}.",
                        confidence_score=95.0,
                        detection_method="content_type_bypass_execution",
                        reproducible=True,
                        verified=True,
                    )
                )
            else:
                findings.append(
                    Finding(
                        category=OwaspCategory.a04,
                        vuln_type="Weak File Upload Validation",
                        severity=SeverityLevel.high,
                        url=form_url,
                        parameter=file_field,
                        method=method,
                        payload=php_name,
                        evidence="Dangerous extension accepted with spoofed image content-type.",
                        confidence_score=80.0,
                        detection_method="content_type_bypass",
                        reproducible=True,
                        verified=True,
                    )
                )

        accepted, response = await self._send_upload(
            client,
            form_url,
            method,
            raw_inputs,
            file_field,
            "sentry_test.php.jpg",
            php_content,
            "image/jpeg",
        )
        if accepted:
            candidate_urls = self._extract_candidate_urls(response, form_url, "sentry_test.php.jpg")
            for path in self._upload_paths:
                candidate_urls.append(urljoin(form_url, path + "sentry_test.php.jpg"))

            accessible_url = await self._find_canary(client, candidate_urls, "SENTRY_UPLOAD_TEST_CANARY")
            if accessible_url:
                findings.append(
                    Finding(
                        category=OwaspCategory.a04,
                        vuln_type="Double Extension Bypass",
                        severity=SeverityLevel.critical,
                        url=form_url,
                        parameter=file_field,
                        method=method,
                        payload="sentry_test.php.jpg",
                        evidence=f"Double extension upload accepted with dangerous inner extension. Canary executed at {accessible_url}.",
                        confidence_score=95.0,
                        detection_method="double_extension_execution",
                        reproducible=True,
                        verified=True,
                    )
                )
            else:
                findings.append(
                    Finding(
                        category=OwaspCategory.a04,
                        vuln_type="Double Extension Bypass",
                        severity=SeverityLevel.high,
                        url=form_url,
                        parameter=file_field,
                        method=method,
                        payload="sentry_test.php.jpg",
                        evidence="Double extension upload accepted with dangerous inner extension.",
                        confidence_score=80.0,
                        detection_method="double_extension",
                        reproducible=True,
                        verified=True,
                    )
                )

        accepted, response = await self._send_upload(
            client,
            form_url,
            method,
            raw_inputs,
            file_field,
            txt_name,
            txt_content,
            "text/plain",
        )
        if accepted and not self._has_error_terms(response.text or ""):
            findings.append(
                Finding(
                    category=OwaspCategory.a04,
                    vuln_type="Missing File Type Validation",
                    severity=SeverityLevel.medium,
                    url=form_url,
                    parameter=file_field,
                    method=method,
                    payload=txt_name,
                    evidence="Upload endpoint accepts arbitrary file types without validation feedback.",
                    confidence_score=60.0,
                    detection_method="no_type_validation",
                    reproducible=True,
                    verified=True,
                )
            )

    async def _send_upload(
        self,
        client: httpx.AsyncClient,
        form_url: str,
        method: str,
        raw_inputs: list,
        file_field: str,
        filename: str,
        content: bytes,
        content_type: str,
    ) -> tuple[bool, httpx.Response]:
        data = self._build_form_payload(raw_inputs, file_field)
        files = {file_field: (filename, content, content_type)}

        response = await client.request(
            method="POST" if method != "POST" else method,
            url=form_url,
            data=data,
            files=files,
        )
        body = response.text or ""
        accepted = response.status_code in {200, 201, 202, 204, 302, 303} and not self._has_error_terms(body)
        return accepted, response

    def _build_form_payload(self, raw_inputs: list, file_field: str) -> dict:
        payload = FormPayloadBuilder.build(raw_inputs)
        if file_field in payload:
            del payload[file_field]
        return payload

    def _has_error_terms(self, body: str) -> bool:
        lowered = body.lower()
        return any(term in lowered for term in self._error_terms)

    def _extract_candidate_urls(self, response: httpx.Response, base_url: str, filename: str) -> list[str]:
        urls: list[str] = []
        body = response.text or ""

        # 1. Check Location header
        location = response.headers.get("Location")
        if location and filename in location:
            urls.append(urljoin(base_url, location))
            
        # 2. Extract from JSON
        import json
        try:
            data = response.json()
            def find_urls(obj):
                if isinstance(obj, dict):
                    for v in obj.values():
                        find_urls(v)
                elif isinstance(obj, list):
                    for v in obj:
                        find_urls(v)
                elif isinstance(obj, str) and filename in obj:
                    urls.append(urljoin(base_url, obj))
            find_urls(data)
        except json.JSONDecodeError:
            pass

        # 3. HTML / regex fallback
        for match in re.findall(r"https?://[^\"'\s>]+", body, re.I):
            if filename in match:
                urls.append(match)

        for match in re.findall(r"/[^\"'\s>]+", body):
            if filename in match:
                urls.append(urljoin(base_url, match))

        return urls

    async def _find_canary(
        self,
        client: httpx.AsyncClient,
        candidate_urls: list[str],
        canary: str,
    ) -> str | None:
        for url in candidate_urls:
            try:
                resp = await client.get(url)
                if resp.status_code == 200 and canary in (resp.text or ""):
                    return url
            except Exception:
                continue
        return None
