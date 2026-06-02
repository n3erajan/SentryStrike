import json
import logging
import re
from urllib.parse import urljoin, urlparse

import httpx

from app.config import get_settings
from app.core.detectors.base_detector import BaseDetector, Finding
from app.models.vulnerability import OwaspCategory, SeverityLevel
from app.utils.http_logging import make_httpx_response_logger
from app.utils.scan_http import create_scan_client

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
            # Resolve the form action against its page URL to get an absolute URL.
            # form.action may be relative (e.g. "" or "../upload") so we must
            # urljoin it against the page that contained the form.
            page_url = getattr(form, "page_url", "") or ""
            raw_action = getattr(form, "action", "") or ""
            if raw_action:
                form_url = urljoin(page_url, raw_action)
            else:
                # No action attribute — browser submits back to the same page.
                form_url = page_url

            form_method = (getattr(form, "method", "POST") or "POST").upper()
            raw_inputs = list(getattr(form, "inputs", []))

            # Accept both "file" and "FILE" — normalise to lower-case.
            file_inputs = [
                inp for inp in raw_inputs
                if getattr(inp, "input_type", "").lower() == "file"
            ]
            if file_inputs:
                candidates.append((form_url, form_method, raw_inputs, file_inputs[0].name))

        if not candidates:
            logger.info(
                "file_upload: no forms with file inputs found in %d form(s) — skipping",
                len(forms),
            )
            return []

        logger.info(
            "file_upload: testing %d upload form(s): %s",
            len(candidates),
            ", ".join(sorted({url for url, _, _, _ in candidates})),
        )

        # Derive the site root once so candidate upload paths can be built
        # relative to the origin rather than the form's own path.
        async with create_scan_client(
            timeout=settings.request_timeout_seconds,
            follow_redirects=True,
            headers={"User-Agent": "SentryStrikeScanner/1.0"},
            cookies=session_cookies,
            event_hooks={"response": [make_httpx_response_logger("file_upload", "upload_test")]},
        ) as client:
            for form_url, method, raw_inputs, file_field in candidates:
                try:
                    await self._test_uploads(
                        client, findings, form_url, method, raw_inputs, file_field
                    )
                except Exception as exc:
                    logger.error("File upload test failed for %s: %s", form_url, exc)

        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _site_root(self, url: str) -> str:
        """Return the scheme+host (+ port) portion of *url*, e.g. 'http://host:8080'."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

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
        site_root = self._site_root(form_url)

        # --- Test 1: plain .php upload with correct content-type ---
        accepted, response = await self._send_upload(
            client, form_url, method, raw_inputs, file_field,
            php_name, php_content, "application/x-php",
        )
        if accepted:
            candidate_urls = self._extract_candidate_urls(response, form_url, site_root, php_name)
            accessible_url = await self._find_canary(client, candidate_urls, "SENTRY_UPLOAD_TEST_CANARY")
            if accessible_url:
                findings.append(Finding(
                    category=OwaspCategory.a05,
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
                ))
                return  # Most severe finding recorded — stop here.

        # --- Test 2: .php upload with spoofed image/jpeg content-type ---
        accepted, response = await self._send_upload(
            client, form_url, method, raw_inputs, file_field,
            php_name, php_content, "image/jpeg",
        )
        if accepted:
            candidate_urls = self._extract_candidate_urls(response, form_url, site_root, php_name)
            accessible_url = await self._find_canary(client, candidate_urls, "SENTRY_UPLOAD_TEST_CANARY")
            if accessible_url:
                findings.append(Finding(
                    category=OwaspCategory.a05,
                    vuln_type="Weak File Upload Validation",
                    severity=SeverityLevel.critical,
                    url=form_url,
                    parameter=file_field,
                    method=method,
                    payload=php_name,
                    evidence=(
                        f"Dangerous extension accepted with spoofed image content-type. "
                        f"Canary executed at {accessible_url}."
                    ),
                    confidence_score=95.0,
                    detection_method="content_type_bypass_execution",
                    reproducible=True,
                    verified=True,
                ))
            else:
                findings.append(Finding(
                    category=OwaspCategory.a05,
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
                ))

        # --- Test 3: double extension (.php.jpg) ---
        dbl_name = "sentry_test.php.jpg"
        accepted, response = await self._send_upload(
            client, form_url, method, raw_inputs, file_field,
            dbl_name, php_content, "image/jpeg",
        )
        if accepted:
            candidate_urls = self._extract_candidate_urls(response, form_url, site_root, dbl_name)
            accessible_url = await self._find_canary(client, candidate_urls, "SENTRY_UPLOAD_TEST_CANARY")
            if accessible_url:
                findings.append(Finding(
                    category=OwaspCategory.a05,
                    vuln_type="Double Extension Bypass",
                    severity=SeverityLevel.critical,
                    url=form_url,
                    parameter=file_field,
                    method=method,
                    payload=dbl_name,
                    evidence=(
                        f"Double extension upload accepted with dangerous inner extension. "
                        f"Canary executed at {accessible_url}."
                    ),
                    confidence_score=95.0,
                    detection_method="double_extension_execution",
                    reproducible=True,
                    verified=True,
                ))
            else:
                findings.append(Finding(
                    category=OwaspCategory.a05,
                    vuln_type="Double Extension Bypass",
                    severity=SeverityLevel.high,
                    url=form_url,
                    parameter=file_field,
                    method=method,
                    payload=dbl_name,
                    evidence="Double extension upload accepted with dangerous inner extension.",
                    confidence_score=80.0,
                    detection_method="double_extension",
                    reproducible=True,
                    verified=True,
                ))

        # --- Test 4: unrestricted type — accepts plain .txt ---
        accepted, response = await self._send_upload(
            client, form_url, method, raw_inputs, file_field,
            txt_name, txt_content, "text/plain",
        )
        if accepted and not self._has_error_terms(response.text or ""):
            findings.append(Finding(
                category=OwaspCategory.a05,
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
            ))

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

        # BUG FIX: original code had inverted ternary:
        #   method="POST" if method != "POST" else method
        # which always resolves to "POST" but was clearly intended to
        # normalise the value — just pass method directly.
        response = await client.request(
            method=method,
            url=form_url,
            data=data,
            files=files,
        )
        body = response.text or ""
        accepted = (
            response.status_code in {200, 201, 202, 204, 302, 303}
            and not self._has_error_terms(body)
        )
        return accepted, response

    def _build_form_payload(self, raw_inputs: list, file_field: str) -> dict:
        # FormPayloadBuilder.build() requires (form_inputs, target_param, target_value)
        # and is designed for injection-style tests.  For file upload we don't have a
        # payload to inject — we just need sibling fields filled with benign defaults so
        # the server doesn't reject the submission for missing required fields.
        # We build that ourselves here rather than misusing FormPayloadBuilder.
        payload: dict[str, str] = {}
        for inp in raw_inputs:
            name = getattr(inp, "name", "")
            if not name:
                continue
            inp_type = getattr(inp, "input_type", "text").lower()
            if inp_type == "file":
                # Exclude all file fields — they are passed via the `files=` kwarg.
                continue
            elif inp_type == "password":
                payload[name] = "sentry_password123"
            elif inp_type in ("submit", "button"):
                payload[name] = getattr(inp, "value", "Submit") or "Submit"
            elif inp_type == "hidden":
                payload[name] = getattr(inp, "value", "") or ""
            else:
                payload[name] = getattr(inp, "value", "") or "sentry_test_val"
        return payload

    def _has_error_terms(self, body: str) -> bool:
        lowered = body.lower()
        return any(term in lowered for term in self._error_terms)

    def _extract_candidate_urls(
        self,
        response: httpx.Response,
        form_url: str,
        site_root: str,
        filename: str,
    ) -> list[str]:
        """
        Build a list of URLs where the uploaded file might be accessible.

        Candidate sources (in priority order):
          1. Location response header
          2. JSON body values that look like paths/URLs
          3. Absolute URLs found via regex in HTML body
          4. Relative paths found via regex in HTML body
          5. Well-known upload directory guesses relative to site root
             (NOT relative to the form URL, which is a sub-path and would
             produce wrong results with urljoin for paths like 'uploads/')
        """
        urls: list[str] = []

        # 1. Location header
        location = response.headers.get("Location", "")
        if location and filename in location:
            urls.append(urljoin(form_url, location))

        # 2. JSON body
        try:
            data = response.json()

            def _walk(obj: object) -> None:
                if isinstance(obj, dict):
                    for v in obj.values():
                        _walk(v)
                elif isinstance(obj, list):
                    for v in obj:
                        _walk(v)
                elif isinstance(obj, str) and filename in obj:
                    # Resolve relative JSON paths against the site root so that
                    # a value like "/hackable/uploads/sentry_test.php" becomes
                    # "http://host/hackable/uploads/sentry_test.php".
                    urls.append(urljoin(site_root, obj))

            _walk(data)
        except (json.JSONDecodeError, Exception):
            pass

        # 3. Absolute URLs in HTML
        for match in re.findall(r"https?://[^\"\'\s>]+", response.text or "", re.I):
            if filename in match:
                urls.append(match)

        # 4. Relative paths in HTML
        for match in re.findall(r"/[^\"\'\s>]+", response.text or ""):
            if filename in match:
                urls.append(urljoin(site_root, match))

        # 5. Common upload directory guesses — anchored to site root, not form path.
        #    Using form_url with urljoin for paths like "uploads/" would resolve to
        #    e.g. http://host/dvwa/vulnerabilities/uploads/ (wrong).
        #    urljoin(site_root, "uploads/sentry_test.php") → http://host/uploads/sentry_test.php
        #    which is the correct behaviour for a root-relative guess.
        for path in self._upload_paths:
            urls.append(urljoin(site_root + "/", path + filename))

        # Deduplicate while preserving order.
        seen: set[str] = set()
        deduped: list[str] = []
        for u in urls:
            if u not in seen:
                seen.add(u)
                deduped.append(u)
        return deduped

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