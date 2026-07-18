import json
import logging
import re
from dataclasses import dataclass, field
from html import unescape
from urllib.parse import urljoin, urlparse

import httpx

from app.config import get_settings
from app.core.detectors.base_detector import BaseDetector, Finding
from app.core.detectors.attack_surface import AttackSurface
from shared.models.vulnerability import OwaspCategory, SeverityLevel
from app.utils.http_logging import make_httpx_response_logger
from app.utils.scan_http import build_httpx_evidence_snippets, build_scan_headers, create_scan_client

logger = logging.getLogger(__name__)


@dataclass
class UploadCandidate:
    url: str
    method: str
    file_field: str
    raw_inputs: list = field(default_factory=list)
    data: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    source: str = "form"


class FileUploadDetector(BaseDetector):
    name = "file_upload"

    # A file upload is a state-changing operation: it is carried only by a
    # request method with a meaningful body (POST/PUT/PATCH). GET/HEAD/DELETE/
    # OPTIONS candidates are never upload sinks — they arise when the crawler
    # observed a plain data request to a URL that superficially matched an upload
    # field/path heuristic. Testing them produces false positives: a GET data
    # endpoint ignores the multipart body, so every file type yields an identical
    # 2xx (and an oversized body is rejected 413 by the framework's *generic*
    # request-size limit, not any upload validator), which trips the accept/reject
    # differential (Test 8). Restricting candidates to body-bearing methods is
    # framework- and target-agnostic.
    _UPLOAD_METHODS = frozenset({"POST", "PUT", "PATCH"})

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
        auth_headers = kwargs.get("auth_headers")
        settings = get_settings()

        candidates: list[UploadCandidate] = []
        for form in forms:
            # Resolve the form action against its page URL to get an absolute URL.
            # form.action may be relative (e.g. "" or "../upload") so we must
            # urljoin it against the page that contained the form.
            page_url = getattr(form, "page_url", "") or ""
            raw_action = getattr(form, "action", "") or ""
            if raw_action:
                form_url = urljoin(page_url, raw_action)
            else:
                # No action attribute - browser submits back to the same page.
                form_url = page_url

            form_method = (getattr(form, "method", "POST") or "POST").upper()
            raw_inputs = list(getattr(form, "inputs", []))

            # Accept both "file" and "FILE" - normalise to lower-case.
            file_inputs = [
                inp for inp in raw_inputs
                if getattr(inp, "input_type", "").lower() == "file"
            ]
            if file_inputs:
                candidates.append(
                    UploadCandidate(
                        url=form_url,
                        method=form_method,
                        raw_inputs=raw_inputs,
                        file_field=file_inputs[0].name,
                        source="html_form",
                    )
                )

        candidates.extend(self._api_upload_candidates(kwargs))

        # Drop candidates whose method cannot carry a file upload (see
        # _UPLOAD_METHODS). A GET/HEAD/DELETE endpoint is not an upload sink;
        # testing it manufactures accept-differential false positives.
        non_upload = [c for c in candidates if (c.method or "").upper() not in self._UPLOAD_METHODS]
        if non_upload:
            logger.info(
                "file_upload: dropping %d non-upload-method candidate(s): %s",
                len(non_upload),
                ", ".join(sorted({f"{c.method} {c.url}" for c in non_upload})),
            )
        candidates = [c for c in candidates if (c.method or "").upper() in self._UPLOAD_METHODS]

        if not candidates:
            logger.info(
                "file_upload: no upload candidates found in %d form(s) - skipping",
                len(forms),
            )
            return []

        logger.info(
            "file_upload: testing %d upload candidate(s): %s",
            len(candidates),
            ", ".join(sorted({candidate.url for candidate in candidates})),
        )

        # Derive the site root once so candidate upload paths can be built
        # relative to the origin rather than the form's own path.
        async with create_scan_client(
            timeout=settings.request_timeout_seconds,
            follow_redirects=True,
            headers=build_scan_headers(auth_headers),
            cookies=session_cookies,
            event_hooks={"response": [make_httpx_response_logger("file_upload", "upload_test")]},
        ) as client:
            for candidate in candidates:
                try:
                    await self._test_uploads(client, findings, candidate)
                except Exception as exc:
                    logger.error("File upload test failed for %s: %s", candidate.url, exc)

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
        candidate: UploadCandidate,
    ) -> None:
        php_name = "sentry_test.php"
        php_content = b'<?php echo "SENTRY_UPLOAD_TEST_CANARY"; ?>'
        txt_name = "sentry_test.txt"
        txt_content = b"SENTRY_UPLOAD_TEST_CANARY"
        form_url = candidate.url
        method = candidate.method
        file_field = candidate.file_field
        site_root = self._site_root(form_url)

        # --- Test 1: plain .php upload with correct content-type ---
        accepted, response = await self._send_upload(
            client, candidate,
            php_name, php_content, "application/x-php",
        )
        if accepted:
            candidate_urls = self._extract_candidate_urls(response, form_url, site_root, php_name)
            accessible_url = await self._find_canary(client, candidate_urls, "SENTRY_UPLOAD_TEST_CANARY")
            response_evidence = self._has_upload_response_evidence(response, php_name)
            if accessible_url:
                request_snippet, response_snippet = build_httpx_evidence_snippets(
                    response, payload=php_name,
                    fallback_url=candidate.url, fallback_method=candidate.method,
                    fallback_headers=candidate.headers, fallback_body=php_name,
                )
                findings.append(Finding(
                    category=OwaspCategory.a01,
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
                    detection_evidence={
                        "canary_executed": True,
                        "accessible_url": accessible_url,
                        "uploaded_filename": php_name,
                    },
                    reproducible=True,
                    verified=True,
                    verification_request_snippet=request_snippet,
                    verification_response_snippet=response_snippet,
                ))
                return  # Most severe finding recorded - stop here.

        # --- Test 2: .php upload with spoofed image/jpeg content-type ---
        accepted, response = await self._send_upload(
            client, candidate,
            php_name, php_content, "image/jpeg",
        )
        if accepted:
            request_snippet, response_snippet = build_httpx_evidence_snippets(
                response, payload=php_name,
                fallback_url=candidate.url, fallback_method=candidate.method,
                fallback_headers=candidate.headers, fallback_body=php_name,
            )
            candidate_urls = self._extract_candidate_urls(response, form_url, site_root, php_name)
            accessible_url = await self._find_canary(client, candidate_urls, "SENTRY_UPLOAD_TEST_CANARY")
            if accessible_url:
                findings.append(Finding(
                    category=OwaspCategory.a01,
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
                    detection_evidence={
                        "canary_executed": True,
                        "accessible_url": accessible_url,
                        "uploaded_filename": php_name,
                        "spoofed_content_type": "image/jpeg",
                    },
                    reproducible=True,
                    verified=True,
                    verification_request_snippet=request_snippet,
                    verification_response_snippet=response_snippet,
                ))
            elif response_evidence:
                findings.append(Finding(
                    category=OwaspCategory.a01,
                    vuln_type="Weak File Upload Validation",
                    severity=SeverityLevel.high,
                    url=form_url,
                    parameter=file_field,
                    method=method,
                    payload=php_name,
                    evidence=(
                        "Dangerous extension upload appeared accepted and the response referenced the uploaded file, "
                        "but subsequent retrieval did not confirm execution or persistence."
                    ),
                    confidence_score=65.0,
                    detection_method="content_type_bypass_response_evidence",
                    detection_evidence={
                        "canary_executed": False,
                        "uploaded_filename": php_name,
                        "spoofed_content_type": "image/jpeg",
                    },
                    reproducible=False,
                    verified=False,
                    verification_request_snippet=request_snippet,
                    verification_response_snippet=response_snippet,
                ))

        # --- Test 3: double extension (.php.jpg) ---
        dbl_name = "sentry_test.php.jpg"
        accepted, response = await self._send_upload(
            client, candidate,
            dbl_name, php_content, "image/jpeg",
        )
        if accepted:
            candidate_urls = self._extract_candidate_urls(response, form_url, site_root, dbl_name)
            accessible_url = await self._find_canary(client, candidate_urls, "SENTRY_UPLOAD_TEST_CANARY")
            response_evidence = self._has_upload_response_evidence(response, dbl_name)
            dbl_request_snippet, dbl_response_snippet = build_httpx_evidence_snippets(
                response, payload=dbl_name,
                fallback_url=candidate.url, fallback_method=candidate.method,
                fallback_headers=candidate.headers, fallback_body=dbl_name,
            )
            if accessible_url:
                findings.append(Finding(
                    category=OwaspCategory.a01,
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
                    detection_evidence={
                        "canary_executed": True,
                        "accessible_url": accessible_url,
                        "uploaded_filename": dbl_name,
                    },
                    reproducible=True,
                    verified=True,
                    verification_request_snippet=dbl_request_snippet,
                    verification_response_snippet=dbl_response_snippet,
                ))
            elif response_evidence:
                findings.append(Finding(
                    category=OwaspCategory.a01,
                    vuln_type="Double Extension Bypass",
                    severity=SeverityLevel.high,
                    url=form_url,
                    parameter=file_field,
                    method=method,
                    payload=dbl_name,
                    evidence=(
                        "Double extension upload appeared accepted and the response referenced the uploaded file, "
                        "but subsequent retrieval did not confirm execution or persistence."
                    ),
                    confidence_score=65.0,
                    detection_method="double_extension_response_evidence",
                    detection_evidence={
                        "canary_executed": False,
                        "uploaded_filename": dbl_name,
                    },
                    reproducible=False,
                    verified=False,
                    verification_request_snippet=dbl_request_snippet,
                    verification_response_snippet=dbl_response_snippet,
                ))

        # --- Test 4: unrestricted type - accepts plain .txt ---
        accepted, response = await self._send_upload(
            client, candidate,
            txt_name, txt_content, "text/plain",
        )
        if accepted and not self._has_error_terms(response.text or ""):
            candidate_urls = self._extract_candidate_urls(response, form_url, site_root, txt_name)
            accessible_url = await self._find_canary(client, candidate_urls, "SENTRY_UPLOAD_TEST_CANARY")
            response_evidence = self._has_upload_response_evidence(response, txt_name)
            if accessible_url or response_evidence:
                txt_request_snippet, txt_response_snippet = build_httpx_evidence_snippets(
                    response, payload=txt_name,
                    fallback_url=candidate.url, fallback_method=candidate.method,
                    fallback_headers=candidate.headers, fallback_body=txt_name,
                )
                findings.append(Finding(
                    category=OwaspCategory.a01,
                    vuln_type="Missing File Type Validation",
                    severity=SeverityLevel.medium,
                    url=form_url,
                    parameter=file_field,
                    method=method,
                    payload=txt_name,
                    evidence=(
                        f"Uploaded text file was retrievable at {accessible_url}."
                        if accessible_url
                        else "Upload response referenced the uploaded text file; retrieval did not confirm persistence."
                    ),
                    confidence_score=80.0 if accessible_url else 55.0,
                    detection_method=(
                        "no_type_validation_persistence"
                        if accessible_url
                        else "no_type_validation_response_evidence"
                    ),
                    reproducible=bool(accessible_url),
                    verified=bool(accessible_url),
                    verification_request_snippet=txt_request_snippet,
                    verification_response_snippet=txt_response_snippet,
                ))

        # --- Test 5: SVG image-validation bypass (stored-XSS-capable image) ---
        await self._test_svg_image_bypass(client, findings, candidate, site_root)

        # --- Test 6: XML entity-parser differential (bounded, safe) ---
        await self._test_xml_parser(client, findings, candidate)

        # --- Test 7: real XXE — external entity file disclosure (reflected) ---
        await self._test_xxe_external_entity(client, findings, candidate)

        # --- Test 8: type-allowlist bypass (accept-differential, no retrieval) ---
        # A secure upload endpoint enforces a type allowlist and REJECTS dangerous
        # active-content / executable types. When a benign allowed type AND a
        # dangerous active-content type are accepted IDENTICALLY, the endpoint
        # applies no server-side file-type validation (CWE-434) — a real weakness
        # even when the stored file is never served back (so Tests 1-5, which all
        # require retrieval/execution to confirm, stay silent).
        #
        # Zero-FP anchor: we ALSO require the endpoint to REJECT an oversized upload.
        # That proves it runs real server-side upload validation (a size guard), so
        # accepting the dangerous type is a genuine gap — not a permissive stub that
        # merely echoes 2xx to everything (which we cannot distinguish from a real
        # handler and must not flag). Framework-agnostic: keyed on the accept/reject
        # differential, never on a target path.
        already_flagged = any(
            f.url == form_url
            and f.vuln_type in {
                "Unrestricted File Upload",
                "Missing File Type Validation",
                "Weak File Upload Validation",
            }
            for f in findings
        )
        if not already_flagged:
            benign_ok, benign_resp = await self._send_upload(
                client, candidate, "sentry_ok.pdf", b"%PDF-1.4\n%sentry benign\n", "application/pdf",
            )
            danger_name = "sentry_active.html"
            danger_ok, danger_resp = await self._send_upload(
                client, candidate, danger_name,
                b"<!doctype html><script>/*SENTRY_UPLOAD_TYPE*/</script>", "text/html",
            )
            # A file large enough to trip any reasonable size guard. A validating
            # handler rejects it; a blind accept-everything stub does not.
            oversize_ok, _oversize_resp = await self._send_upload(
                client, candidate, "sentry_big.pdf", b"%PDF-1.4\n" + b"A" * (512 * 1024), "application/pdf",
            )
            if (
                benign_ok
                and danger_ok
                and benign_resp.status_code == danger_resp.status_code
                and not oversize_ok
            ):
                danger_request_snippet, danger_response_snippet = build_httpx_evidence_snippets(
                    danger_resp, payload=danger_name,
                    fallback_url=candidate.url, fallback_method=candidate.method,
                    fallback_headers=candidate.headers, fallback_body=danger_name,
                )
                findings.append(Finding(
                    category=OwaspCategory.a01,
                    vuln_type="Missing File Type Validation",
                    severity=SeverityLevel.medium,
                    url=form_url,
                    parameter=file_field,
                    method=method,
                    payload=danger_name,
                    evidence=(
                        "Upload endpoint enforces server-side validation (an oversized upload was "
                        "rejected) but applies NO file-type allowlist: a benign 'application/pdf' file "
                        "and a dangerous active-content 'text/html' file were both accepted with an "
                        f"identical HTTP {danger_resp.status_code} response (CWE-434). If such an upload "
                        "is later served from this origin it enables stored XSS or code execution; "
                        "storage/retrieval was not confirmed here."
                    ),
                    confidence_score=70.0,
                    detection_method="upload_type_allowlist_bypass_differential",
                    detection_evidence={
                        "benign_content_type": "application/pdf",
                        "benign_status": benign_resp.status_code,
                        "dangerous_content_type": "text/html",
                        "dangerous_status": danger_resp.status_code,
                        "oversize_rejected": True,
                        "retrieval_confirmed": False,
                    },
                    reproducible=True,
                    verified=True,
                    verification_request_snippet=danger_request_snippet,
                    verification_response_snippet=danger_response_snippet,
                ))

    # A bounded, entirely internal XML entity. There is NO external reference
    # (no SYSTEM/http/file) and NO recursive expansion, so it can never cause an
    # SSRF, file read, or billion-laughs blow-up — it only reveals whether the
    # parser expands entities at all, a precondition for XXE.
    _XML_ENTITY_CANARY = "SENTRY_XXE_ENTITY_CANARY"
    _XML_ENTITY_DOC = (
        '<?xml version="1.0"?>'
        f'<!DOCTYPE sentry [<!ENTITY probe "{_XML_ENTITY_CANARY}">]>'
        "<sentry>&probe;</sentry>"
    ).encode()
    _XML_CONTROL_DOC = (
        '<?xml version="1.0"?><sentry>SENTRY_XML_CONTROL</sentry>'
    ).encode()

    # External-entity (real XXE) probes. Each references a benign, universally
    # present read-only OS file; the signature is content that appears ONLY when
    # the parser resolves the external entity and reflects it — never in our own
    # payload — so a match is undeniable proof of arbitrary file disclosure (zero
    # false positive). Read-only and bounded (one small doc per probe). No SSRF,
    # no write, no recursion. Covers the two dominant server OS families so the
    # check is target-agnostic (a Linux or Windows backend each has one hit).
    _XXE_CANARY = "SENTRY_XXE_EXT"
    _XXE_EXTERNAL_PROBES = (
        ("file:///etc/passwd", re.compile(r"root:.*?:0:0:", re.I)),
        ("file:///c:/windows/win.ini", re.compile(r"\[(?:extensions|fonts|mci extensions)\]", re.I)),
    )

    # Tokens that mark an endpoint as a likely document/data parser rather than a
    # plain image/avatar upload. Deliberately excludes the ubiquitous
    # ``upload``/``file`` tokens (which match nearly every candidate) so the XML
    # entity probe stays off image forms and only fires on parser-like surfaces.
    _XML_PARSER_TOKENS = (
        "xml", "import", "document", "doc", "parse", "feed", "sitemap",
        "svg", "convert", "ingest",
    )

    def _looks_xml_parser_candidate(self, candidate: UploadCandidate) -> bool:
        """True when the candidate endpoint plausibly parses uploaded XML.

        Gated so the bounded XML entity probe fires only on document/import/parse-
        like endpoints (or fields), never on every avatar/image form. A field or
        URL token match is enough; verification still requires a real response
        differential, so a loose gate cannot manufacture a finding.
        """
        haystack = f"{candidate.url} {candidate.file_field}".lower()
        for token in candidate.data or {}:
            haystack += f" {str(token).lower()}"
        return any(token in haystack for token in self._XML_PARSER_TOKENS)

    async def _test_svg_image_bypass(
        self,
        client: httpx.AsyncClient,
        findings: list[Finding],
        candidate: UploadCandidate,
        site_root: str,
    ) -> None:
        """Upload a tiny SVG carrying a canary; confirm via retrieval.

        An SVG accepted as an image and served inline is script-capable (stored
        XSS). Bounded (a few hundred bytes) and non-destructive; reported only
        when the uploaded canary is retrievable, mirroring the other subchecks.
        """
        svg_name = "sentry_test.svg"
        svg_content = (
            '<?xml version="1.0"?>'
            '<svg xmlns="http://www.w3.org/2000/svg">'
            "<text>SENTRY_UPLOAD_TEST_CANARY</text></svg>"
        ).encode()
        accepted, response = await self._send_upload(
            client, candidate, svg_name, svg_content, "image/svg+xml",
        )
        if not accepted:
            return
        candidate_urls = self._extract_candidate_urls(response, candidate.url, site_root, svg_name)
        accessible_url = await self._find_canary(client, candidate_urls, "SENTRY_UPLOAD_TEST_CANARY")
        if not accessible_url:
            return
        svg_request_snippet, svg_response_snippet = build_httpx_evidence_snippets(
            response, payload=svg_name,
            fallback_url=candidate.url, fallback_method=candidate.method,
            fallback_headers=candidate.headers, fallback_body=svg_name,
        )
        findings.append(Finding(
            category=OwaspCategory.a01,
            vuln_type="Unrestricted File Upload",
            severity=SeverityLevel.high,
            url=candidate.url,
            parameter=candidate.file_field,
            method=candidate.method,
            payload=svg_name,
            evidence=(
                "SVG image upload accepted and retrievable at "
                f"{accessible_url}; SVG served inline can execute script (stored XSS)."
            ),
            confidence_score=85.0,
            detection_method="svg_image_upload_persistence",
            detection_evidence={
                "canary_executed": False,
                "accessible_url": accessible_url,
                "uploaded_filename": svg_name,
            },
            reproducible=True,
            verified=True,
            verification_request_snippet=svg_request_snippet,
            verification_response_snippet=svg_response_snippet,
        ))

    async def _test_xml_parser(
        self,
        client: httpx.AsyncClient,
        findings: list[Finding],
        candidate: UploadCandidate,
    ) -> None:
        """Exercise a multipart XML endpoint with a bounded internal-entity doc.

        Sends a benign control document and an internal-entity document (no
        external/SYSTEM reference, no recursion) and compares. If the entity's
        expanded value appears in the response, entity expansion is verified;
        if only the response differs consistently, a probable signal is recorded.
        Never reports on the benign control alone.
        """
        if not self._looks_xml_parser_candidate(candidate):
            return
        control_accepted, control_resp = await self._send_upload(
            client, candidate, "sentry_control.xml", self._XML_CONTROL_DOC, "text/xml",
        )
        entity_accepted, entity_resp = await self._send_upload(
            client, candidate, "sentry_entity.xml", self._XML_ENTITY_DOC, "text/xml",
        )
        if not entity_accepted:
            return
        entity_body = entity_resp.text or ""
        entity_request_snippet, entity_response_snippet = build_httpx_evidence_snippets(
            entity_resp, payload="sentry_entity.xml",
            fallback_url=candidate.url, fallback_method=candidate.method,
            fallback_headers=candidate.headers, fallback_body="sentry_entity.xml",
        )
        # Strongest signal: the parser expanded the internal entity and reflected
        # its value (the raw entity name is gone, the canary text is present).
        if self._XML_ENTITY_CANARY in entity_body and "&probe;" not in entity_body:
            findings.append(Finding(
                category=OwaspCategory.a05,
                vuln_type="XML Entity Expansion",
                severity=SeverityLevel.medium,
                url=candidate.url,
                parameter=candidate.file_field,
                method=candidate.method,
                payload="sentry_entity.xml",
                evidence=(
                    "Uploaded XML had its internal entity expanded and reflected in "
                    "the response — the parser resolves entities, a precondition for "
                    "XXE. Bounded internal-only entity was used (no external fetch)."
                ),
                confidence_score=70.0,
                detection_method="xml_entity_expansion_reflected",
                detection_evidence={"parser_expands_entities": True},
                reproducible=True,
                verified=True,
                verification_request_snippet=entity_request_snippet,
                verification_response_snippet=entity_response_snippet,
            ))
            return
        # Weaker signal: the entity doc is processed differently from the benign
        # control (accepted/rejected divergence or a parser error only on entity).
        control_body = control_resp.text or ""
        entity_error = self._has_error_terms(entity_body)
        control_error = control_accepted and not self._has_error_terms(control_body)
        if control_error and entity_error:
            findings.append(Finding(
                category=OwaspCategory.a05,
                vuln_type="XML Parser Behavior - Probable",
                severity=SeverityLevel.low,
                url=candidate.url,
                parameter=candidate.file_field,
                method=candidate.method,
                payload="sentry_entity.xml",
                evidence=(
                    "A multipart XML endpoint processed a benign control document but "
                    "errored on a document containing an internal entity, indicating "
                    "server-side XML entity handling worth manual XXE review."
                ),
                confidence_score=45.0,
                detection_method="xml_parser_control_differential",
                detection_evidence={"proof_type": "control_differential"},
                reproducible=False,
                verified=False,
                verification_request_snippet=entity_request_snippet,
                verification_response_snippet=entity_response_snippet,
            ))

    async def _test_xxe_external_entity(
        self,
        client: httpx.AsyncClient,
        findings: list[Finding],
        candidate: UploadCandidate,
    ) -> None:
        """Upload an XML doc with an EXTERNAL entity and detect reflected file read.

        This is the genuine XXE test (distinct from ``_test_xml_parser``, which
        uses an internal-only entity to detect mere entity expansion). Each probe
        references a benign read-only OS file via a ``file://`` SYSTEM entity; the
        finding fires ONLY when the referenced file's content is reflected in the
        response, which is undeniable proof the parser resolved the external
        entity and disclosed a server-side file. Fires on any upload candidate
        (an XML sink may be reached even through a field named ``file``); the
        reflection requirement makes it zero-FP on endpoints that ignore the XML
        or strip entities, so no parser-token gate is needed. Bounded, read-only,
        non-destructive.
        """
        for uri, signature in self._XXE_EXTERNAL_PROBES:
            doc = (
                '<?xml version="1.0" encoding="UTF-8"?>'
                f'<!DOCTYPE sentry [<!ENTITY xxe SYSTEM "{uri}">]>'
                f"<sentry><probe>{self._XXE_CANARY}&xxe;</probe></sentry>"
            ).encode()
            try:
                _accepted, response = await self._send_upload(
                    client, candidate, "sentry_xxe.xml", doc, "application/xml",
                )
            except Exception:
                continue
            body = response.text or ""
            match = signature.search(body)
            # The signature is reflected file content, never present in our
            # payload — any match proves external-entity resolution + disclosure.
            if not match:
                continue
            disclosed = body[match.start(): match.start() + 80]
            xxe_request_snippet, xxe_response_snippet = build_httpx_evidence_snippets(
                response, payload="sentry_xxe.xml", extra_markers=[disclosed],
                fallback_url=candidate.url, fallback_method=candidate.method,
                fallback_headers=candidate.headers, fallback_body="sentry_xxe.xml",
            )
            findings.append(Finding(
                category=OwaspCategory.a05,
                vuln_type="XML External Entity (XXE) Injection",
                severity=SeverityLevel.high,
                url=candidate.url,
                parameter=candidate.file_field,
                method=candidate.method,
                payload="sentry_xxe.xml",
                evidence=(
                    "Uploaded XML with an external SYSTEM entity "
                    f"({uri}) was resolved server-side and the referenced file's "
                    "content was reflected in the response — arbitrary file "
                    f"disclosure via XXE. Disclosed content: {disclosed!r}."
                ),
                confidence_score=95.0,
                detection_method="xxe_external_entity_file_read",
                detection_evidence={
                    "entity_uri": uri,
                    "reflected_file_content": disclosed,
                    "file_disclosed": True,
                },
                reproducible=True,
                verified=True,
                verification_request_snippet=xxe_request_snippet,
                verification_response_snippet=xxe_response_snippet,
            ))
            return

    async def _send_upload(
        self,
        client: httpx.AsyncClient,
        candidate: UploadCandidate,
        filename: str,
        content: bytes,
        content_type: str,
    ) -> tuple[bool, httpx.Response]:
        data = dict(candidate.data)
        if candidate.raw_inputs:
            data.update(self._build_form_payload(candidate.raw_inputs, candidate.file_field))
        files = {candidate.file_field: (filename, content, content_type)}

        # BUG FIX: original code had inverted ternary:
        #   method="POST" if method != "POST" else method
        # which always resolves to "POST" but was clearly intended to
        # normalise the value - just pass method directly.
        response = await client.request(
            method=candidate.method,
            url=candidate.url,
            data=data,
            files=files,
            headers=candidate.headers or None,
        )
        body = response.text or ""
        accepted = (
            response.status_code in {200, 201, 202, 204, 302, 303}
            and not self._has_error_terms(body)
        )
        return accepted, response

    def _api_upload_candidates(self, kwargs: dict[str, object]) -> list[UploadCandidate]:
        candidates: list[UploadCandidate] = []
        seen: set[tuple[str, str, str]] = set()

        def add(url: str, method: str, field_name: str, data: dict[str, str], headers: dict[str, str], source: str) -> None:
            if not url or not field_name:
                return
            key = (url, method.upper(), field_name)
            if key in seen:
                return
            seen.add(key)
            candidates.append(
                UploadCandidate(
                    url=url,
                    method=method.upper() or "POST",
                    file_field=field_name,
                    data=data,
                    headers={
                        key: value
                        for key, value in (headers or {}).items()
                        if key.lower() not in {"content-type", "content-length"}
                    },
                    source=source,
                )
            )

        upload_name = lambda name: any(
            token in (name or "").lower()
            for token in ("file", "upload", "avatar", "image", "document", "attachment", "import")
        )

        for target in AttackSurface.build(
            [],
            [],
            api_endpoints=list(kwargs.get("api_endpoints") or []),
            requests=list(kwargs.get("requests") or []),
            filter_fn=upload_name,
        ):
            if "multipart/form-data" not in str(target.content_type or "").lower():
                continue
            prepared = target.build_request(
                ("sentry_probe.txt", b"SENTRY_UPLOAD_TEST_CANARY", "text/plain")
            )
            add(
                prepared.url,
                prepared.method,
                target.parameter,
                dict(prepared.data or {}),
                dict(prepared.headers or {}),
                f"attack_surface_{target.source}",
            )

        for request in kwargs.get("requests") or []:
            headers = dict(getattr(request, "request_headers", {}) or {})
            content_type = " ".join(
                str(value).lower() for key, value in headers.items() if key.lower() == "content-type"
            )
            post_data = getattr(request, "post_data", None)
            if "multipart/form-data" not in content_type:
                continue
            fields = self._field_names_from_multipart_post_data(str(post_data or ""))
            file_field = next(
                (field for field in fields if any(token in field.lower() for token in ("file", "upload", "avatar", "image", "document"))),
                fields[0] if fields else "file",
            )
            data = {field: "sentry_test_val" for field in fields if field != file_field}
            add(
                str(getattr(request, "url", "") or ""),
                str(getattr(request, "method", "POST") or "POST"),
                file_field,
                data,
                headers,
                "browser_multipart_request",
            )

        for endpoint in kwargs.get("api_endpoints") or []:
            content_type = str(getattr(endpoint, "content_type", "") or "").lower()
            url = str(getattr(endpoint, "url", "") or "")
            body = getattr(endpoint, "request_body", None)
            if "multipart/form-data" not in content_type and not (
                url and any(token in url.lower() for token in ("upload", "file", "avatar", "image", "document", "import"))
            ):
                continue
            fields = list(body.keys()) if isinstance(body, dict) else []
            file_fields = [
                field for field in fields
                if any(token in field.lower() for token in ("file", "upload", "avatar", "image", "document"))
            ]
            file_field = file_fields[0] if file_fields else "file"
            sibling_data = {
                field: str(value)
                for field, value in body.items()
                if field != file_field
            } if isinstance(body, dict) else {}
            add(
                url,
                str(getattr(endpoint, "method", "POST") or "POST"),
                file_field,
                sibling_data,
                dict(getattr(endpoint, "headers", {}) or {}),
                "api_multipart_endpoint",
            )

        for asset in kwargs.get("assets") or []:
            text = str(asset)
            if "FormData" not in text and ".append(" not in text:
                continue
            endpoint_matches = [
                match
                for match in re.findall(r"""['"]([^'"]*(?:upload|file|avatar|image|document)[^'"]*)['"]""", text, re.I)
                if match.startswith(("/", "http://", "https://")) or "/" in match
            ]
            field_matches = re.findall(r"""\.append\(\s*['"]([^'"]+)['"]""", text)
            file_fields = [
                field for field in field_matches
                if any(token in field.lower() for token in ("file", "upload", "avatar", "image", "document"))
            ]
            root_url = str(kwargs.get("root_url") or "")
            for endpoint in endpoint_matches:
                url = urljoin(root_url, endpoint)
                add(
                    url,
                    "POST",
                    file_fields[0] if file_fields else "file",
                    {field: "sentry_test_val" for field in field_matches if field not in file_fields},
                    {},
                    "static_formdata_javascript",
                )

        return candidates

    @staticmethod
    def _field_names_from_multipart_post_data(post_data: str) -> list[str]:
        fields = re.findall(r'name="([^"]+)"', post_data or "")
        return list(dict.fromkeys(fields))

    def _build_form_payload(self, raw_inputs: list, file_field: str) -> dict:
        # FormPayloadBuilder.build() requires (form_inputs, target_param, target_value)
        # and is designed for injection-style tests.  For file upload we don't have a
        # payload to inject - we just need sibling fields filled with benign defaults so
        # the server doesn't reject the submission for missing required fields.
        # We build that ourselves here rather than misusing FormPayloadBuilder.
        payload: dict[str, str] = {}
        for inp in raw_inputs:
            name = getattr(inp, "name", "")
            if not name:
                continue
            inp_type = getattr(inp, "input_type", "text").lower()
            if inp_type == "file":
                # Exclude all file fields - they are passed via the `files=` kwarg.
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

    def _has_upload_response_evidence(self, response: httpx.Response, filename: str) -> bool:
        """True when the upload response itself references the submitted file."""
        location = response.headers.get("Location", "") or response.headers.get("location", "")
        if filename and filename in location:
            return True
        body = response.text or ""
        if filename and filename in body:
            return True
        try:
            return filename in json.dumps(response.json(), default=str)
        except Exception:
            return False

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
          3. URL/path references found in the response body
          4. Well-known upload directory guesses relative to site root
             (NOT relative to the form URL, which is a sub-path and would
             produce wrong results with urljoin for paths like 'uploads/')
        """
        urls: list[str] = []
        response_url = str(getattr(response, "url", "") or form_url)

        def _add_reference(reference: str) -> None:
            reference = unescape(str(reference or "")).strip().rstrip(".,;:)]}")
            if filename not in reference:
                return
            # Relative references are defined relative to the response URL. This
            # preserves application base paths and correctly normalises ../
            # segments; root-relative and absolute references also retain their
            # standard urljoin semantics.
            urls.append(urljoin(response_url, reference))

        # 1. Location header
        location = response.headers.get("Location", "")
        _add_reference(location)

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
                    _add_reference(obj)

            _walk(data)
        except (json.JSONDecodeError, Exception):
            pass

        # 3. References in HTML, JSON-like text, or plain success messages. Keep
        # the leading ../ or ./ portion: dropping it changes the application base
        # path for deployments mounted below the origin root.
        reference_pattern = re.compile(
            rf"(?:https?://|//|/|\.\.?/)?[^\s\"'<>]*{re.escape(filename)}[^\s\"'<>]*",
            re.I,
        )
        for match in reference_pattern.findall(response.text or ""):
            _add_reference(match)

        # 4. Common upload directory guesses - anchored to site root, not form path.
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
