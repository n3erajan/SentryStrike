from app.utils.pdf_generator import (
    _clean_category,
    _clean_enum,
    _dedupe_semicolon_text,
    _response_evidence_label_and_text,
    _split_response_evidence,
    build_detailed_findings,
    build_remediation_roadmap,
    build_scan_pdf,
    build_statistics,
    build_styles,
    build_vulnerability_summary,
    full_code_block,
)


def _flowable_text(flowables: list) -> str:
    parts: list[str] = []
    for flowable in flowables:
        nested = getattr(flowable, "_content", None) or getattr(flowable, "_flowables", None)
        if nested:
            parts.append(_flowable_text(list(nested)))
        if hasattr(flowable, "getPlainText"):
            parts.append(flowable.getPlainText())
        if hasattr(flowable, "_cellvalues"):
            for row in flowable._cellvalues:
                for cell in row:
                    if hasattr(cell, "getPlainText"):
                        parts.append(cell.getPlainText())
                    else:
                        parts.append(str(cell))
    return "\n".join(parts)


def test_pdf_helpers_strip_enum_prefixes_and_map_owasp_category() -> None:
    assert _clean_enum("SeverityLevel.medium") == "Medium"
    assert _clean_enum("Exploitability.easy") == "Easy"
    assert _clean_category("OwaspCategory.a05") == "A05-Injection"


def test_pdf_labels_evidence_only_response_blocks() -> None:
    label, text = _response_evidence_label_and_text(
        "VERIFICATION EVIDENCE:\nAuthentication form has no CSRF token parameter."
    )

    assert label == "VERIFICATION EVIDENCE"
    assert text == "Authentication form has no CSRF token parameter."


def test_pdf_splits_and_deduplicates_verification_evidence() -> None:
    evidence, excerpt = _split_response_evidence(
        "VERIFICATION EVIDENCE:\n"
        "Header not found: x-frame-options; Header not found: x-frame-options\n\n"
        "RESPONSE EXCERPT:\n<body>proof</body>"
    )

    assert evidence == "Header not found: x-frame-options"
    assert excerpt == "<body>proof</body>"


def test_pdf_evidence_dedupe_preserves_semicolons_inside_sql_excerpt() -> None:
    text = (
        "GET http://target.test/sqli?id=%27 -> HTTP 200 | "
        "Excerpt: \"<pre>You have an error in your SQL syntax; check the manual "
        "that corresponds to your MySQL server version for the right syntax</pre>\""
    )

    deduped = _dedupe_semicolon_text(text)

    assert "SQL syntax; check the manual" in deduped


def test_pdf_evidence_dedupe_drops_repeated_verbose_error_records() -> None:
    text = (
        "GET http://target.test/sqli?id=%27 -> HTTP 200 | Trigger: form fuzz | "
        "Excerpt: \"<pre>You have an error in your SQL syntax; check the manual "
        "that corresponds to your MySQL server version for the right syntax to use near ''''' at line 1</pre>\"; "
        "GET http://target.test/sqli -> HTTP 200 | Trigger: observed during SQLi | "
        "Excerpt: \"<pre>You have an error in your SQL syntax; check the manual "
        "that corresponds to your MySQL server version for the right syntax to use near ''' at line 1</pre>\""
    )

    deduped = _dedupe_semicolon_text(text)

    assert deduped.count("You have an error in your SQL syntax") == 1


def test_pdf_remediation_roadmap_keeps_full_remediation_text() -> None:
    long_remediation = (
        "Replace concatenated SQL with prepared statements. "
        "Use PDO::prepare(), bind parameters with explicit types, centralize query helpers, "
        "add regression tests for quote, boolean, and time-based payloads, and disable verbose "
        "database exceptions in production responses."
    )
    scan_data = {
        "data": {
            "vulnerabilities": [
                {
                    "vuln_type": "SQL Injection",
                    "severity": "SeverityLevel.critical",
                    "ai_analysis": {
                        "exploitability": "Exploitability.easy",
                        "remediation": long_remediation,
                    },
                }
            ]
        }
    }

    elems = build_remediation_roadmap(scan_data, build_styles())
    table = next(elem for elem in elems if hasattr(elem, "_cellvalues"))
    action_cell = table._cellvalues[1][1]

    assert "disable verbose database exceptions" in action_cell.getPlainText()
    assert "..." not in action_cell.getPlainText()


def test_pdf_detailed_findings_do_not_repeat_remediation_section() -> None:
    scan_data = {
        "data": {
            "vulnerabilities": [
                {
                    "vuln_type": "SQL Injection",
                    "category": "OwaspCategory.a05",
                    "severity": "SeverityLevel.critical",
                    "cvss_score": 9.0,
                    "location": {"url": "http://target.test/sqli", "parameter": "id", "http_method": "GET"},
                    "evidence": {},
                    "ai_analysis": {
                        "business_impact": "Database disclosure.",
                        "exploitability": "Exploitability.easy",
                        "exploitability_reasoning": "Payload triggers SQL errors.",
                        "remediation": "Use prepared statements.",
                    },
                }
            ]
        }
    }

    flowables = build_detailed_findings(scan_data, build_styles())
    labels = [getattr(flowable, "getPlainText", lambda: "")() for flowable in flowables]

    assert "REMEDIATION" not in labels


def test_pdf_executive_summary_includes_owner_and_authorization_metadata() -> None:
    from app.utils.pdf_generator import build_executive_summary

    scan_data = {
        "data": {
            "scan_id": "scan-1",
            "generated_at": "2026-06-08T09:10:17",
            "executive_summary": "Summary.",
            "risk_score": 45.0,
            "owner_email": "user@example.test",
            "authorization": {
                "confirmed": True,
                "confirmed_at": "2026-06-08T09:00:00",
            },
            "vulnerabilities": [{"location": {"url": "https://target.example/path"}}],
        }
    }

    text = _flowable_text(build_executive_summary(scan_data, build_styles()))

    assert "Submitted By" in text
    assert "user@example.test" in text
    assert "Authorization Confirmed" in text
    assert "Yes" in text
    assert "Authorization Confirmed At" in text


def test_pdf_statistics_include_evidence_auth_and_spa_api_coverage() -> None:
    scan_data = {
        "data": {
            "statistics": {
                "total_urls_crawled": 3,
                "total_vulnerabilities": 4,
                "severity_breakdown": {"critical": 1, "high": 1, "medium": 1, "low": 0, "info": 1},
            },
            "risk_score": 72.5,
            "vulnerabilities": [
                {"category": "OwaspCategory.a05"},
                {"category": "OwaspCategory.a07"},
            ],
            "evidence_strength_breakdown": {
                "confirmed_exploit": 1,
                "confirmed_observation": 1,
                "probable": 1,
                "possible": 0,
                "informational": 1,
            },
            "auth_coverage": {
                "state": "authenticated_verified",
                "authenticated_url_count": 2,
                "unauthenticated_url_count": 1,
                "protected_targets_verified": 1,
                "auth_headers_present": True,
                "session_cookies_present": True,
            },
            "spa_api_coverage": {
                "spa_detected": True,
                "js_assets_inspected": 4,
                "routes_extracted": 6,
                "api_endpoints_extracted": 5,
                "parameters_extracted": 9,
                "browser_requests_observed": 7,
                "dead_spa_fallback_routes_suppressed": 2,
            },
            "scanner_limitations": ["Browser discovery was disabled for this scan."],
        }
    }

    text = _flowable_text(build_statistics(scan_data, build_styles()))

    assert "Evidence Strength" in text
    assert "Confirmed Exploit" in text
    assert "Authenticated Coverage" in text
    assert "Authenticated Verified" in text
    assert "SPA / API Coverage" in text
    assert "API Endpoints Extracted" in text
    assert "Dead SPA Fallback Routes Suppressed" in text
    assert "Browser discovery was disabled for this scan." in text


def test_pdf_summary_labels_findings_by_evidence_and_review_status() -> None:
    scan_data = {
        "data": {
            "vulnerabilities": [
                {
                    "vuln_type": "Component CVE",
                    "category": "OwaspCategory.a03",
                    "severity": "SeverityLevel.medium",
                    "cvss_score": 5.0,
                    "review_status": "ReviewStatus.likely",
                    "evidence_strength": "probable",
                    "evidence": {},
                }
            ]
        }
    }

    text = _flowable_text(build_vulnerability_summary(scan_data, build_styles()))

    assert "Evidence" in text
    assert "Probable" in text
    assert "Likely" in text
    assert "confirmed vulnerabilities" not in text


def test_pdf_detailed_findings_include_evidence_strength_and_auth_context() -> None:
    scan_data = {
        "data": {
            "vulnerabilities": [
                {
                    "vuln_type": "JSON SQL Injection",
                    "category": "OwaspCategory.a05",
                    "severity": "SeverityLevel.critical",
                    "cvss_score": 9.0,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "review_status": "ReviewStatus.confirmed",
                    "evidence_strength": "confirmed_exploit",
                    "auth_context": "authenticated",
                    "location": {
                        "url": "http://target.test/api/search",
                        "parameter": "q",
                        "parameter_location": "json_body",
                        "http_method": "POST",
                    },
                    "evidence": {
                        "verified": True,
                        "detection_method": "json_body_sqli",
                    },
                    "ai_analysis": {
                        "business_impact": "Database disclosure.",
                        "exploitability": "Exploitability.easy",
                        "exploitability_reasoning": "Payload triggers SQL errors.",
                    },
                }
            ]
        }
    }

    text = _flowable_text(build_detailed_findings(scan_data, build_styles()))

    assert "Evidence Strength" in text
    assert "Confirmed Exploit" in text
    assert "Auth Context" in text
    assert "Authenticated" in text
    assert "Parameter Location" in text
    assert "Json Body" in text
    assert "Detection Method" in text
    assert "json_body_sqli" in text
    assert "Detector Verified" in text
    assert "Yes" in text


def test_pdf_code_block_wraps_long_encoded_get_request_inside_available_width() -> None:
    styles = build_styles()
    request = (
        "GET /dvwa/vulnerabilities/sqli/?id=1%27+AND+extractvalue%281%2Cconcat%280x7e%2C%28SELECT+"
        "%40%40version%29%29%29--&Submit=Submit HTTP/1.1"
    )
    block = full_code_block(request, styles)
    available_width = 170 * 2.83465

    block.wrap(available_width, 800)

    max_text_width = available_width - (block.pad_x * 2)
    assert len(block.lines) > 1
    assert all(block._string_width(line) <= max_text_width + 0.01 for line in block.lines)


def test_pdf_builds_with_full_long_response_snippet() -> None:
    long_response = "line-1\n" + ("x" * 1400) + "\nunique-response-tail"
    scan_data = {
        "success": True,
        "data": {
            "scan_id": "scan-1",
            "generated_at": "2026-06-08T09:10:17",
            "executive_summary": "Summary.",
            "statistics": {
                "total_urls_crawled": 1,
                "total_vulnerabilities": 1,
                "severity_breakdown": {
                    "critical": 0,
                    "high": 0,
                    "medium": 1,
                    "low": 0,
                    "info": 0,
                },
            },
            "risk_score": 55.0,
            "technology_stack": [],
            "vulnerabilities": [
                {
                    "vuln_type": "Reflected XSS",
                    "category": "OwaspCategory.a05",
                    "severity": "SeverityLevel.medium",
                    "cvss_score": 5.5,
                    "cvss_vector": "N/A",
                    "review_status": "ReviewStatus.confirmed",
                    "location": {
                        "url": "http://target.test/xss",
                        "parameter": "q",
                        "http_method": "GET",
                    },
                    "evidence": {
                        "payload": "<script>alert(1)</script>",
                        "request_snippet": "GET /xss?q=test HTTP/1.1",
                        "response_snippet": long_response,
                    },
                    "ai_analysis": {
                        "business_impact": "Browser execution.",
                        "exploitability": "Exploitability.easy",
                        "exploitability_reasoning": "The payload executes.",
                        "false_positive_probability": 0.1,
                        "ai_analysis_status": "AiAnalysisStatus.success",
                    },
                }
            ],
        },
    }

    pdf = build_scan_pdf(scan_data=scan_data)

    assert pdf.startswith(b"%PDF")
    assert len(pdf) > 1000


def test_pdf_escapes_dynamic_markup_in_ai_text() -> None:
    scan_data = {
        "success": True,
        "data": {
            "scan_id": "scan-markup",
            "generated_at": "2026-06-08T09:10:17",
            "executive_summary": "Summary with <raw> tag.",
            "statistics": {
                "total_urls_crawled": 1,
                "total_vulnerabilities": 1,
                "severity_breakdown": {
                    "critical": 0,
                    "high": 0,
                    "medium": 1,
                    "low": 0,
                    "info": 0,
                },
            },
            "risk_score": 45.0,
            "technology_stack": [
                {"name": "Apache <httpd", "version": "2.4 < 2.4.58", "category": "Web <Server", "cves": ["CVE-TEST<1>"]}
            ],
            "vulnerabilities": [
                {
                    "vuln_type": "Reflected <script> XSS",
                    "category": "OwaspCategory.a05",
                    "severity": "SeverityLevel.medium",
                    "cvss_score": 5.5,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                    "review_status": "ReviewStatus.confirmed",
                    "location": {
                        "url": "http://target.test/search?q=<script>",
                        "parameter": "q<script>",
                        "http_method": "GET",
                    },
                    "evidence": {
                        "payload": "<script>alert(1)</script>",
                        "request_snippet": "GET /search?q=<script> HTTP/1.1",
                        "response_snippet": "VERIFICATION EVIDENCE:\nPayload <script> executed.",
                    },
                    "ai_analysis": {
                        "business_impact": "Attacker can run <script>alert(1)",
                        "exploitability": "Exploitability.easy",
                        "exploitability_reasoning": "Uses <script> without closing markup.",
                        "false_positive_probability": 0.1,
                        "ai_analysis_status": "AiAnalysisStatus.success",
                        "remediation": "Encode output with <script> and <b unclosed tag examples.",
                    },
                }
            ],
        },
    }

    pdf = build_scan_pdf(scan_data=scan_data)

    assert pdf.startswith(b"%PDF")
    assert len(pdf) > 1000
