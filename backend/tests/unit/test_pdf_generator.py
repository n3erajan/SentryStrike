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
    build_technology_detected,
    build_tested_surface,
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


def test_pdf_remediation_roadmap_excludes_suppressed_false_positive() -> None:
    scan_data = {
        "data": {
            "vulnerabilities": [
                {
                    "vuln_type": "Suppressed XSS",
                    "severity": "High",
                    "is_false_positive": True,
                    "ai_analysis": {"remediation": "Do not show this action."},
                },
                {
                    "vuln_type": "Active SQL Injection",
                    "severity": "Critical",
                    "is_false_positive": False,
                    "ai_analysis": {"remediation": "Use prepared statements."},
                },
            ]
        }
    }

    text = _flowable_text(build_remediation_roadmap(scan_data, build_styles()))

    assert "Active SQL Injection" in text
    assert "Suppressed XSS" not in text


def _roadmap_phase_of(elems, vuln_type: str) -> str | None:
    """Return the roadmap phase heading under which *vuln_type* is listed.

    Walks the flowables in document order, tracking the most recent sub-header
    (phase label) and returning it when a table row naming *vuln_type* appears.
    """
    current_phase = None
    for elem in elems:
        text = getattr(elem, "text", None)
        if text and any(
            marker in text
            for marker in ("Immediate", "Urgent", "Planned", "Backlog")
        ):
            current_phase = text
        if hasattr(elem, "_cellvalues"):
            for row in elem._cellvalues:
                cell = row[0]
                cell_text = cell.getPlainText() if hasattr(cell, "getPlainText") else str(cell)
                if vuln_type in cell_text:
                    return current_phase
    return None


def test_roadmap_high_severity_sqli_is_urgent_not_backlog() -> None:
    # Regression: a High-severity SQL injection with Medium exploitability must
    # NOT fall through to the low-priority backlog phase. Severity drives the
    # phase; exploitability only orders within it.
    scan_data = {
        "data": {
            "vulnerabilities": [
                {
                    "vuln_type": "SQL Injection (Error-Based)",
                    "severity": "SeverityLevel.high",
                    "ai_analysis": {
                        "exploitability": "Exploitability.medium",
                        "remediation": "Use prepared statements.",
                    },
                },
                {
                    "vuln_type": "Missing Security Header",
                    "severity": "SeverityLevel.low",
                    "ai_analysis": {
                        "exploitability": "Exploitability.medium",
                        "remediation": "Add headers.",
                    },
                },
            ]
        }
    }

    elems = build_remediation_roadmap(scan_data, build_styles())

    assert _roadmap_phase_of(elems, "SQL Injection (Error-Based)") == "Urgent (High)"
    assert "Backlog" in (_roadmap_phase_of(elems, "Missing Security Header") or "")


def test_roadmap_orders_by_exploitability_within_phase() -> None:
    # Within one severity phase, easier-to-exploit items are listed first.
    scan_data = {
        "data": {
            "vulnerabilities": [
                {
                    "vuln_type": "Hard High Finding",
                    "severity": "SeverityLevel.high",
                    "ai_analysis": {"exploitability": "Exploitability.hard", "remediation": "x"},
                },
                {
                    "vuln_type": "Easy High Finding",
                    "severity": "SeverityLevel.high",
                    "ai_analysis": {"exploitability": "Exploitability.easy", "remediation": "y"},
                },
            ]
        }
    }

    elems = build_remediation_roadmap(scan_data, build_styles())
    table = next(elem for elem in elems if hasattr(elem, "_cellvalues"))
    ordered = [row[0].getPlainText() for row in table._cellvalues[1:]]
    assert ordered == ["Easy High Finding", "Hard High Finding"]


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


def test_pdf_executive_summary_includes_submitter_and_authorization_metadata() -> None:
    from app.utils.pdf_generator import build_executive_summary

    scan_data = {
        "data": {
            "scan_id": "scan-1",
            "generated_at": "2026-06-08T09:10:17",
            "submitted_by_full_name": "Niuradaj Adhadh",
            "submitted_by_email": "user@example.test",
            "executive_summary": "Summary.",
            "risk_score": 45.0,
            "authorization": {
                "confirmed": True,
                "confirmed_at": "2026-06-08T09:00:00",
            },
            "vulnerabilities": [{"location": {"url": "https://target.example/path"}}],
        }
    }

    text = _flowable_text(build_executive_summary(scan_data, build_styles()))

    assert "Submitted By" in text
    assert "Niuradaj Adhadh user@example.test" in text
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


def test_pdf_detailed_findings_show_false_positive_reviewer() -> None:
    scan_data = {
        "data": {
            "vulnerabilities": [
                {
                    "vuln_type": "Reflected XSS",
                    "category": "OwaspCategory.a05",
                    "severity": "SeverityLevel.high",
                    "cvss_score": 8.0,
                    "review_status": "suppressed",
                    "is_false_positive": True,
                    "false_positive_reason": "Generic SPA fallback response.",
                    "false_positive_marked_by_email": "analyst@example.test",
                    "false_positive_marked_at": "2026-07-22T10:00:00+00:00",
                    "location": {"url": "https://target.example/search"},
                    "evidence": {},
                    "ai_analysis": {},
                }
            ]
        }
    }

    text = _flowable_text(build_detailed_findings(scan_data, build_styles()))

    assert "Marked By" in text
    assert "analyst@example.test" in text
    assert "Review Reason" in text
    assert "Generic SPA fallback response." in text


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
            "submitted_by_full_name": "Niuradaj Adhadh",
            "submitted_by_email": "user@example.test",
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
            "submitted_by_full_name": "Niuradaj Adhadh",
            "submitted_by_email": "user@example.test",
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


def test_pdf_tested_surface_reports_measured_coverage_and_gaps() -> None:
    """The coverage section states what was tested from the request ledger, names
    the reached-but-unprobed gap, and reproduces the scanner's own warnings."""
    scan_data = {
        "data": {
            "tested_surface": {
                "paths_tested": 12,
                "paths_probed_by_detector": 9,
                "parameters_tested": 27,
                "requests_sent": 1840,
                "requests_without_response": 4,
                "requests_denied_by_budget": 61,
                "detectors_exercised": ["injection_sql_command", "xss"],
                "tested_paths": [{"path": "http://t/a", "methods": ["GET"]}],
                "tested_paths_truncated": False,
                "tested_paths_omitted": 0,
                "ledger_entries_omitted": 0,
                "browser_probes_itemised": False,
            },
            "coverage_warnings": [
                "No second-user account configured; horizontal IDOR comparison was not tested.",
            ],
        }
    }

    text = _flowable_text(build_tested_surface(scan_data, build_styles()))

    assert "Tested Surface" in text
    assert "Existing Paths Reached" in text and "12" in text
    assert "Paths Probed by a Detector" in text and "9" in text
    assert "Parameters Tested" in text and "27" in text
    assert "1840" in text
    assert "Requests Denied by Request Budget" in text and "61" in text
    # The reached-but-never-probed gap is spelled out, not left for the reader.
    assert "3 of the 12 existing paths reached" in text
    assert "treat" in text and "untested" in text
    # Browser probes are disclosed as unlisted rather than silently missing.
    assert "Browser-driven probes" in text
    # The scanner's own coverage warning is reproduced verbatim.
    assert "horizontal IDOR comparison was not tested" in text
    assert "Coverage Gaps" in text


def test_pdf_tested_surface_distinguishes_unrecorded_from_nothing_tested() -> None:
    """A scan with no ledger (predating the feature) must not print zeros that
    would read as 'nothing was tested'."""
    text = _flowable_text(build_tested_surface({"data": {}}, build_styles()))

    assert "No tested-surface inventory was recorded" in text
    assert "does not mean nothing was tested" in text
    # With no recorded gaps, the section still refuses to imply full coverage.
    assert "not that the whole" in text


def test_pdf_tested_surface_reports_truncated_inventory() -> None:
    scan_data = {
        "data": {
            "tested_surface": {
                "paths_tested": 640,
                "paths_probed_by_detector": 640,
                "parameters_tested": 900,
                "requests_sent": 9000,
                "tested_paths": [{"path": f"http://t/p{i}"} for i in range(500)],
                "tested_paths_truncated": True,
                "tested_paths_omitted": 140,
                "ledger_entries_omitted": 12,
                "browser_probes_itemised": False,
            }
        }
    }

    text = _flowable_text(build_tested_surface(scan_data, build_styles()))

    assert "140 further tested paths exceeded the storage" in text
    assert "12 distinct parameter probes exceeded the" in text


def test_pdf_tested_surface_separates_404_probes_from_tested_surface() -> None:
    """Path-guessing checks probe thousands of URLs that do not exist. The report
    must count those apart from tested surface, or a DVWA scan claims 2,873
    tested paths against an app with a few dozen."""
    scan_data = {
        "data": {
            "tested_surface": {
                "paths_tested": 34,
                "paths_probed_by_detector": 34,
                "paths_absent": 2839,
                "paths_existence_unconfirmed": 2,
                "requests_to_absent_paths": 4102,
                "parameters_tested": 166,
                "requests_sent": 6974,
                "requests_without_response": 2,
                "requests_denied_by_budget": 590,
                "detectors_exercised": ["sensitive_paths", "xss"],
                "tested_paths": [{"path": "http://t/dvwa/"}],
                "browser_probes_itemised": False,
            }
        }
    }

    text = _flowable_text(build_tested_surface(scan_data, build_styles()))

    assert "Existing Paths Reached" in text and "34" in text
    assert "Candidate Paths Found Absent" in text and "2839" in text
    assert "Requests Proving a Path Absent (404)" in text and "4102" in text
    # The reader is told plainly why those are not coverage.
    assert "excluded from the tested surface" in text
    assert "inflate coverage with paths that do not exist" in text
    # Unanswered probes are their own bucket, not silently folded into either.
    assert "Paths With Existence Unconfirmed" in text
    assert "not established in either direction" in text
    # The honest request total is still shown.
    assert "6974" in text


# --------------------------------------------------------------------------- #
# Technology section: an empty CVE list must not read as "clean"
# --------------------------------------------------------------------------- #

def _tech_section(technologies: list[dict]) -> str:
    styles = build_styles()
    return _flowable_text(
        build_technology_detected({"data": {"technology_stack": technologies}}, styles)
    )


def test_pdf_distinguishes_an_assessed_clean_component_from_an_unassessed_one() -> None:
    """"None found" for a component nobody looked up is misinformation.

    PHP and MySQL reach the report version-less, inferred from WordPress's
    ``implies`` list. Neither can be CVE-matched, and the old table printed
    "None found" against both.
    """
    text = _tech_section([
        {
            "name": "WordPress", "version": "7.1", "category": "cms", "cves": [],
            "cve_assessment": "assessed", "cve_source": "nvd-cpe",
        },
        {
            "name": "PHP", "version": None, "category": "language", "cves": [],
            "cve_assessment": "not_assessed",
            "cve_assessment_reason": "no version detected for PHP",
        },
    ])

    assert "None found" in text
    assert "Not assessed" in text
    assert "no version detected for PHP" in text


def test_pdf_reports_a_failed_lookup_as_failed() -> None:
    text = _tech_section([{
        "name": "Nginx", "version": "1.24.0", "category": "server", "cves": [],
        "cve_assessment": "failed",
        "cve_assessment_reason": "NVD returned HTTP 429 for f5:nginx",
    }])

    assert "Lookup failed" in text
    assert "HTTP 429" in text
    assert "None found" not in text


def test_pdf_names_the_source_behind_each_cve_list() -> None:
    text = _tech_section([{
        "name": "Express", "version": "4.18.2", "category": "framework",
        "cves": ["CVE-2024-43796"], "cve_assessment": "assessed", "cve_source": "osv",
    }])

    assert "CVE-2024-43796" in text
    assert "OSV.dev" in text


def test_pdf_flags_known_exploited_cves_in_the_technology_table() -> None:
    text = _tech_section([{
        "name": "Nginx", "version": "1.24.0", "category": "server",
        "cves": ["CVE-2021-44228", "CVE-2024-0001"],
        "cve_assessment": "assessed", "cve_source": "nvd-cpe",
        "cve_kev": ["CVE-2021-44228"],
    }])

    assert "CVE-2021-44228 (exploited)" in text
    assert "CVE-2024-0001 (exploited)" not in text


def test_pdf_technology_section_tolerates_legacy_records_without_assessment_fields() -> None:
    """Scans stored before this field existed must still render."""
    text = _tech_section([
        {"name": "jQuery", "version": "3.6.0", "category": "library", "cves": []},
    ])

    assert "jQuery" in text
