from app.utils.pdf_generator import (
    _clean_category,
    _clean_enum,
    _response_evidence_label_and_text,
    _split_response_evidence,
    build_scan_pdf,
)


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
                    "detected_at": "2026-06-08T09:10:17",
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
                    "detected_at": "2026-06-08T09:10:17",
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
