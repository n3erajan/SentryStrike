import logging
import math
from time import perf_counter

from app.config import get_settings
from app.core.evidence_grader import EvidenceGrade
from shared.models.scan import ScanPhase
from shared.models.vulnerability import (
    AiAnalysisStatus,
    AiVerdict,
    EvidenceStrength,
    ReviewStatus,
    Vulnerability,
    normalize_exploitability,
)

logger = logging.getLogger("app.core.scanner")


def _normalize_llm_string(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        return "\n".join(str(item) for item in value)
    return str(value)


REMEDIATION_FALLBACKS: dict[str, str] = {
    "Cross-Site Request Forgery (CSRF)": (
        "Add CSRF tokens (synchronizer token pattern) to all state-changing forms; "
        "validate Origin/Referer headers."
    ),
    "Insecure Direct Object Reference (IDOR)": (
        "Implement object-level authorization and verify the authenticated user has "
        "permission to access the referenced resource."
    ),
    "Path Traversal / Arbitrary File Read": (
        "Canonicalize requested paths, reject traversal sequences, enforce an allowlist of readable "
        "files/directories, and ensure file access stays inside the intended document root."
    ),
    "OS Command Injection": (
        "Never pass user input to shell commands. Use parameterized APIs "
        "(e.g., subprocess with shell=False) and strict allowlists."
    ),
    "SQL Injection": (
        "Use parameterized queries / prepared statements. Never concatenate user input into SQL."
    ),
    "Reflected XSS": (
        "Apply context-aware output encoding. Use Content-Security-Policy to restrict inline scripts."
    ),
    "Stored XSS": (
        "Sanitize input on storage and apply context-aware output encoding on display. Use CSP."
    ),
    "Local File Inclusion (LFI)": (
        "Validate and whitelist allowed file paths. Never use user input directly in file operations."
    ),
    "Insecure Transport": (
        "Enforce HTTPS via HSTS with a long max-age and redirect all HTTP traffic to HTTPS."
    ),
    "Missing Security Header": (
        "Add the missing security header with appropriate directives per OWASP guidance."
    ),
    "Server-Side Request Forgery (SSRF)": (
        "Validate and whitelist allowed destination URLs/IPs and block internal/private ranges."
    ),
    "Unrestricted File Upload": (
        "Validate extension, MIME type, and content. Store uploads outside webroot and randomize names."
    ),
    "Weak File Upload Validation": (
        "Validate uploads server-side using extension allowlists, MIME checks, and file magic bytes; "
        "store files outside the webroot with randomized names and disable script execution."
    ),
    "Double Extension Bypass": (
        "Normalize filenames before validation, reject dangerous compound extensions, and enforce "
        "server-side allowlists independent of client-supplied MIME types."
    ),
    "Missing File Type Validation": (
        "Enforce server-side file type validation using allowlisted extensions and magic-byte inspection; "
        "reject unexpected content types and scan uploaded files before storage."
    ),
    "Insecure Session Cookie Attributes": (
        "Set HttpOnly, Secure, and SameSite=Strict (or Lax) on session cookies."
    ),
    "Vulnerable Component": (
        "Upgrade the affected component to a patched version, remove unsupported versions, and verify "
        "the component is no longer matched to the reported CVE."
    ),
    "Verbose Error Handling": (
        "Disable verbose errors in production, return generic error pages, and send stack traces or "
        "debug details only to protected server-side logs."
    ),
    "Credential / Config Disclosure in Response Body": (
        "Remove hardcoded credentials and configuration secrets from application responses. "
        "Use environment variables or a secrets manager, and ensure error handlers never "
        "dump configuration values in production."
    ),
    "Debug / Metrics Endpoint Exposed": (
        "Restrict access to debug, metrics, and actuator endpoints by IP allowlist, "
        "reverse-proxy rules, or authentication. Disable in production or serve on a "
        "separate administrative port."
    ),
}


DESCRIPTION_FALLBACKS: dict[str, str] = {
    "SQL Injection": (
        "The application builds database queries by pasting user input directly into them. "
        "An attacker can send crafted input that changes what the query does, letting them "
        "read, modify, or delete data in the database they were never meant to touch."
    ),
    "NoSQL Injection": (
        "The application passes user input straight into a NoSQL database query (e.g. MongoDB). "
        "An attacker can send specially shaped input that alters the query's logic — for "
        "example, to bypass a login check or return records that should be hidden."
    ),
    "OS Command Injection": (
        "User input reaches a system shell command. An attacker can smuggle in extra commands "
        "that run on the server itself, potentially taking full control of the machine."
    ),
    "Server-Side Request Forgery (SSRF)": (
        "The server fetches a URL supplied by the user. An attacker can point it at internal "
        "systems the outside world can't normally reach — cloud metadata services, internal "
        "admin panels, or private APIs — and read the responses."
    ),
    "Path Traversal / Arbitrary File Read": (
        "A file name or path from the user isn't restricted to the intended folder. By adding "
        "sequences like ../ an attacker can step outside that folder and read arbitrary files "
        "on the server, such as configuration files or credentials."
    ),
    "Local File Inclusion (LFI)": (
        "The application loads a file whose path is chosen by user input. An attacker can point "
        "it at unintended files on the server to read their contents or, in some setups, run "
        "their own code."
    ),
    "XML External Entity (XXE) Injection": (
        "The application parses XML in a way that lets the document reference external files or "
        "URLs. An attacker can abuse this to read files off the server or make the server issue "
        "requests to other systems."
    ),
    "Stored XSS": (
        "An attacker's script gets saved by the application (e.g. in a comment or profile) and "
        "then runs in the browser of everyone who views that content. It can steal sessions, "
        "impersonate users, or deface the page — victims need only open the page."
    ),
    "DOM-Based XSS": (
        "Client-side JavaScript takes attacker-controllable input and writes it into the page "
        "unsafely, so a malicious script runs in the victim's browser. It can steal session "
        "tokens or perform actions as the victim."
    ),
    "Reflected XSS": (
        "Input from a request is echoed straight back into the page, so a crafted link can make "
        "the victim's browser run an attacker's script — used to steal sessions or perform "
        "actions as the victim."
    ),
    "Broken Object-Level Authorization": (
        "The application trusts an ID in the request without checking the requester is allowed "
        "to access that specific record. By changing the ID, an attacker can read or modify "
        "other users' data. (Also known as BOLA or IDOR.)"
    ),
    "Insecure Direct Object Reference (IDOR)": (
        "Records are addressed by a predictable ID (like a number in the URL), and the app "
        "doesn't verify the record belongs to the requester. Changing the ID exposes other "
        "users' data. (The access-control name for this is BOLA.)"
    ),
    "Horizontal Authorization Bypass": (
        "A user can reach another user's data or actions at the same permission level — the app "
        "confirms who you are but not that the specific item is yours."
    ),
    "Missing Authorization on State-Changing Request": (
        "An action that changes data (create, update, delete) doesn't check whether the caller "
        "is allowed to perform it, so any user — sometimes any anonymous visitor — can trigger it."
    ),
    "Mass Assignment / Privilege Field Injection": (
        "The application blindly maps submitted fields onto internal objects. An attacker can "
        "add fields that shouldn't be user-editable — such as \"role\": \"admin\" — to escalate "
        "their own privileges."
    ),
    "Cross-Site Request Forgery (CSRF)": (
        "A state-changing action can be triggered using only the victim's logged-in session, "
        "with no unguessable token to prove intent. A malicious page the victim visits can "
        "silently make their browser perform the action on the real site."
    ),
    "Open Redirect": (
        "The application redirects users to a URL taken from the request without restriction. "
        "Attackers use this to send victims to phishing sites via a link that appears to point "
        "at the trusted domain."
    ),
    "Verbose Error Handling": (
        "When something goes wrong the server returns detailed internal errors — stack traces, "
        "file paths, SQL statements, library versions. On its own this leaks nothing critical, "
        "but it hands attackers a map of the system that makes other attacks easier."
    ),
    "Credential / Config Disclosure in Response Body": (
        "A server response contains secrets it shouldn't — passwords, API keys, or configuration "
        "values. Anyone who sees the response gains credentials they can reuse to access the "
        "system or connected services."
    ),
    "Secret-Like Value Exposure": (
        "A response exposes a value that looks like a secret (a token, key, or credential). If it "
        "is a live secret, an attacker can reuse it to access protected functionality."
    ),
    "Exposed API Documentation": (
        "Internal API documentation is reachable without authentication. It reveals the full list "
        "of endpoints and parameters, giving an attacker a detailed blueprint of the attack surface."
    ),
    "Debug / Metrics Endpoint Exposed": (
        "An administrative debug or metrics endpoint is publicly reachable. It can leak internal "
        "state, configuration, or operational data useful for planning further attacks."
    ),
    "JWT alg=none Forgery Accepted": (
        "The server accepts JSON Web Tokens signed with \"none\" — i.e. not signed at all. An "
        "attacker can forge a token claiming to be any user, including an admin, and be trusted."
    ),
    "JWT Missing Expiration Claim": (
        "Authentication tokens never expire. If one is ever leaked or stolen, it stays valid "
        "forever because there is no built-in cutoff."
    ),
    "Missing File Type Validation": (
        "Uploaded files aren't checked for type, so an attacker may upload dangerous content "
        "(such as a script) that the server later serves or executes."
    ),
    "Password Reset Relies on Security Question (Weak Recovery)": (
        "Account recovery depends on a security-question answer, which is often guessable or "
        "publicly known. An attacker who answers it can take over the account without the password."
    ),
    "API Login Lacks Safe-Probe Rate-Limit Signal": (
        "The login endpoint shows no sign of rate limiting, so an attacker can try large numbers "
        "of username/password guesses (credential stuffing or brute force) without being slowed."
    ),
    "No TLS Configuration": (
        "The service is served over plain HTTP with no encryption. Anyone on the network path can "
        "read or tamper with the traffic, including passwords and session cookies."
    ),
    "Missing Security Header": (
        "A recommended HTTP security header is absent. The browser therefore misses a layer of "
        "protection (against clickjacking, content sniffing, or script injection, depending on "
        "the header), making related attacks easier."
    ),
    "Vulnerable Component": (
        "The application uses a third-party component with a known, publicly documented security "
        "flaw. Attackers can exploit that flaw using techniques that are already published."
    ),
}

class AiAnalysisMixin:
    async def _analyze_all_findings(self, vulnerabilities: list[Vulnerability], scan: 'Scan') -> list[Vulnerability]:
            """Analyze findings with AI using optimised local model constraints.

            When ``ai_analysis_enabled`` is False, the LLM is skipped entirely —
            each finding is populated from deterministic fallbacks (evidence
            grade, calibrated exploitability, framework-aware remediation).
            The resulting vulnerabilities have ``ai_analysis_status=skipped``.
            """
            if not vulnerabilities:
                return vulnerabilities

            settings = get_settings()
            if not settings.ai_analysis_enabled:
                logger.info(
                    "AI analysis disabled (AI_ANALYSIS_ENABLED=false); "
                    "populating %d finding(s) with deterministic fallbacks",
                    len(vulnerabilities),
                )
                for vuln in vulnerabilities:
                    grade = self.evidence_grader.grade(vuln)
                    fallback = self._get_fallback_for(
                        vuln.vuln_type, scan.technology_stack, proof_type=grade.proof_type
                    )
                    vuln.ai_analysis.exploitability = normalize_exploitability(fallback["exploitability"])
                    vuln.ai_analysis.business_impact = fallback["business_impact"]
                    vuln.ai_analysis.false_positive_probability = fallback["false_positive_probability"]
                    vuln.ai_analysis.verdict = (
                        AiVerdict.confirmed
                        if grade.proof_type in {
                            "active_output", "error_echo", "structural",
                            "timing_strong", "auth_confirmed",
                        }
                        else AiVerdict.uncertain
                    )
                    vuln.ai_analysis.evidence_grade = grade.grade
                    vuln.ai_analysis.evidence_grade_reason = grade.reason
                    vuln.ai_analysis.remediation = fallback["remediation"]
                    vuln.ai_analysis.exploitability = self._calibrate_exploitability(vuln)
                    vuln.ai_analysis.ai_analysis_status = AiAnalysisStatus.skipped
                return vulnerabilities

            BATCH_SIZE = settings.ai_batch_size
            analyzed: list[Vulnerability] = []

            tech_stack_str = ", ".join(t.name for t in scan.technology_stack) if scan.technology_stack else "Unknown"

            total_findings = len(vulnerabilities)
            batch_seconds: list[float] = []
            for batch_start in range(0, len(vulnerabilities), BATCH_SIZE):
                batch = vulnerabilities[batch_start : batch_start + BATCH_SIZE]
                logger.info(
                    "Analyzing batch %d-%d of %d vulnerabilities with local LLM",
                    batch_start + 1,
                    batch_start + len(batch),
                    len(vulnerabilities),
                )

                # Pre-grade findings BEFORE the AI call — the proof characterization
                # (proof_type, ceiling, brief) is needed to build the discriminative
                # evidence brief in the prompt.
                batch_grades = [self.evidence_grader.grade(v) for v in batch]

                results = []
                batch_started = perf_counter()
                try:
                    if BATCH_SIZE == 1:
                        result = await self._analyze_single(batch[0], tech_stack_str, batch_grades[0])
                        results = [result]
                    else:
                        results = await self._analyze_batch(batch, tech_stack_str, batch_grades)
                except Exception as e:
                    logger.warning("Analysis call failed, falling back to individual processing: %s: %s", type(e).__name__, e)
                    for i, vuln in enumerate(batch):
                        try:
                            res = await self._analyze_single(vuln, tech_stack_str, batch_grades[i])
                            results.append(res)
                        except Exception as single_e:
                            logger.warning("Single analysis failed for %s: %s", vuln.id, single_e)
                            results.append({"ai_analysis_status": "failed"})
                batch_elapsed = max(0.1, perf_counter() - batch_started)
                batch_seconds.append(batch_elapsed)

                # Calibrate AI ETA from measured batch pace (rolling average).
                avg_batch_s = sum(batch_seconds) / len(batch_seconds)
                remaining_findings = max(0, total_findings - (batch_start + len(batch)))
                remaining_batches = math.ceil(remaining_findings / BATCH_SIZE) if remaining_findings else 0
                self._eta_state.ai_remaining_s = remaining_batches * avg_batch_s
                self._eta_state.ai_total_s = sum(batch_seconds) + self._eta_state.ai_remaining_s
                self._eta_state.ai_fraction = (batch_start + len(batch)) / total_findings

                # Apply AI results back to each vulnerability
                for idx, (vuln, result) in enumerate(zip(batch, results), start=batch_start + 1):
                    grade = batch_grades[idx - batch_start - 1]
                    logger.info(
                        "Evidence grade: vuln_type=%r proof_type=%s grade=%s fp_ceiling=%.2f url=%s",
                        vuln.vuln_type, grade.proof_type, grade.grade, grade.fp_ceiling, vuln.location.url,
                    )

                    if result.get("ai_analysis_status") == "failed" or "results" in result:
                        # Guard against malformed nested batch JSON structures
                        if "results" in result and isinstance(result["results"], list) and len(result["results"]) > 0:
                            result = result["results"][0]
                        else:
                            vuln.ai_analysis.ai_analysis_status = AiAnalysisStatus.failed
                            vuln.ai_analysis.exploitability = self._calibrate_exploitability(vuln)
                            # When AI fails: preserve deterministic proof. Interpretive
                            # evidence records an uncertain advisory estimate, but review
                            # status still comes from evidence strength.
                            if grade.proof_type in (
                                "auth_differential",
                                "pattern_match",
                                "heuristic",
                                "timing_weak",
                                "ssrf_differential",
                            ):
                                vuln.ai_analysis.false_positive_probability = 0.49
                                vuln.ai_analysis.verdict = AiVerdict.uncertain
                            else:
                                vuln.ai_analysis.false_positive_probability = grade.fp_ceiling
                                vuln.ai_analysis.verdict = AiVerdict.confirmed
                            vuln.ai_analysis.evidence_grade = grade.grade
                            vuln.ai_analysis.evidence_grade_reason = grade.reason
                            # AI produced nothing usable — fall back to the curated
                            # plain-language description so the reader still gets one.
                            vuln.ai_analysis.description = self._description_for(vuln.vuln_type)
                            analyzed.append(vuln)
                            continue

                    fallback = self._get_fallback_for(vuln.vuln_type, scan.technology_stack, proof_type=grade.proof_type)
                    # AI FP output is clamped to the proof-type ceiling.
                    # For active_output/error_echo/structural/timing_strong: low ceiling
                    # (the proof is undeniable — AI cannot dismiss it).
                    # For auth_differential/pattern_match: ceiling is 1.0 (no cap —
                    # AI judges freely from the discriminative evidence brief).
                    raw_ai_fp = float(
                        result.get(
                            "false_positive_probability",
                            fallback["false_positive_probability"],
                        )
                    )
                    fp_prob, ai_verdict = self._calibrate_ai_false_positive(
                        vuln,
                        grade,
                        raw_ai_fp,
                        result.get("verdict"),
                        result.get("false_positive_reasoning"),
                    )

                    vuln.ai_analysis.exploitability = normalize_exploitability(
                        result.get("exploitability", fallback["exploitability"])
                    )
                    vuln.ai_analysis.description = _normalize_llm_string(result.get("description")) or fallback["description"]
                    vuln.ai_analysis.business_impact = _normalize_llm_string(result.get("business_impact", fallback["business_impact"]))
                    vuln.ai_analysis.verdict = ai_verdict
                    vuln.ai_analysis.false_positive_probability = fp_prob
                    vuln.ai_analysis.false_positive_reasoning = _normalize_llm_string(result.get("false_positive_reasoning"))
                    vuln.ai_analysis.exploitability_reasoning = _normalize_llm_string(result.get("exploitability_reasoning"))
                    vuln.ai_analysis.evidence_grade = grade.grade
                    vuln.ai_analysis.evidence_grade_reason = grade.reason
                    remediation = _normalize_llm_string(result.get("remediation", fallback["remediation"]))
                    if self._remediation_is_incompatible(vuln.vuln_type, remediation):
                        logger.info(
                            "Replacing incompatible AI remediation with fallback: vuln_type=%r remediation=%r",
                            vuln.vuln_type,
                            remediation,
                        )
                        remediation = fallback["remediation"]
                    vuln.ai_analysis.remediation = remediation
                    vuln.ai_analysis.exploitability = self._calibrate_exploitability(vuln)
                    vuln.ai_analysis.ai_analysis_status = AiAnalysisStatus.success

                    analyzed.append(vuln)

                # Tick progress after each batch
                batch_end = min(batch_start + BATCH_SIZE, total_findings)
                await self._set_phase_progress(
                    scan,
                    ScanPhase.ai_analysis,
                    batch_end / total_findings,
                    f"Analyzing findings: {batch_end}/{total_findings} complete",
                )

            return analyzed

    async def _analyze_batch(self, batch: list[Vulnerability], tech_stack_str: str, grades: list[EvidenceGrade]) -> list[dict]:
        vuln_descriptions = []
        for i, vuln in enumerate(batch):
            req = vuln.evidence.request_snippet or ""
            resp = vuln.evidence.response_snippet or ""
            payload = vuln.evidence.payload or ""
            auth_ctx = "requires_auth" if "cookie" in req.lower() else "unknown_auth"
            auth_ctx = vuln.auth_context.value if getattr(vuln, "auth_context", None) else auth_ctx

            # Discriminative evidence brief — replaces the old descriptive block
            # that exposed detector_verified/confidence_score (which caused the
            # AI to defer to the detector circularly). The brief gives the AI
            # the proof TYPE, markers, and weaknesses so it can judge the finding
            # on the evidence itself.
            evidence_brief = self.evidence_grader.build_evidence_brief(vuln, grades[i])
            evidence_block = (
                "evidence_block=\n"
                f"- url={vuln.location.url}\n"
                f"- http_method={vuln.location.http_method}\n"
                f"- parameter={vuln.location.parameter or 'none'}\n"
                f"- auth_context={auth_ctx}\n"
                f"- detection_method={vuln.evidence.detection_method or 'unknown'}\n"
                f"- verification_completed={vuln.evidence.verified}\n"
                f"- deterministic_evidence_strength={vuln.evidence_strength.value}\n"
                f"- payload={payload or 'n/a'}\n"
                f"- request_snippet={req[:1600] if req else 'n/a'}\n"
                f"- response_snippet={resp[:1600] if resp else 'n/a'}\n"
                f"- {evidence_brief}\n"
            )

            vuln_descriptions.append(
                f"[{i}] type={vuln.vuln_type}; category={vuln.category.value}; "
                f"severity={vuln.severity.value}; auth_context={auth_ctx}; "
                + evidence_block
            )

        prompt = self._build_prompt(tech_stack_str, vuln_descriptions, is_batch=True)
        return await self.ai_client.generate_json_list(prompt, expected_count=len(batch))


    async def _analyze_single(self, vuln: Vulnerability, tech_stack_str: str, grade: EvidenceGrade) -> dict:
        req = vuln.evidence.request_snippet or ""
        resp = vuln.evidence.response_snippet or ""
        payload = vuln.evidence.payload or ""
        auth_ctx = "requires_auth" if "cookie" in req.lower() else "unknown_auth"
        auth_ctx = vuln.auth_context.value if getattr(vuln, "auth_context", None) else auth_ctx

        evidence_brief = self.evidence_grader.build_evidence_brief(vuln, grade)
        evidence_block = (
            "evidence_block=\n"
            f"- url={vuln.location.url}\n"
            f"- http_method={vuln.location.http_method}\n"
            f"- parameter={vuln.location.parameter or 'none'}\n"
            f"- auth_context={auth_ctx}\n"
            f"- detection_method={vuln.evidence.detection_method or 'unknown'}\n"
            f"- verification_completed={vuln.evidence.verified}\n"
            f"- deterministic_evidence_strength={vuln.evidence_strength.value}\n"
            f"- payload={payload or 'n/a'}\n"
            f"- request_snippet={req[:1600] if req else 'n/a'}\n"
            f"- response_snippet={resp[:1600] if resp else 'n/a'}\n"
            f"- {evidence_brief}\n"
        )

        vuln_desc = (
            f"type={vuln.vuln_type}; category={vuln.category.value}; "
            f"severity={vuln.severity.value}; auth_context={auth_ctx}; "
            + evidence_block
        )
        prompt = self._build_prompt(tech_stack_str, [vuln_desc], is_batch=False)
        return await self.ai_client.generate_json(prompt)


    def _build_prompt(self, tech_stack_str: str, vuln_descriptions: list[str], is_batch: bool) -> str:
        """Constructs an evaluation prompt optimised for Qwen3 8B / local 8B models."""

        # Role framing with explicit task decomposition. Smaller local models
        # (e.g. Qwen3 8B) produce more reliable output when asked to "think
        # step by step" with named stages.
        role_and_task = (
            "You are a senior penetration tester writing a verified security report. "
            "For each finding, perform these steps IN ORDER before writing JSON:\n"
            "  Step 1: Read the evidence_block carefully. Identify the EXACT proof markers present.\n"
            "  Step 2: Decide whether the evidence supports the vulnerability definition. "
            "Do not confuse incomplete impact, missing exploit chaining, or remediation uncertainty "
            "with a false positive.\n"
            "  Step 3: For pattern-match findings (e.g., Verbose Error Handling, path disclosure): "
            "determine whether the matched string is causally connected to the payload or is a "
            "genuine error condition - or if it could merely be from normal page content, reflected "
            "payload text, or navigation HTML. Do NOT accept the detector's confidence score at "
            "face value; independently reason about the plausibility of the match.\n"
            "  Step 4: Write remediation that is specific to the vuln_type AND the tech stack below.\n"
            "  Step 5: Describe business_impact in terms of what data/capability is concretely at risk.\n"
            "  Step 6: Write a plain-language description of what this vulnerability class IS, so a "
            "non-technical reader understands it without knowing the jargon.\n"
            "Output ONLY the JSON. No preamble, no explanation outside the JSON.\n\n"
        )

        # Provide concrete examples of good vs bad output — smaller models
        # learn format from examples far better than from abstract instructions.
        output_examples = (
            "OUTPUT QUALITY RULES WITH EXAMPLES:\n"

            "description - Explain what this class of vulnerability IS in plain language for a "
            "non-technical reader. Define any acronym. Do NOT reference this specific finding's "
            "URL/parameter or the fix (that belongs in business_impact/remediation):\n"
            "  BAD:  'IDOR on the /api/user endpoint via the id parameter.'\n"
            "  GOOD (IDOR): 'Insecure Direct Object Reference (IDOR) means the application trusts an "
            "identifier supplied by the user - such as an account or order number in the web address - "
            "without checking they are allowed to see it, so changing that number can reveal someone "
            "else's data.'\n"
            "  GOOD (CSRF): 'Cross-Site Request Forgery (CSRF) tricks a logged-in user's browser into "
            "silently submitting an action they did not intend, because the site cannot tell a genuine "
            "click apart from one triggered by a malicious page.'\n\n"

            "business_impact - Reference the parameter name, URL path, and attacker capability:\n"
            "  BAD:  'An attacker can access sensitive information and compromise the server.'\n"
            "  GOOD (OS Command Injection on exec/ via ip param): "
            "'An attacker can execute arbitrary OS commands as www-data on the web server, "
            "enabling exfiltration of /etc/passwd, lateral movement to internal services, "
            "or installation of a reverse shell - full server compromise without credentials.'\n"
            "  GOOD (Stored XSS on guestbook via comment param): "
            "'Any authenticated user can inject a persistent script that steals session cookies "
            "of every visitor, enabling account takeover across all user roles including admins.'\n\n"
            
            "remediation - Name the exact function/config for the detected tech stack:\n"
            "  BAD:  'Implement input validation and use parameterized queries.'\n"
            "  GOOD (SQLi on PHP/MySQL): "
            "'Replace concatenated SQL with PDO prepared statements: "
            "$stmt = $pdo->prepare(\"SELECT * FROM users WHERE id = ?\"); $stmt->execute([$id]);'\n"
            "  GOOD (OS Command Injection on PHP): "
            "'Remove shell execution entirely. If pinging is required, use fsockopen() or a "
            "dedicated PHP network library. Never pass $_POST[\"ip\"] to exec(), system(), or shell_exec().'\n"
            "  GOOD (Reflected XSS on PHP): "
            "'Wrap all echoed user input in htmlspecialchars($value, ENT_QUOTES, \"UTF-8\") "
            "and add Content-Security-Policy: default-src \\'self\\' to the response headers.'\n\n"
            
            "exploitability_reasoning - Reference the specific evidence marker that justifies the rating:\n"
            "  BAD:  'The payload was executed successfully.'\n"
            "  GOOD: 'Response contains uid=33(www-data) confirming shell command execution with no auth required.'\n"
            "  GOOD: 'Time delta of 5.1s vs baseline 0.3s confirms SLEEP(5) was evaluated by the database.'\n\n"
        )

        verification_guardrails = (
            "FALSE-POSITIVE ADJUDICATION RULES:\n"
            "A false positive means the reported vulnerability did NOT occur. It does NOT mean "
            "the impact is limited, the exploit requires authentication, retrieval was not tested, "
            "or a larger exploit chain was not demonstrated. Those facts affect impact or "
            "exploitability, not whether the finding is true.\n"
            "Each finding's evidence_block includes a PROOF TYPE that tells you what kind "
            "of evidence demonstrates the vulnerability. Judge the PROOF itself, not the "
            "detector's verdict:\n"
            "- active_output / error_echo: the proof is IN the response (accepted forged token, "
            "file contents, persisted privilege field, database error, executed canary). Mark "
            "verdict=confirmed and false_positive_probability <= 0.05. Do not demand an additional "
            "exploit chain beyond the vulnerability definition.\n"
            "- structural (missing headers, TLS, admin paths): the observation IS the proof. "
            "Mark verdict=confirmed and false_positive_probability <= 0.10.\n"
            "- timing_strong: a large response delay matching the sleep argument is strong. "
            "Mark confirmed unless a recorded control demonstrates equivalent delay.\n"
            "- ssrf_differential: repeated internal/control timeout, status, or body differences "
            "are indirect evidence only. Without reflected internal content or a correlated OAST "
            "interaction, use verdict=uncertain — never confirmed.\n"
            "- auth_confirmed: distinct users or roles crossed the reported object/privilege "
            "boundary. Shared restricted identifiers or fields are the proof. Mark confirmed; "
            "anonymous denial does not weaken a horizontal authorization finding.\n"
            "- auth_differential (access-control, IDOR, data exposure): a 200 response is NOT "
            "proof. You MUST evaluate whether the data is genuinely restricted. If anonymous "
            "and authenticated responses are identical with no secret fields, the endpoint is "
            "PUBLIC by design — use verdict=likely_false_positive and cite the exact "
            "responses_identical marker.\n"
            "- pattern_match (verbose error, credential disclosure): a regex hit is NOT proof. "
            "You MUST evaluate whether the matched text is a genuine error or reflected payload "
            "/ normal content. Use likely_false_positive only when a marker directly shows "
            "reflection or benign baseline content.\n"
            "- Use the JUDGE THIS question in each evidence_block as your primary criterion.\n"
            "- verdict=uncertain means evidence is incomplete or ambiguous; uncertainty alone "
            "must stay below 0.50 FP probability.\n"
            "- verdict=likely_false_positive requires a concrete contradictory marker already "
            "present in the evidence. Cite it verbatim in false_positive_reasoning.\n"
            "- Do NOT invent evidence or application intent.\n"
            "Probability calibration: 0.00-0.05 direct/structural proof; 0.10-0.20 "
            "strong repeatable differential; 0.30-0.49 genuinely ambiguous evidence; "
            "0.60-0.79 strong alternative explanation; 0.80-1.00 only a concrete "
            "contradiction proving the detector's interpretation wrong.\n\n"
        )

        # Explicit schema with value constraints anchored to the evidence block.
        schema_keys = (
            "Return a flat JSON object with EXACTLY these keys (no extras, no nesting):\n"
            "{\n"
            '  "description": "plain-language vulnerability-class description",\n'
            '  "exploitability": "Easy",\n'
            '  "exploitability_reasoning": "specific evidence marker",\n'
            '  "business_impact": "current attacker gain and worst-case escalation",\n'
            '  "verdict": "confirmed",\n'
            '  "false_positive_probability": 0.05,\n'
            '  "false_positive_reasoning": "strongest supporting or contradictory marker",\n'
            '  "remediation": "specific stack-appropriate fix"\n'
            "}\n"
            "Constraints: description is 2-3 sentences and expands acronyms; exploitability is "
            "exactly Easy, Medium, or Hard (Easy=single request/no interaction; Medium=auth or "
            "multi-step; Hard=special configuration, chaining, or privileged access); verdict is "
            "exactly confirmed, uncertain, or likely_false_positive; false_positive_probability "
            "is a JSON number from 0.0 to 1.0; reasoning cites evidence; business_impact has two "
            "sentences; remediation names the relevant function/config and includes a one-line "
            "example when applicable.\n\n"
        )

        # Pass application context so the model can gauge realistic business
        # impact from the URL path and parameter names.
        context_note = (
            f"Target Technology Stack: {tech_stack_str}\n"
            "Note: Treat the application as a real production target. "
            "Infer application type from URL paths and parameter names when writing business_impact "
            "(e.g. /login → credential theft risk, /exec → RCE risk, /upload → file plant risk).\n\n"
        )

        if is_batch:
            return (
                role_and_task
                + output_examples
                + context_note
                + verification_guardrails
                + "Return a JSON object with a top-level \"results\" array. "
                "Retain exact index order. Each element uses the schema above.\n\n"
                + schema_keys.replace("flat JSON object", "object in the results array")
                + "Vulnerabilities to process:\n"
                + "\n".join(vuln_descriptions)
            )
        else:
            return (
                role_and_task
                + output_examples
                + context_note
                + verification_guardrails
                + schema_keys
                + "Vulnerability to analyze:\n"
                + "\n".join(vuln_descriptions)
            )
        
    def _get_fallback_for(self, vuln_type: str, tech_stack: list['TechnologyComponent'] = None, *, proof_type: str = "heuristic") -> dict:
        remediation = "Apply defense-in-depth controls appropriate to this vulnerability class."
        for key, value in self._remediation_fallbacks.items():
            if key.lower() in vuln_type.lower() or vuln_type.lower() in key.lower():
                remediation = value
                break
                
        # Framework-specific remediation overrides based on detected technology stack.
        stack_names = [t.name.lower() for t in (tech_stack or [])]
        if "sql injection" in vuln_type.lower():
            if "php" in stack_names:
                remediation = "Use mysqli_prepare() / PDO."
            elif "django" in stack_names:
                remediation = "Use Django ORM."
            elif "express" in stack_names or "node.js" in stack_names:
                remediation = "Use parameterized queries."
            elif "spring" in stack_names or "java" in stack_names:
                remediation = "Use PreparedStatement."
        elif "xss" in vuln_type.lower():
            if "php" in stack_names:
                remediation = "Use htmlspecialchars()."
            elif "django" in stack_names:
                remediation = "Use escape() in templates."
        elif "csrf" in vuln_type.lower():
            if "php" in stack_names:
                remediation = "Store csrf_token in session and validate on POST."
            elif "django" in stack_names:
                remediation = "Use @csrf_protect."
            elif "express" in stack_names or "node.js" in stack_names:
                remediation = "Use csurf middleware."
            elif "spring" in stack_names or "java" in stack_names:
                remediation = "Enable Spring Security CSRF protection."

        # Fallback FP probability varies by proof type — when the AI doesn't
        # provide a value, the fallback should reflect the proof's reliability.
        # Strong proof types get low FP; interpretive types use an explicitly
        # uncertain advisory estimate. Review status is derived separately from
        # deterministic evidence strength.
        _undeniable = {
            "active_output", "error_echo", "structural", "timing_strong",
            "auth_confirmed",
        }
        fallback_fp = 0.1 if proof_type in _undeniable else 0.4

        return {
            "exploitability": "Medium",
            "description": self._description_for(vuln_type),
            "business_impact": f"Potential security impact from {vuln_type or 'this issue'}.",
            "false_positive_probability": fallback_fp,
            "remediation": remediation,
        }

    @staticmethod
    def _normalize_ai_verdict(value: object, fp_prob: float) -> AiVerdict:
        """Normalize model verdicts while keeping legacy responses compatible."""
        try:
            return AiVerdict(str(value).strip().lower())
        except (TypeError, ValueError):
            if fp_prob >= 0.8:
                return AiVerdict.likely_false_positive
            if fp_prob >= 0.4:
                return AiVerdict.uncertain
            return AiVerdict.confirmed

    def _calibrate_ai_false_positive(
        self,
        vuln: Vulnerability,
        grade: EvidenceGrade,
        raw_fp_prob: float,
        raw_verdict: object,
        reasoning: object,
    ) -> tuple[float, AiVerdict]:
        """Constrain model judgment to the deterministic proof contract.

        The probability answers only whether the finding itself is incorrect. It
        must not encode missing impact, exploit-chain completeness, or remediation
        uncertainty. Strong proof classes therefore remain confirmed. Interpretive
        findings can receive a high FP estimate only when the evidence brief contains
        a concrete contradiction such as an identical public response or mere payload
        reflection.
        """
        raw_fp_prob = min(1.0, max(0.0, raw_fp_prob))
        verdict = self._normalize_ai_verdict(raw_verdict, raw_fp_prob)
        strong_proof_types = {
            "active_output",
            "error_echo",
            "structural",
            "timing_strong",
            "auth_confirmed",
        }

        if grade.proof_type in strong_proof_types:
            calibrated = min(raw_fp_prob, grade.fp_ceiling)
            verdict = AiVerdict.confirmed
        elif grade.proof_type == "ssrf_differential" and verdict == AiVerdict.confirmed:
            calibrated = min(raw_fp_prob, grade.fp_ceiling, 0.49)
            verdict = AiVerdict.uncertain
        elif verdict == AiVerdict.confirmed:
            calibrated = min(raw_fp_prob, grade.fp_ceiling, 0.15)
        elif verdict == AiVerdict.uncertain:
            # Uncertainty is not evidence that the detector is wrong.
            calibrated = min(raw_fp_prob, grade.fp_ceiling, 0.49)
        elif self._has_concrete_fp_contradiction(vuln, grade, reasoning):
            calibrated = min(raw_fp_prob, grade.fp_ceiling)
        else:
            calibrated = min(raw_fp_prob, grade.fp_ceiling, 0.49)
            verdict = AiVerdict.uncertain
            logger.info(
                "Downgraded unsupported AI false-positive verdict: "
                "vuln_type=%r proof_type=%s ai_fp=%.2f url=%s reasoning=%r",
                vuln.vuln_type,
                grade.proof_type,
                raw_fp_prob,
                vuln.location.url,
                reasoning,
            )

        if calibrated != raw_fp_prob:
            logger.info(
                "Calibrated AI FP estimate: vuln_type=%r proof_type=%s "
                "ai_fp=%.2f -> %.2f verdict=%s url=%s",
                vuln.vuln_type,
                grade.proof_type,
                raw_fp_prob,
                calibrated,
                verdict.value,
                vuln.location.url,
            )
        return calibrated, verdict

    def _has_concrete_fp_contradiction(
        self,
        vuln: Vulnerability,
        grade: EvidenceGrade,
        reasoning: object,
    ) -> bool:
        """Return whether high-FP reasoning cites a contradiction in the evidence."""
        reasoning_text = (_normalize_llm_string(reasoning) or "").lower()
        markers = self.evidence_grader.build_evidence_brief(vuln, grade).lower()

        if grade.proof_type == "auth_differential":
            public_response = "responses_identical: true" in markers
            no_secrets = "secret_fields_in_anonymous_response: none" in markers
            not_object_scoped = "object_scoped_request: true" not in markers
            cites_public_marker = any(
                phrase in reasoning_text
                for phrase in ("responses_identical", "identical response", "public by design")
            )
            return public_response and no_secrets and not_object_scoped and cites_public_marker

        if grade.proof_type == "pattern_match":
            reflected_only = "payload_reflected_in_response: true" in markers
            cites_reflection = any(
                phrase in reasoning_text
                for phrase in ("payload_reflected", "reflected payload", "normal page content")
            )
            return reflected_only and cites_reflection

        return False

    def _description_for(self, vuln_type: str) -> str:
        """Curated plain-language description for a vuln_type, matched by substring.

        Used only when the AI does not supply a description. Matching is two-phase,
        longest key first each phase:
          1. forward — a canonical key is contained in the detector's vuln_type
             (e.g. "SQL Injection" in "SQL Injection (Error-Based)"). Doing this
             first avoids cross-family reverse matches such as "sql injection"
             being a substring of the "NoSQL Injection" key.
          2. reverse — the (shorter) vuln_type is contained in a key, covering
             abbreviations like "IDOR" -> "Insecure Direct Object Reference (IDOR)".
        """
        vt = (vuln_type or "").strip().lower()
        if vt:
            keys_by_len = sorted(self._description_fallbacks, key=len, reverse=True)
            for key in keys_by_len:
                if key.lower() in vt:
                    return self._description_fallbacks[key]
            for key in keys_by_len:
                if vt in key.lower():
                    return self._description_fallbacks[key]
        return (
            f"A security weakness of type '{vuln_type}' was identified. It could allow an "
            "attacker to compromise the confidentiality, integrity, or availability of the "
            "application or its data."
        )

    def _remediation_is_incompatible(self, vuln_type: str, remediation: object) -> bool:
        text = str(remediation or "").lower()
        vt = (vuln_type or "").lower()
        if not text:
            return True

        sql_terms = ("prepared statement", "parameterized quer", "mysqli_prepare", "pdo", "django orm", "sql")
        if ("file inclusion" in vt or "lfi" in vt or "rfi" in vt) and any(term in text for term in sql_terms):
            return True
        if ("file upload" in vt or "extension bypass" in vt or "file type validation" in vt) and any(term in text for term in sql_terms):
            return True
        if "xss" in vt and any(term in text for term in sql_terms):
            return True
        if "csrf" in vt and any(term in text for term in sql_terms):
            return True
        return False

    def _apply_ai_review_statuses(self, vulnerabilities: list[Vulnerability]) -> None:
        """Apply advisory review statuses without changing risk or suppression.

        AI can request human review when it produced a calibrated
        ``likely_false_positive`` verdict. It cannot set ``is_false_positive``,
        suppress a finding, or alter CVSS/severity. Explicitly marked false
        positives remain suppressed for future manual-review workflows.
        """
        for vuln in vulnerabilities:
            if vuln.is_false_positive:
                vuln.review_status = ReviewStatus.suppressed
            elif (
                vuln.ai_analysis.verdict == AiVerdict.likely_false_positive
                and (vuln.ai_analysis.false_positive_probability or 0.0) >= 0.8
            ):
                vuln.review_status = ReviewStatus.needs_review
            elif (
                vuln.evidence_strength == EvidenceStrength.confirmed_observation
                and vuln.ai_analysis.verdict == AiVerdict.uncertain
                and (vuln.ai_analysis.false_positive_probability or 0.0) >= 0.3
            ):
                vuln.review_status = ReviewStatus.needs_review
            elif vuln.evidence_strength == EvidenceStrength.informational:
                vuln.review_status = ReviewStatus.informational
            elif vuln.evidence_strength == EvidenceStrength.probable:
                vuln.review_status = ReviewStatus.likely
            elif vuln.evidence_strength == EvidenceStrength.possible:
                vuln.review_status = ReviewStatus.needs_review
            else:
                vuln.review_status = ReviewStatus.confirmed
