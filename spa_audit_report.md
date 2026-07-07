# SPA Vulnerability Scanner Audit Report

## 1. Root Cause Analysis

### 1.1 Coverage Gaps (Scanner fails to reach/render vulnerable surfaces)

The scanner's failure to discover vulnerabilities in modern SPAs is primarily driven by significant coverage gaps in the crawling and discovery phase.

#### A. Reactive Form Submission Failure (97% Failure Rate)
The provided logs show that out of 71 forms discovered, only 2 resulted in a successful mutating request.
- **Root Cause:** In `backend/app/core/crawler/browser_engine.py`, the `_fill_to_valid` and `_await_submit_enabled` methods attempt to satisfy reactive form validation by filling fields and waiting for the submit button to become enabled. However, modern SPAs (React, Angular, Vue) often have complex, multi-field dependencies and custom validation logic (e.g., matching passwords, async availability checks) that the scanner's generic `_synthetic_value` generator cannot satisfy.
- **Consequence:** If the submit button remains disabled, `_submit_form` fails to fire the real mutating XHR/fetch request. Since the scanner relies on observing these runtime requests to build its attack surface (`AttackSurface.build`), most API endpoints and parameters are never even seen by the detectors.

#### B. Early Termination of Async Operations (`settle_page`)
- **Root Cause:** The `settle_page` function in `backend/app/core/crawler/spa.py` uses a hard cap (`cap_ms=2500.0`) and a quiet period (`quiet_ms=300.0`).
- **Consequence:** In complex SPAs, 2.5 seconds is often insufficient for deep component trees to render or for multiple sequential async fetches to complete (e.g., a component that fetches data, then renders a child that fetches more data). This leads to "flash of initial shell" crawling where lazy-loaded routes and components are missed entirely.

#### C. Ineffective State-Dependent Workflow Navigation
- **Root Cause:** The `_exercise_page` strategy in `browser_engine.py` relies on blind-clicking (`INTERACTIVE_SELECTOR`) and a simple `_ui_state_signature` for deduplication.
- **Consequence:** It lacks a true understanding of application state or multi-step workflows (e.g., a multi-page checkout or a wizard). The scanner often gets "stuck" or fails to reach deep vulnerable surfaces that require a specific sequence of valid state transitions.

### 1.2 Detection Gaps (Scanner reaches surface but fails to recognize vulnerability)

#### A. Limited "DOM Reflection Sweep" and Execution Vectors
- **Root Cause:** The `_browser_dom_reflection_sweep` in `xss_detector.py` is throttled to 12 jobs by default and restricted to `GET` query/path parameters.
- **Consequence:** Vulnerabilities in `POST` body reflections that are rendered client-side are ignored. Additionally, the set of 5 vectors in `_DOM_XSS_VECTOR_TEMPLATES` is too narrow; modern frameworks often sanitize `onerror` on `img` tags but might be vulnerable to `iframe src="javascript:..."` or custom component property injections which are not tested.

#### B. Failure of Raw-String Reflection Oracles
- **Root Cause:** `XSSVerifier` and `ResponseAnalyzer.verify_reflection` use string-based matching to confirm payloads in API responses.
- **Consequence:** In SPAs, the "reflection" is often not a literal echo. The data might be part of a larger JSON structure, base64 encoded, or used to dynamically construct DOM element attributes (e.g., `id` or `title`) where a raw `<script>` tag won't execute but an attribute breakout would. The current oracle is blind to these transformations.

#### C. Brittle Body-Injection Synthesis for Complex APIs
- **Root Cause:** `AttackSurface._synthesize_body_targets` creates shallow JSON objects (e.g., `{"data": "test"}`) for endpoints where no request body was observed.
- **Consequence:** Many modern APIs use highly structured, nested JSON or GraphQL. Shallow synthesis fails to satisfy backend schema validators (returning 400s), preventing the scanner from ever testing the actual logic where vulnerabilities like SQLi or Command Injection reside.

### 1.3 Validation and Reporting Gaps (Findings are detected but lost)

#### A. Premature Suppression in `verified` Scan Mode
- **Root Cause:** In `backend/app/core/scanner.py`, the `verified` mode logic (controlled by `HEURISTIC_PASSTHROUGH_TYPES`) is too restrictive. It drops any non-verified finding unless it matches a specific set of server-side heuristic keywords.
- **Consequence:** Findings like "Reflected XSS in API Response" (detected in `XSSVerifier._create_api_reflection_finding`) are correctly identified as medium severity but are dropped because they don't have a browser-confirmed exploit execution. This effectively silences valid "source" evidence that just lacks a confirmed "sink."

#### B. Context-Poor AI Analysis (LLM Grounding)
- **Root Cause:** The AI analysis pipeline (`_analyze_all_findings` in `scanner.py`) feeds the LLM truncated snippets of requests and responses.
- **Consequence:** Modern SPAs often require analyzing the JavaScript sink code (e.g., `element.innerHTML = data.user_input`) to confirm exploitability. Since the crawler doesn't store or pass the relevant client-side code segments to the LLM, the AI is forced to guess, leading to a high rate of False Negative misclassifications for findings that lack a simple server-side echo.

## 2. Architectural Recommendations

### 2.1 State-Graph Aware Crawling
Instead of blind-clicking, the crawler should build a dynamic **State-Transition Graph**.
- **Recommendation:** Implement a strategy that tracks DOM signatures and URL changes as nodes, and interactive events as edges. This allows the scanner to detect when it has reached a "new" application state even if the URL remains the same (common in SPAs).
- **Workflow Navigation:** Introduce "Workflow Templates" for common SPA patterns (e.g., Auth, Checkout, Search). These templates should define the expected sequence of state transitions and field types required to progress through multi-step flows.

### 2.2 Deep-Hooking of Browser Sinks
To solve the "source-to-sink" detection problem, move verification from the HTTP level to the **Browser Runtime level**.
- **Recommendation:** Inject a persistent instrumentation script into the browser context (via `add_init_script`) that hooks common JavaScript sinks (e.g., `element.innerHTML`, `eval`, `setTimeout`, `document.write`).
- **Real-Time Discovery:** When the crawler interacts with the page (Phase 1), any payload that reaches a hooked sink should be captured immediately as "Observed Execution." This eliminates the need for a separate, throttled "Reflection Sweep" later and provides perfect grounding for the AI analyzer.

### 2.3 Intelligent API Interception and Schema Inference
- **Recommendation:** Enhance `ApiExtractor` to perform deep static analysis of JavaScript bundles to recover full request schemas, including nested objects and optional fields.
- **Dynamic Learning:** Use observed requests from the browser crawl to dynamically update synthesized body templates. If a 400 Bad Request is encountered during injection, the scanner should attempt to "fix" the payload structure based on the error response or nearby JS code.

### 2.4 Robust Session and Authentication Persistence
- **Recommendation:** Implement "Session Heartbeat" checks. Before each navigation or interaction, the scanner should verify it is still authenticated (e.g., by checking for the presence of a specific DOM element or calling a lightweight `/me` API). If the session is lost, it should perform an automatic, state-aware re-login without losing the current crawl progress.

### 2.5 Evidence-First Reporting
- **Recommendation:** Modify the `verified` scan mode to include "High-Confidence Heuristics." Findings like "Reflected XSS in API Response" should be preserved if the API endpoint is known to be consumed by the frontend and the reflection context is potentially dangerous, even without a confirmed exploit.

## 3. Prioritized Action List

| Priority | Action Item | Expected Impact | Effort | Rationale |
| :--- | :--- | :--- | :--- | :--- |
| **P0** | **Fix Reactive Form Submission** | **Very High** | Medium | Essential for discovering the API attack surface of modern SPAs. Without this, detectors are blind. |
| **P0** | **Deep-Hook Browser Sinks** | **Very High** | High | Provides definitive proof of execution for DOM XSS and client-side reflected XSS, eliminating false negatives. |
| **P1** | **State-Graph Crawling** | **High** | High | Enables discovery of deep application states and complex multi-step workflows that blind-clicking misses. |
| **P1** | **Improve API Schema Inference** | **High** | Medium | Increases the success rate of body-injection attacks against structured JSON/GraphQL APIs. |
| **P2** | **Adjust Verified Mode Logic** | **Medium** | Low | Prevents high-confidence SPA findings from being dropped before the reporting phase. |
| **P2** | **Tune SPA Settling Time** | **Medium** | Low | Reduces "flash-of-shell" discovery failures by allowing slow components to render. |
| **P3** | **Session Heartbeat & Re-Login** | **Low** | Medium | Ensures scan continuity during long browser sessions; less critical than initial discovery. |
