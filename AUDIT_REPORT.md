# Vulnerability Scanner Audit Report: SPA Effectiveness

## 1. Root Cause Analysis

Based on a comprehensive audit of the Sentry Strike codebase, the scanner's failure to discover vulnerabilities in modern Single Page Applications (SPAs) is attributed to the following coverage, detection, and reporting gaps.

### 1.1 Coverage Gaps (Scanner fails to reach/render the surface)

#### **1.1.1 Hash-Route Blindness (Critical)**
*   **Evidence:** `backend/app/core/crawler/url_parser.py` (Line 28: `normalize_for_dedupe`) and `backend/app/core/crawler/spider.py` (Line 115: `should_enqueue`).
*   **Explanation:** The URL normalization logic used for deduplication explicitly strips fragments (e.g., `#/dashboard`). In SPAs using hash-based routing, every application state is treated as identical to the root URL. The crawler discards these routes as "already visited" before they can be enqueued for the browser discovery engine or analyzed by detectors.

#### **1.1.2 Static UI Component Model**
*   **Evidence:** `backend/app/core/crawler/browser_engine.py` (Line 157: `FORM_CAPTURE_SCRIPT`).
*   **Explanation:** The `FORM_CAPTURE_SCRIPT` primarily targets standard HTML tags (`input`, `textarea`, `select`). Modern SPAs heavily utilize custom components (e.g., React/Vue components rendered as `div` or `span` with ARIA roles). These are never captured as fillable or interactive fields, leaving complex business logic (and their underlying APIs) untested.

#### **1.1.3 Workflow State Ignorance**
*   **Evidence:** `backend/app/core/crawler/browser_engine.py` (Line 1433: `_exercise_page`).
*   **Explanation:** The interaction model uses a "blind click" strategy limited by a fixed `max_interactions` count. It lacks a state-transition graph, meaning it cannot navigate multi-step flows (e.g., "Add to Cart" -> "Checkout" -> "Payment Form") where vulnerabilities often reside in deeper, state-dependent surfaces.

---

### 1.2 Detection Gaps (Scanner reaches the surface but fails to recognize the vulnerability)

#### **1.2.1 HTML-Biased Similarity Analysis**
*   **Evidence:** `backend/app/core/verification/sqli_verifier.py` (Line 60: `_STABILITY_FLOOR = 0.70`).
*   **Explanation:** The similarity thresholds are tuned for static HTML pages. API responses in SPAs often return large JSON objects containing naturally varying data (timestamps, counters, non-deterministic arrays). These "noisy" responses frequently fall below the stability floor, causing the `SQLiVerifier` and `XSSVerifier` to skip analysis due to false "instability" signals.

#### **1.2.2 Limited Evidence Snippets**
*   **Evidence:** `backend/app/core/crawler/browser_engine.py` (Line 414: `_wire_page_observers`).
*   **Explanation:** Runtime API response snippets are hard-capped at 1000 characters. Large, nested JSON responses used by SPAs to populate dashboards or tables are often truncated, causing the `ResponseAnalyzer` to miss evidence of sensitive data exposure or reflected payloads located deeper in the response body.

---

### 1.3 Reporting Gaps (Scanner detects finding but drops it)

#### **1.3.1 Aggressive "Verified" Mode Filtering**
*   **Evidence:** `backend/app/core/scanner.py` (Line 650: `scan_mode == "verified"`) and the `HEURISTIC_PASSTHROUGH_TYPES` list.
*   **Explanation:** The orchestrator silently drops any finding not marked as `verified` unless it belongs to a narrow list of heuristic types. Critical SPA issues like "Reflected XSS in API Response" or "Unauthenticated API Data Exposure" are frequently marked as unverified because they represent structural risks rather than traditional "exploit proof" triggers. Because these modern classes are missing from the passthrough list, they never reach the final report.

---

## 2. Architectural Recommendations

### 2.1 SPA-Aware Routing & Deduplication
Modify the crawler's deduplication logic to treat fragments as distinct paths when hash-routing patterns (e.g., `#/` or `#!/`) are detected. This ensures the browser engine navigates to and exercises every unique application state.

### 2.2 Semantic Component Discovery
Enhance `FORM_CAPTURE_SCRIPT` to identify interactive elements based on ARIA roles (`role="button"`, `role="listbox"`) and event listeners, rather than just tag names. This will significantly increase the discoverable attack surface in modern component-based UIs.

### 2.3 JSON-Contextual Verification
Detectors should transition from flat-string reflection analysis to JSON-aware parsing. This allows for:
1.  **Field-Specific Stability:** Ignoring volatile fields (e.g., `updated_at`) during similarity checks.
2.  **Contextual Encoding:** Understanding if a payload reflected in a JSON field is potentially executable once rendered into a client-side sink.

### 2.4 Structural Risk Reporting
Expand the `HEURISTIC_PASSTHROUGH_TYPES` in the orchestrator to include structural SPA vulnerabilities. If an API endpoint returns PII or lacks session validation, it should be reported regardless of whether a "shell-pop" payload succeeded.

---

## 3. Prioritized Action List

| Priority | Action | Rationale | Effort |
| :--- | :--- | :--- | :--- |
| **1** | Fix Hash-Route Deduplication | Fundamental coverage blocker; prevents the scanner from even seeing 90% of some SPAs. | Low |
| **2** | Expand Reporting Passthrough List | Immediate impact on visibility; prevents confirmed structural risks from being suppressed. | Low |
| **3** | Increase API Snippet Cap | Essential for detecting data exposure in large SPA JSON responses. | Low |
| **4** | Semantic ARIA-based Discovery | Necessary to reach modern custom UI components and their bound APIs. | Medium |
| **5** | Implement JSON-Aware Stability | Reduces false negatives caused by natural variance in API data. | High |
