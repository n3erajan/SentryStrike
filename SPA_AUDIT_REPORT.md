# Sentry Strike SPA Vulnerability Scanner: Comprehensive Audit Report

## 1. Executive Summary
This audit provides a detailed analysis of the Sentry Strike vulnerability scanner's performance against modern Single Page Applications (SPAs). The scanner, while possessing advanced capabilities like headless rendering and programmatic route hooking, suffers from fundamental architectural gaps in its discovery and detection pipelines. These gaps result in significant "blind spots" where entire classes of vulnerabilities (e.g., BOLA in non-sequential APIs, WebSocket-based flaws, and deep-workflow state vulnerabilities) are consistently missed.

## 2. Root Cause Analysis (RCA)

### 2.1 Coverage Gaps (Discovery & Rendering)
*   **Split Seeding Strategy:** In `spider.py`, the headless browser is only seeded with routes extracted via static JavaScript regex. Standard `<a>` links and brute-forced paths found by the spider are **not** passed to the browser. This means the scanner never "renders" many reachable parts of the application, failing to trigger hydration and subsequent API calls.
*   **Limited Interactive Surface:** The `INTERACTIVE_SELECTOR` in `browser_engine.py` focuses on standard roles (`button`, `a[href]`). Modern frameworks (React, Vue) often use `div` or `span` elements with custom `onClick` handlers. Without `role="button"` or `tabindex`, these elements are ignored by the blind clicker.
*   **WebSocket & Binary Protocol Blind Spot:** `browser_engine.py` explicitly classifies WebSockets as "noise." This is a major gap for modern apps that use real-time sockets or binary protocols like Protobuf/gRPC-web for core logic.
*   **Interaction Limits:** The default `max_interactions=25` is insufficient for complex, state-heavy SPAs. A single large page with many components can easily exhaust this budget before reaching deep states.
*   **Settling & Timing Issues:** The 2.5s `cap_ms` in `settle_page` is a "one-size-fits-all" solution that fails for slow-hydrating SPAs. If the scanner proceeds before API calls are fired, those surfaces are never discovered.

### 2.2 Detection Gaps (Recognition & Verifiers)
*   **Predictable ID Mutation:** `AccessControlDetector` primarily uses `+1` / `-1` increments. Modern APIs favor non-sequential UUIDs or opaque tokens (e.g., Snowflake IDs). The scanner's "guess" logic is too shallow to find valid cross-user object references in these environments.
*   **JSON Similarity Suppression:** The IDOR detector uses a character-based similarity floor (`0.95`). In structured JSON, changing a single identifier might only alter 1% of the body, causing the scanner to misclassify a successful bypass as a "generic template" and suppress the finding.
*   **Legacy SQLi Markers:** `sqli_verifier.py` relies on 20+ year old database engine error strings. Cloud-native backends often hide these behind 500 errors or wrap them in generic JSON error envelopes that the verifier does not recognize.
*   **State-Agnostic Testing:** Detectors test parameters in isolation. They do not understand that a "Delete" action might only be vulnerable if an item was first "Created" and its ID captured. The scanner lacks the "sequence memory" to chain these operations.
*   **Static Synthesis Inaccuracy:** Fallback bodies like `{ "data": "test" }` fail validation in strict APIs. Without inferring actual field names and types from JS mining, synthetic probes are often blocked at the validation layer.

### 2.3 Validation/Reporting Gaps (Findings Loss)
*   **Prioritization Starvation:** `AttackPlanner` heavily penalizes `static_synth` targets. If the browser crawl is even slightly incomplete, the scanner effectively abandons the statically-mined API surface.
*   **Fragile AI Post-Processing:** `scanner.py` auto-suppresses findings if the AI reasoning does not explicitly name an "evidence marker." If the AI model fails to be descriptive (common with smaller local models like Qwen), verified findings are dropped.
*   **Session Loss Sensitivity:** The scanner relies on static auth materials. If an interaction triggers a logout or token expiration, the scanner continues in an unauthenticated state without attempting a re-login, leading to silent coverage loss.

---

## 3. Architectural Recommendations

### 3.1 Unified Browser-First Crawling
*   **Shift:** Move to a pipeline where the browser is the **primary** worker. Every URL discovered (regardless of source) must be rendered in the browser. This ensures 100% hydration coverage and allows the scanner to intercept real-world API traffic for every reachable state.

### 3.2 Workflow Sequence Engine
*   **Shift:** Implement a "State Graph" for interactions. The crawler should record sequences of events (e.g., *Login -> Search -> Select -> Delete*). This allows verifiers to "replay" to a specific state before injecting payloads, reaching surfaces that are hidden behind multi-step workflows.

### 3.3 Semantic JSON Analysis
*   **Shift:** Replace character-based similarity with **Structural Differentials**. Compare JSON responses by key presence, value type changes, and identifier entropy. This allows the scanner to detect BOLA/IDOR even when response bodies are 99% identical.

### 3.4 Adaptive API Probing
*   **Shift:** When an API endpoint is discovered, the scanner should move beyond passive observation. It should attempt active discovery techniques like GraphQL introspection, `OPTIONS` verb fuzzing, and directory brute-forcing against standard API versioning paths (`/api/v1`, `/api/v2`).

---

## 4. Prioritized Action List

| Rank | Action Item | Expected Impact | Implementation Effort | Rationale |
| :--- | :--- | :--- | :--- | :--- |
| **1** | **Fix Seeding Gap** | **High** | **Low** | Ensures the browser renders every route found by the spider, immediately boosting coverage. |
| **2** | **Enhanced ID Fuzzer** | **High** | **Medium** | Supporting UUIDs and cross-parameter ID swapping is critical for modern API security. |
| **3** | **JSON Semantic Matcher** | **High** | **Medium** | Essential for detecting IDOR/BOLA in structured API responses without false-positive suppression. |
| **4** | **Expand Interactive Selectors** | **Medium** | **Low** | Including `div`/`span` in clicking logic reaches custom React/Vue controls missed by standard selectors. |
| **5** | **WebSocket Discovery** | **Medium** | **High** | Closes a significant 0% coverage blind spot in many modern real-time applications. |
| **6** | **GraphQL Introspection** | **Low** | **Medium** | Provides more complete coverage for GraphQL backends than simple passive string mining. |
