import {
  WarningOctagon,
  Warning,
  WarningCircle,
  Info,
  CheckCircle,
  TreeStructure,
  Gauge,
  Bug,
  Browsers,
  ShieldCheck,
  Pulse,
  ClockCounterClockwise,
} from "@phosphor-icons/react";

const SEVERITIES = ["critical", "high", "medium", "low", "info"];

const SEVERITY_META = {
  critical: {
    color: "#ef4444",
    bg: "rgba(239,68,68,0.12)",
    border: "rgba(239,68,68,0.35)",
    label: "CRITICAL",
    Icon: WarningOctagon,
  },
  high: {
    color: "#f97316",
    bg: "rgba(249,115,22,0.12)",
    border: "rgba(249,115,22,0.35)",
    label: "HIGH",
    Icon: Warning,
  },
  medium: {
    color: "#eab308",
    bg: "rgba(234,179,8,0.12)",
    border: "rgba(234,179,8,0.35)",
    label: "MEDIUM",
    Icon: WarningCircle,
  },
  low: {
    color: "#38bdf8",
    bg: "rgba(56,189,248,0.12)",
    border: "rgba(56,189,248,0.35)",
    label: "LOW",
    Icon: Info,
  },
  info: {
    color: "#64748b",
    bg: "rgba(100,116,139,0.12)",
    border: "rgba(100,116,139,0.35)",
    label: "INFO",
    Icon: Info,
  },
  safe: {
    color: "#22c55e",
    bg: "rgba(34,197,94,0.12)",
    border: "rgba(34,197,94,0.35)",
    label: "SAFE",
    Icon: CheckCircle,
  },
};

const SCAN_STAGES = [
  "Initializing scanner...",
  "Crawling target...",
  "Detecting vulnerabilities...",
  "Running OWASP checks...",
  "AI analysis in progress...",
  "Generating security report...",
  "Scan complete",
];

// Scan verification mode — maps to CreateScanRequest.config.scan_mode.
const SCAN_MODES = [
  ["verified", "Verified", "Only evidence-verified findings"],
  ["heuristic", "Heuristic", "Adds strong heuristic matches"],
  ["aggressive", "Aggressive", "Widest checks, more noise"],
];

// Every ScanConfig override, grouped for the advanced panel. Each field maps
// 1:1 to a backend ScanConfig key; `type`/`min`/`max`/`step` mirror the
// pydantic constraints so the UI can't submit out-of-range values. Leaving a
// field blank omits it, so the backend falls back to its global default.
const CONFIG_GROUPS = [
  {
    title: "Crawler",
    icon: TreeStructure,
    blurb: "How far and how fast SentryStrike discovers pages.",
    fields: [
      {
        key: "crawl_depth",
        label: "Crawl depth",
        type: "int",
        min: 1,
        max: 10,
        placeholder: "e.g. 3",
        help: "Maximum link-follow depth from the root.",
      },
      {
        key: "crawl_max_urls",
        label: "Max URLs",
        type: "int",
        min: 10,
        max: 5000,
        placeholder: "e.g. 500",
        help: "Maximum number of URLs to discover.",
      },
      {
        key: "crawl_rate_limit_per_second",
        label: "Rate limit",
        type: "float",
        min: 0.5,
        max: 100,
        step: 0.5,
        unit: "req/s",
        placeholder: "e.g. 10",
        help: "HTTP requests per second during crawling.",
      },
      {
        key: "crawl_browser_mode",
        label: "Browser mode",
        type: "select",
        options: [
          ["auto", "Auto (SPA only)"],
          ["always", "Always"],
          ["never", "Never"],
        ],
        help: "When to use a real browser for discovery.",
      },
      {
        key: "crawl_browser_max_interactions",
        label: "Browser interactions",
        type: "int",
        min: 1,
        max: 200,
        placeholder: "e.g. 40",
        help: "Max clicks/navigations per page in browser mode.",
      },
      {
        key: "crawl_browser_budget_seconds",
        label: "Browser budget",
        type: "float",
        min: 10,
        max: 3600,
        unit: "s",
        placeholder: "e.g. 120",
        help: "Max wall-clock seconds for browser discovery.",
      },
    ],
  },
  {
    title: "Scanner engine",
    icon: Gauge,
    blurb: "Throughput and timeouts for the active probing phase.",
    fields: [
      {
        key: "scanner_concurrency",
        label: "Concurrency",
        type: "int",
        min: 1,
        max: 50,
        placeholder: "e.g. 10",
        help: "Concurrent HTTP workers during scanning.",
      },
      {
        key: "request_timeout_seconds",
        label: "Request timeout",
        type: "float",
        min: 1,
        max: 120,
        unit: "s",
        placeholder: "e.g. 30",
        help: "HTTP request timeout in seconds.",
      },
      {
        key: "sensitive_paths_permutation_cap",
        label: "Sensitive-path cap",
        type: "int",
        min: 0,
        max: 2000,
        placeholder: "e.g. 500",
        help: "Maximum sensitive-path permutations to probe.",
      },
    ],
  },
  {
    title: "Injection & SSRF",
    icon: Bug,
    blurb: "Timing thresholds and out-of-band callbacks for blind findings.",
    fields: [
      {
        key: "blind_injection_timing_threshold",
        label: "Blind timing threshold",
        type: "float",
        min: 0.1,
        max: 1,
        step: 0.05,
        placeholder: "0.1 – 1.0",
        help: "Fraction of expected delay used as the blind-injection threshold.",
      },
      {
        key: "ssrf_inband_timing_delta_ms",
        label: "SSRF timing delta",
        type: "float",
        min: 100,
        max: 30000,
        unit: "ms",
        placeholder: "e.g. 1000",
        help: "Min internal/external response-time delta for in-band SSRF.",
      },
      {
        key: "oast_callback_base_url",
        label: "OAST callback URL",
        type: "text",
        maxLength: 2048,
        placeholder: "https://oast.example/…",
        help: "Out-of-band callback URL for SSRF confirmation.",
      },
      {
        key: "oast_poll_url",
        label: "OAST poll URL",
        type: "text",
        maxLength: 2048,
        placeholder: "https://oast.example/poll",
        help: "URL to retrieve OAST callback results.",
      },
    ],
  },
  {
    title: "DOM XSS sweep",
    icon: Browsers,
    blurb: "Budget for the browser-driven client-side reflection sweep.",
    fields: [
      {
        key: "xss_browser_dom_max_jobs",
        label: "Max DOM jobs",
        type: "int",
        min: 0,
        max: 100,
        placeholder: "e.g. 20",
        help: "Max route+param probes for the browser DOM-XSS sweep.",
      },
      {
        key: "xss_browser_dom_budget_seconds",
        label: "DOM sweep budget",
        type: "float",
        min: 0,
        max: 600,
        unit: "s",
        placeholder: "e.g. 60",
        help: "Wall-clock budget for the DOM-XSS browser sweep.",
      },
    ],
  },
];

// The three credential roles accepted by ScanCredentials. Supplying an account
// unlocks authenticated crawling and the corresponding access-control tests.
const CRED_ROLES = [
  {
    key: "main",
    label: "Primary user",
    desc: "Authenticates the crawl and acts as the authed baseline.",
  },
  {
    key: "second",
    label: "Second user",
    desc: "A second regular user — proves horizontal IDOR.",
  },
  {
    key: "admin",
    label: "Admin user",
    desc: "A privileged user — proves vertical privilege escalation.",
  },
];

// Fields on a single ScanAccountCredential. `advanced: true` fields are the
// login-flow overrides most scans never need, so the UI can tuck them away.
const CRED_FIELDS = [
  { key: "username", label: "Username / email", type: "text", maxLength: 320 },
  { key: "password", label: "Password", type: "password", maxLength: 512 },
  {
    key: "cookie",
    label: "Cookie",
    type: "text",
    maxLength: 8192,
    advanced: true,
    placeholder: "session=abc; csrf=def",
    help: "Raw cookie fallback if username/password login isn't possible.",
  },
  {
    key: "header",
    label: "Header",
    type: "text",
    maxLength: 8192,
    advanced: true,
    placeholder: "Authorization: Bearer …",
    help: "Raw header fallback, e.g. a bearer token.",
  },
  {
    key: "login_url",
    label: "Login URL",
    type: "text",
    maxLength: 2048,
    advanced: true,
    help: "Explicit login endpoint if it differs from the target root.",
  },
  {
    key: "success_url",
    label: "Success URL",
    type: "text",
    maxLength: 2048,
    advanced: true,
    help: "URL that confirms a logged-in session (e.g. /dashboard).",
  },
  {
    key: "success_text",
    label: "Success text",
    type: "text",
    maxLength: 256,
    advanced: true,
    help: "Body text that confirms login success.",
  },
  {
    key: "success_regex",
    label: "Success regex",
    type: "text",
    maxLength: 512,
    advanced: true,
    help: "Regex matching a login-success signature.",
  },
  {
    key: "failure_text",
    label: "Failure text",
    type: "text",
    maxLength: 256,
    advanced: true,
    help: "Body text that indicates login failure.",
  },
  {
    key: "failure_regex",
    label: "Failure regex",
    type: "text",
    maxLength: 512,
    advanced: true,
    help: "Regex matching a login-failure signature.",
  },
  {
    key: "validation_url",
    label: "Validation URL",
    type: "text",
    maxLength: 2048,
    advanced: true,
    help: "Protected URL used to verify an active session.",
  },
];

// Vertical-sidebar navigation. Each entry is an /app child route. The Active
// item carries a live badge (count of queued/running scans) supplied by the
// Sidebar, so no count lives here.
const NAV_ITEMS = [
  { to: "/app/scan", label: "New Scan", Icon: ShieldCheck, end: false },
  { to: "/app/active", label: "Active", Icon: Pulse, badge: "active" },
  { to: "/app/history", label: "History", Icon: ClockCounterClockwise },
];

export {
  SEVERITIES,
  SEVERITY_META,
  SCAN_STAGES,
  SCAN_MODES,
  CONFIG_GROUPS,
  CRED_ROLES,
  CRED_FIELDS,
  NAV_ITEMS,
};
