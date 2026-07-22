import {
  Home,
  Boxes,
  ShieldPlus,
  Activity,
  FileBarChart,
  Users,
  Settings,
} from "lucide-react";

const NAV_ITEMS = [
  { to: "/home", label: "Home", Icon: Home, end: true },
  // { to: "/apps", label: "Web applications", Icon: Boxes },
  { to: "/scan", label: "New Scan", Icon: ShieldPlus },
  { to: "/active", label: "Active scans", Icon: Activity },
  { to: "/reports", label: "Reports", Icon: FileBarChart },
  // { to: "/team", label: "Team", Icon: Users },
  // { to: "/settings", label: "Settings", Icon: Settings },
];

const MOBILE_NAV = [
  { to: "/home", label: "Home", Icon: Home },
  { to: "/apps", label: "Apps", Icon: Boxes },
  { to: "/scan", label: "Assess", Icon: ShieldPlus },
  { to: "/reports", label: "Reports", Icon: FileBarChart },
  { to: "/settings", label: "Settings", Icon: Settings },
];

const ROUTE_NAMES = {
  "/home": "Home",
  "/apps": "Web applications",
  "/scan": "New Scan",
  "/active": "Active scans",
  "/reports": "Reports",
  "/team": "Team",
  "/settings": "Settings",
};

const SEVERITIES = ["critical", "high", "medium", "low", "info"];

const SEVERITY_META = {
  critical: { color: "var(--sev-critical)", label: "CRITICAL" },
  high: { color: "var(--sev-high)", label: "HIGH" },
  medium: { color: "var(--sev-medium)", label: "MEDIUM" },
  low: { color: "var(--sev-low)", label: "LOW" },
  info: { color: "var(--sev-info)", label: "INFO" },
  safe: { color: "var(--sev-low)", label: "SAFE" },
};

// Single source of truth for mapping a severity value to its CSS color class
// (.critical/.high/.medium/.low/.info). Use everywhere instead of ad-hoc
// ternaries so every severity keeps one consistent color across the app.
const SEVERITY_CLASSES = new Set(["critical", "high", "medium", "low", "info"]);

function severityClass(severity) {
  const s = (severity || "").toString().toLowerCase();
  if (SEVERITY_CLASSES.has(s)) return s;
  if (s === "safe") return "low";
  // Unknown/empty severities are treated as informational, never as high.
  return "info";
}

const SCAN_PHASES = [
  { key: "queued", label: "Queued" },
  { key: "initializing", label: "Initializing" },
  { key: "crawling", label: "Crawling" },
  { key: "technology_detection", label: "Technology detection" },
  { key: "tls_analysis", label: "TLS analysis" },
  { key: "vulnerability_detection", label: "Vulnerability detection" },
  { key: "deduplication", label: "Deduplication" },
  { key: "ai_analysis", label: "AI analysis" },
  { key: "risk_scoring", label: "Risk scoring" },
  { key: "report_generation", label: "Report generation" },
];

const SCAN_MODES = [
  ["verified", "Verified", "Only evidence-verified findings"],
  ["heuristic", "Heuristic", "Adds strong heuristic matches"],
  ["aggressive", "Aggressive", "Widest checks, more noise"],
];

const CONFIG_GROUPS = [
  {
    title: "Crawler",
    blurb: "How far and how fast SentryStrike discovers pages.",
    fields: [
      {
        key: "crawl_depth",
        label: "Crawl depth",
        description: "Maximum number of link levels to follow from the target page.",
        type: "int",
        min: 1,
        max: 10,
        placeholder: "e.g. 3",
      },
      {
        key: "crawl_max_urls",
        label: "Max URLs",
        description: "Stops discovery after this many unique URLs have been collected.",
        type: "int",
        min: 10,
        max: 5000,
        placeholder: "e.g. 500",
      },
      {
        key: "crawl_rate_limit_per_second",
        label: "Rate limit",
        description: "Caps requests per second to reduce load on the target.",
        type: "float",
        min: 0.5,
        max: 100,
        step: 0.5,
        unit: "req/s",
        placeholder: "e.g. 10",
      },
      {
        key: "crawl_browser_mode",
        label: "Browser mode",
        description: "Controls when a real browser is used for JavaScript-rendered pages.",
        type: "select",
        options: [
          ["auto", "Auto (SPA only)"],
          ["always", "Always"],
          ["never", "Never"],
        ],
      },
      {
        key: "crawl_browser_max_interactions",
        label: "Browser interactions",
        description: "Maximum clicks and form interactions performed during discovery.",
        type: "int",
        min: 1,
        max: 200,
        placeholder: "e.g. 40",
      },
      {
        key: "crawl_browser_budget_seconds",
        label: "Browser budget",
        description: "Maximum time reserved for browser-based crawling.",
        type: "float",
        min: 10,
        max: 3600,
        unit: "s",
        placeholder: "e.g. 120",
      },
    ],
  },
  {
    title: "Scanner engine",
    blurb: "Throughput and timeouts for the active probing phase.",
    fields: [
      {
        key: "scanner_concurrency",
        label: "Concurrency",
        description: "Maximum number of security checks that can run at the same time.",
        type: "int",
        min: 1,
        max: 50,
        placeholder: "e.g. 10",
      },
      {
        key: "request_timeout_seconds",
        label: "Request timeout",
        description: "How long each request may wait before it is treated as timed out.",
        type: "float",
        min: 1,
        max: 120,
        unit: "s",
        placeholder: "e.g. 30",
      },
      {
        key: "sensitive_paths_permutation_cap",
        label: "Sensitive-path cap",
        description: "Limits generated path variations used to find exposed resources.",
        type: "int",
        min: 0,
        max: 2000,
        placeholder: "e.g. 500",
      },
    ],
  },
  {
    title: "Injection & SSRF",
    blurb: "Timing thresholds and out-of-band callbacks for blind findings.",
    fields: [
      {
        key: "blind_injection_timing_threshold",
        label: "Blind timing threshold",
        description: "Minimum response-time confidence used for blind injection signals.",
        type: "float",
        min: 0.1,
        max: 1,
        step: 0.05,
        placeholder: "0.1 – 1.0",
      },
      {
        key: "ssrf_inband_timing_delta_ms",
        label: "SSRF timing delta",
        description: "Minimum delay used to identify possible in-band SSRF behavior.",
        type: "float",
        min: 100,
        max: 30000,
        unit: "ms",
        placeholder: "e.g. 1000",
      },
      {
        key: "oast_callback_base_url",
        label: "OAST callback URL",
        description: "Callback base URL used to verify out-of-band interactions.",
        type: "text",
        maxLength: 2048,
        placeholder: "https://oast.example/…",
      },
      {
        key: "oast_poll_url",
        label: "OAST poll URL",
        description: "Endpoint polled for captured out-of-band interaction results.",
        type: "text",
        maxLength: 2048,
        placeholder: "https://oast.example/poll",
      },
    ],
  },
  {
    title: "DOM XSS sweep",
    blurb: "Budget for the browser-driven client-side reflection sweep.",
    fields: [
      {
        key: "xss_browser_dom_max_jobs",
        label: "Max DOM jobs",
        description: "Maximum browser jobs used to verify client-side XSS behavior.",
        type: "int",
        min: 0,
        max: 100,
        placeholder: "e.g. 20",
      },
      {
        key: "xss_browser_dom_budget_seconds",
        label: "DOM sweep budget",
        description: "Maximum time reserved for the browser-driven DOM XSS sweep.",
        type: "float",
        min: 0,
        max: 600,
        unit: "s",
        placeholder: "e.g. 60",
      },
    ],
  },
];

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

const CRED_FIELDS = [
  {
    key: "username",
    label: "Username / email",
    type: "text",
    maxLength: 320,
    description: "Account identifier used to sign in to the target application.",
  },
  {
    key: "password",
    label: "Password",
    type: "password",
    maxLength: 512,
    description: "Password for this test account; leave blank for session-only access.",
  },
  {
    key: "cookie",
    label: "Cookie",
    description: "Existing session cookies to attach when a login flow is unavailable.",
    type: "text",
    maxLength: 8192,
    advanced: true,
    placeholder: "session=abc; csrf=def",
  },
  {
    key: "header",
    label: "Header",
    description: "Custom authentication header sent with requests for this account.",
    type: "text",
    maxLength: 8192,
    advanced: true,
    placeholder: "Authorization: Bearer …",
  },
  {
    key: "login_url",
    label: "Login URL",
    description: "Exact page where this account submits its sign-in details.",
    type: "text",
    maxLength: 2048,
    advanced: true,
  },
  {
    key: "success_url",
    label: "Success URL",
    description: "URL expected after a successful sign-in.",
    type: "text",
    maxLength: 2048,
    advanced: true,
  },
  {
    key: "success_text",
    label: "Success text",
    description: "Page text that confirms the account signed in successfully.",
    type: "text",
    maxLength: 256,
    advanced: true,
  },
  {
    key: "success_regex",
    label: "Success regex",
    description: "Regular expression matched against a successful sign-in response.",
    type: "text",
    maxLength: 512,
    advanced: true,
  },
  {
    key: "failure_text",
    label: "Failure text",
    description: "Page text that indicates the sign-in attempt failed.",
    type: "text",
    maxLength: 256,
    advanced: true,
  },
  {
    key: "failure_regex",
    label: "Failure regex",
    description: "Regular expression matched against a failed sign-in response.",
    type: "text",
    maxLength: 512,
    advanced: true,
  },
  {
    key: "validation_url",
    label: "Validation URL",
    description: "Authenticated page used to confirm the session remains valid.",
    type: "text",
    maxLength: 2048,
    advanced: true,
  },
];

export {
  NAV_ITEMS,
  MOBILE_NAV,
  ROUTE_NAMES,
  SEVERITIES,
  SEVERITY_META,
  severityClass,
  SCAN_PHASES,
  SCAN_MODES,
  CONFIG_GROUPS,
  CRED_ROLES,
  CRED_FIELDS,
};
