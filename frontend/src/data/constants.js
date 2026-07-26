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
  { to: "/apps", label: "Web applications", Icon: Boxes },
  { to: "/scan", label: "New scan", Icon: ShieldPlus },
  { to: "/active", label: "Active scans", Icon: Activity, badge: "active" },
  { to: "/reports", label: "Reports", Icon: FileBarChart },
  { to: "/team", label: "Team", Icon: Users },
  { to: "/settings", label: "Settings", Icon: Settings },
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
  "/scan": "New scan",
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

// The scanner pipeline's phases, in order. AI enrichment is no longer part of
// this list — it runs in the standalone analyzer worker after the scan
// completes, and is reported separately through the scan's `analysis` state.
const SCAN_PHASES = [
  { key: "queued", label: "Queued" },
  { key: "initializing", label: "Initializing" },
  { key: "crawling", label: "Crawling" },
  { key: "technology_detection", label: "Technology detection" },
  { key: "tls_analysis", label: "TLS analysis" },
  { key: "vulnerability_detection", label: "Vulnerability detection" },
  { key: "deduplication", label: "Deduplication" },
  { key: "risk_scoring", label: "Risk scoring" },
];

const SCAN_MODES = [
  ["verified", "Verified", "Report findings backed by verification"],
  ["heuristic", "Heuristic", "Include strong signals that need review"],
  ["aggressive", "Aggressive", "Run the broadest checks; expect more noise"],
];

const CONFIG_GROUPS = [
  {
    title: "Crawler",
    blurb: "Control how far and how quickly the crawler explores the app.",
    fields: [
      {
        key: "crawl_depth",
        label: "Crawl depth",
        description:
          "Maximum number of link levels to follow from the target page.",
        type: "int",
        min: 1,
        max: 10,
        defaultValue: 3,
      },
      {
        key: "crawl_max_urls",
        label: "Max URLs",
        description:
          "Stop after collecting this many unique URLs.",
        type: "int",
        min: 10,
        max: 5000,
        defaultValue: 200,
      },
      {
        key: "crawl_rate_limit_per_second",
        label: "Rate limit",
        description: "Limit requests per second to reduce load on the target.",
        type: "float",
        min: 0.5,
        max: 100,
        step: 0.5,
        unit: "req/s",
        defaultValue: 8,
      },
      {
        key: "crawl_browser_mode",
        label: "Browser mode",
        description:
          "Choose when to use browser discovery. Detected SPAs always use it.",
        type: "select",
        defaultLabel: "Auto (detected SPAs)",
        options: [
          ["auto", "Auto (detected SPAs)"],
          ["always", "Always (all sites)"],
          ["never", "Never (except detected SPAs)"],
        ],
      },
      {
        key: "crawl_browser_max_interactions",
        label: "Browser interactions",
        description:
          "Limit clicks and form interactions during browser discovery.",
        type: "int",
        min: 1,
        max: 200,
        defaultValue: 25,
      },
      {
        key: "crawl_browser_budget_seconds",
        label: "Browser budget",
        description:
          "Limit the time spent on browser discovery.",
        type: "float",
        min: 10,
        max: 3600,
        unit: "s",
        defaultValue: 300,
      },
    ],
  },
  {
    title: "Scanner engine",
    blurb: "Set concurrency and timeouts for active checks.",
    fields: [
      {
        key: "scanner_concurrency",
        label: "Concurrency",
        description:
          "Limit how many security checks can run at once.",
        type: "int",
        min: 1,
        max: 50,
        defaultValue: 8,
      },
      {
        key: "request_timeout_seconds",
        label: "Request timeout",
        description:
          "Mark a request as timed out after this long.",
        type: "float",
        min: 1,
        max: 120,
        unit: "s",
        defaultValue: 10,
      },
      {
        key: "sensitive_paths_permutation_cap",
        label: "Sensitive-path cap",
        description:
          "Limit path variations used to find exposed resources.",
        type: "int",
        min: 0,
        max: 2000,
        defaultValue: 200,
      },
    ],
  },
  {
    title: "Injection & SSRF",
    blurb: "Set the timing thresholds used for blind injection and SSRF checks.",
    fields: [
      {
        key: "blind_injection_timing_threshold",
        label: "Blind timing threshold",
        description:
          "Minimum timing confidence for a blind injection signal.",
        type: "float",
        min: 0.1,
        max: 1,
        step: 0.05,
        defaultValue: 0.7,
      },
      {
        key: "ssrf_inband_timing_delta_ms",
        label: "SSRF timing delta",
        description:
          "Minimum delay for a possible in-band SSRF signal.",
        type: "float",
        min: 100,
        max: 30000,
        unit: "ms",
        defaultValue: 1500,
      },
    ],
  },
  {
    title: "DOM XSS sweep",
    blurb: "Set limits for browser-based DOM XSS checks.",
    fields: [
      {
        key: "xss_browser_dom_max_jobs",
        label: "Max DOM jobs",
        description:
          "Limit browser jobs used to verify client-side XSS.",
        type: "int",
        min: 0,
        max: 100,
        defaultValue: 12,
      },
      {
        key: "xss_browser_dom_budget_seconds",
        label: "DOM sweep budget",
        description:
          "Limit the time spent on DOM XSS checks.",
        type: "float",
        min: 0,
        max: 600,
        unit: "s",
        defaultValue: 60,
      },
    ],
  },
];

const CRED_ROLES = [
  {
    key: "main",
    label: "Primary user",
    desc: "Signs in for the crawl and provides the authenticated baseline.",
  },
  {
    key: "second",
    label: "Second user",
    desc: "A second standard user for horizontal access checks.",
  },
  {
    key: "admin",
    label: "Admin user",
    desc: "A privileged user for vertical access checks.",
  },
];

const CRED_FIELDS = [
  {
    key: "username",
    label: "Username / email",
    type: "text",
    maxLength: 320,
    description:
      "The account name used to sign in to the target app.",
  },
  {
    key: "password",
    label: "Password",
    type: "password",
    maxLength: 512,
    description:
      "The test account password. Leave it blank when using a cookie or header.",
  },
  {
    key: "cookie",
    label: "Cookie",
    description:
      "Existing session cookies to use instead of a login flow.",
    type: "text",
    maxLength: 8192,
    advanced: true,
    placeholder: "session=abc; csrf=def",
  },
  {
    key: "header",
    label: "Header",
    description:
      "An authentication header to send with this account's requests.",
    type: "text",
    maxLength: 8192,
    advanced: true,
    placeholder: "Authorization: Bearer …",
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
