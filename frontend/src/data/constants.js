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
  { to: "/scan", label: "New Scan", Icon: ShieldPlus },
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
  "/scan": "New Scan",
  "/active": "Active scans",
  "/reports": "Reports",
  "/team": "Team",
  "/settings": "Settings",
};

const SEVERITIES = ["critical", "high", "medium", "low", "info"];

const SEVERITY_META = {
  critical: { color: "var(--bad)", label: "CRITICAL" },
  high: { color: "var(--bad)", label: "HIGH" },
  medium: { color: "var(--warn)", label: "MEDIUM" },
  low: { color: "var(--good)", label: "LOW" },
  info: { color: "var(--muted)", label: "INFO" },
  safe: { color: "var(--good)", label: "SAFE" },
};

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
        type: "int",
        min: 1,
        max: 10,
        placeholder: "e.g. 3",
      },
      {
        key: "crawl_max_urls",
        label: "Max URLs",
        type: "int",
        min: 10,
        max: 5000,
        placeholder: "e.g. 500",
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
      },
      {
        key: "crawl_browser_max_interactions",
        label: "Browser interactions",
        type: "int",
        min: 1,
        max: 200,
        placeholder: "e.g. 40",
      },
      {
        key: "crawl_browser_budget_seconds",
        label: "Browser budget",
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
        type: "int",
        min: 1,
        max: 50,
        placeholder: "e.g. 10",
      },
      {
        key: "request_timeout_seconds",
        label: "Request timeout",
        type: "float",
        min: 1,
        max: 120,
        unit: "s",
        placeholder: "e.g. 30",
      },
      {
        key: "sensitive_paths_permutation_cap",
        label: "Sensitive-path cap",
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
        type: "float",
        min: 0.1,
        max: 1,
        step: 0.05,
        placeholder: "0.1 – 1.0",
      },
      {
        key: "ssrf_inband_timing_delta_ms",
        label: "SSRF timing delta",
        type: "float",
        min: 100,
        max: 30000,
        unit: "ms",
        placeholder: "e.g. 1000",
      },
      {
        key: "oast_callback_base_url",
        label: "OAST callback URL",
        type: "text",
        maxLength: 2048,
        placeholder: "https://oast.example/…",
      },
      {
        key: "oast_poll_url",
        label: "OAST poll URL",
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
        type: "int",
        min: 0,
        max: 100,
        placeholder: "e.g. 20",
      },
      {
        key: "xss_browser_dom_budget_seconds",
        label: "DOM sweep budget",
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
  { key: "username", label: "Username / email", type: "text", maxLength: 320 },
  { key: "password", label: "Password", type: "password", maxLength: 512 },
  {
    key: "cookie",
    label: "Cookie",
    type: "text",
    maxLength: 8192,
    advanced: true,
    placeholder: "session=abc; csrf=def",
  },
  {
    key: "header",
    label: "Header",
    type: "text",
    maxLength: 8192,
    advanced: true,
    placeholder: "Authorization: Bearer …",
  },
  {
    key: "login_url",
    label: "Login URL",
    type: "text",
    maxLength: 2048,
    advanced: true,
  },
  {
    key: "success_url",
    label: "Success URL",
    type: "text",
    maxLength: 2048,
    advanced: true,
  },
  {
    key: "success_text",
    label: "Success text",
    type: "text",
    maxLength: 256,
    advanced: true,
  },
  {
    key: "success_regex",
    label: "Success regex",
    type: "text",
    maxLength: 512,
    advanced: true,
  },
  {
    key: "failure_text",
    label: "Failure text",
    type: "text",
    maxLength: 256,
    advanced: true,
  },
  {
    key: "failure_regex",
    label: "Failure regex",
    type: "text",
    maxLength: 512,
    advanced: true,
  },
  {
    key: "validation_url",
    label: "Validation URL",
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
  SCAN_PHASES,
  SCAN_MODES,
  CONFIG_GROUPS,
  CRED_ROLES,
  CRED_FIELDS,
};
