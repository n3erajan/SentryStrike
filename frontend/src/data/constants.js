const SEVERITIES = ["critical", "high", "medium", "low"];

const SEVERITY_META = {
  critical: {
    color: "#ef4444",
    bg: "rgba(239,68,68,0.12)",
    border: "rgba(239,68,68,0.35)",
    label: "CRITICAL",
    icon: "⬡",
  },
  high: {
    color: "#f97316",
    bg: "rgba(249,115,22,0.12)",
    border: "rgba(249,115,22,0.35)",
    label: "HIGH",
    icon: "▲",
  },
  medium: {
    color: "#eab308",
    bg: "rgba(234,179,8,0.12)",
    border: "rgba(234,179,8,0.35)",
    label: "MEDIUM",
    icon: "◆",
  },
  low: {
    color: "#3b82f6",
    bg: "rgba(59,130,246,0.12)",
    border: "rgba(59,130,246,0.35)",
    label: "LOW",
    icon: "●",
  },
  safe: {
    color: "#22c55e",
    bg: "rgba(34,197,94,0.12)",
    border: "rgba(34,197,94,0.35)",
    label: "SAFE",
    icon: "✓",
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

const LOG_LINES = [
  { kind: "ok", text: "[✓] Resolving DNS records" },
  { kind: "ok", text: "[✓] TLS handshake completed (TLS 1.2)" },
  { kind: "ok", text: "[✓] Crawled 24 endpoints" },
  { kind: "ok", text: "[✓] Security headers analyzed" },
  { kind: "warn", text: "[!] Missing Content-Security-Policy" },
  { kind: "warn", text: "[!] Potential SQL injection on /api/users" },
  { kind: "ok", text: "[✓] Reflected XSS confirmed on /search" },
  { kind: "ok", text: "[✓] Cookie attributes inspected" },
  { kind: "ok", text: "[✓] TLS configuration checked" },
  { kind: "ok", text: "[✓] AI cross-validation completed" },
  { kind: "ok", text: "[✓] Report compiled" },
];

export { SEVERITIES, SEVERITY_META, SCAN_STAGES, LOG_LINES };
