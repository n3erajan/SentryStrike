// Scan service — wraps the backend `/scans/*` routes (mounted under /api/v1).
//
//   POST   /scans                 { target_url, crawl_mode,
//                                   authorization_confirmed,
//                                   credentials? (main/second/admin accounts),
//                                   config? (full ScanConfig overrides) }
//                                 -> 202 { scan_id, status, progress, ... }
//   GET    /scans                 ?skip&limit -> { items: [...], total }
//   GET    /scans/{id}            -> full scan document
//   GET    /scans/{id}/status     -> { id, status, progress, current_phase,
//                                     phase_message, eta_seconds, error }
//   POST   /scans/{id}/cancel     -> { cancelled: bool }
//
// `status` is one of: queued | running | completed | failed | cancelled
import { apiRequest } from "./apiClient.js";

// Drop empty strings/null/undefined so unset fields are omitted entirely and
// the backend falls back to its own defaults. Returns the object only if it
// still has keys, else undefined.
function compact(obj) {
  const out = {};
  for (const [key, value] of Object.entries(obj || {})) {
    if (value === null || value === undefined || value === "") continue;
    out[key] = typeof value === "string" ? value.trim() : value;
  }
  return Object.keys(out).length ? out : undefined;
}

const CREDENTIAL_FIELDS = ["username", "password", "cookie", "header"];
const CONFIG_FIELDS = [
  "crawl_depth",
  "crawl_max_urls",
  "crawl_rate_limit_per_second",
  "crawl_browser_mode",
  "crawl_browser_max_interactions",
  "crawl_browser_budget_seconds",
  "scan_mode",
  "blind_injection_timing_threshold",
  "ssrf_inband_timing_delta_ms",
  "scanner_concurrency",
  "sensitive_paths_permutation_cap",
  "xss_browser_dom_max_jobs",
  "xss_browser_dom_budget_seconds",
  "allow_secondary_provisioning",
  "request_timeout_seconds",
];

function compactFields(obj, allowedFields) {
  return compact(
    Object.fromEntries(allowedFields.map((field) => [field, obj?.[field]])),
  );
}

// Build the optional `credentials` block from up to three role accounts
// (main/second/admin). Each account is a ScanAccountCredential; empty accounts
// are dropped so we never send blank roles.
function buildCredentials(credentials = {}) {
  const out = {};
  for (const role of ["main", "second", "admin"]) {
    const account = compactFields(credentials[role], CREDENTIAL_FIELDS);
    const populated =
      (account?.username && account?.password) ||
      account?.cookie ||
      account?.header;
    if (populated) out[role] = account;
  }
  return Object.keys(out).length ? out : undefined;
}

export function createScan({
  targetUrl,
  crawlMode,
  authorizationConfirmed,
  credentials,
  config,
}) {
  return apiRequest("/scans", {
    method: "POST",
    body: {
      target_url: targetUrl,
      crawl_mode: crawlMode,
      authorization_confirmed: authorizationConfirmed,
      credentials: buildCredentials(credentials),
      config: compactFields(config, CONFIG_FIELDS),
    },
  });
}

export function listScans({ skip = 0, limit = 50, signal } = {}) {
  return apiRequest(`/scans?skip=${skip}&limit=${limit}`, { signal });
}

export function getScanDetails(scanId, signal) {
  return apiRequest(`/scans/${scanId}`, { signal });
}

export function getScanStatus(scanId, signal) {
  return apiRequest(`/scans/${scanId}/status`, { signal });
}

export function cancelScan(scanId) {
  return apiRequest(`/scans/${scanId}/cancel`, { method: "POST" });
}
