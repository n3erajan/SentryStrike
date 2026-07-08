// Scan service — wraps the backend `/scans/*` routes (mounted under /api/v1).
//
//   POST   /scans                 { target_url, crawl_mode,
//                                   authorization_confirmed, authorization_text,
//                                   credentials? (main/second/admin accounts),
//                                   config? (full ScanConfig overrides) }
//                                 -> 202 { scan_id, status, progress, ... }
//   GET    /scans                 ?skip&limit -> { items: [...], total }
//   GET    /scans/{id}            -> full scan document
//   GET    /scans/{id}/status     -> { id, status, progress, error }
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

// Build the optional `credentials` block from up to three role accounts
// (main/second/admin). Each account is a ScanAccountCredential; empty accounts
// are dropped so we never send blank roles.
function buildCredentials(credentials = {}) {
  const out = {};
  for (const role of ["main", "second", "admin"]) {
    const account = compact(credentials[role]);
    if (account) out[role] = account;
  }
  return Object.keys(out).length ? out : undefined;
}

export function createScan({
  targetUrl,
  crawlMode,
  authorizationConfirmed,
  authorizationText,
  credentials,
  config,
}) {
  return apiRequest("/scans", {
    method: "POST",
    body: {
      target_url: targetUrl,
      crawl_mode: crawlMode,
      authorization_confirmed: authorizationConfirmed,
      authorization_text: authorizationText ? authorizationText.trim() : null,
      credentials: buildCredentials(credentials),
      config: compact(config),
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
