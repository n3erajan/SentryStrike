// Scan service — wraps the backend `/scans/*` routes (mounted under /api/v1).
//
//   POST   /scans                 { target_url, crawl_mode,
//                                   authorization_confirmed, authorization_text,
//                                   credentials?, config? }
//                                 -> 202 { scan_id, status, progress, ... }
//   GET    /scans                 ?skip&limit -> { items: [...], total }
//   GET    /scans/{id}            -> full scan document
//   GET    /scans/{id}/status     -> { id, status, progress, error }
//   POST   /scans/{id}/cancel     -> { cancelled: bool }
//
// `status` is one of: queued | running | completed | failed | cancelled
import { apiRequest } from "./apiClient.js";

// Build the optional `credentials` block only when a main account is supplied.
// The backend accepts up to three roles (main/second/admin); we expose the
// primary account, which drives the authenticated crawl and IDOR baseline.
function buildCredentials({ authUsername, authPassword } = {}) {
  if (!authUsername || !authPassword) return undefined;
  return {
    main: {
      username: authUsername.trim(),
      password: authPassword,
    },
  };
}

// Only send config keys the user actually set, so unset fields fall back to
// the backend's global defaults.
function buildConfig({ scanMode } = {}) {
  const config = {};
  if (scanMode) config.scan_mode = scanMode;
  return Object.keys(config).length ? config : undefined;
}

export function createScan({
  targetUrl,
  crawlMode,
  authorizationConfirmed,
  authorizationText,
  authUsername,
  authPassword,
  scanMode,
}) {
  return apiRequest("/scans", {
    method: "POST",
    body: {
      target_url: targetUrl,
      crawl_mode: crawlMode,
      authorization_confirmed: authorizationConfirmed,
      authorization_text: authorizationText ? authorizationText.trim() : null,
      credentials: buildCredentials({ authUsername, authPassword }),
      config: buildConfig({ scanMode }),
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
