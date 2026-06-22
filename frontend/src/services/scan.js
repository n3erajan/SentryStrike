// Scan service — wraps the backend `/scans/*` routes (mounted under /api/v1).
//
//   POST   /scans                 { target_url, crawl_mode,
//                                   authorization_confirmed, authorization_text }
//                                 -> 202 { scan_id, status, progress, ... }
//   GET    /scans/{id}/status     -> { id, status, progress, error }
//   POST   /scans/{id}/cancel     -> { cancelled: bool }
//
// `status` is one of: queued | running | completed | failed | cancelled
import { apiRequest } from "./apiClient.js";

export function createScan({ targetUrl, crawlMode, authorizationConfirmed, authorizationText }) {
  return apiRequest("/scans", {
    method: "POST",
    body: {
      target_url: targetUrl,
      crawl_mode: crawlMode,
      authorization_confirmed: authorizationConfirmed,
      authorization_text: authorizationText ? authorizationText.trim() : null,
    },
  });
}

export function getScanStatus(scanId, signal) {
  return apiRequest(`/scans/${scanId}/status`, { signal });
}

export function cancelScan(scanId) {
  return apiRequest(`/scans/${scanId}/cancel`, { method: "POST" });
}
