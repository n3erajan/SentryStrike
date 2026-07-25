// Application service — wraps the backend `/applications/*` routes (mounted
// under /api/v1). An Application is an org-scoped web-app target that owns a
// name, a target URL, and a default ScanConfig used to prefill new scans.
//
//   POST   /applications              { name, target_url, default_scan_config }
//                                     -> 201 application
//   GET    /applications              ?skip&limit -> { items: [...], total }
//   GET    /applications/{id}         -> application
//   PUT    /applications/{id}         { name?, target_url?, default_scan_config? }
//   DELETE /applications/{id}         -> { deleted: true }
//   GET    /applications/{id}/scans   ?skip&limit -> { items: [...], total }
//
// Everyone except a viewer may create, update, or delete.
import { apiRequest } from "./apiClient.js";
import { compactScanConfig } from "./scan.js";

export function listApplications({ skip = 0, limit = 50, signal } = {}) {
  return apiRequest(`/applications?skip=${skip}&limit=${limit}`, { signal });
}

export function getApplication(appId, signal) {
  return apiRequest(`/applications/${appId}`, { signal });
}

export function createApplication({ name, targetUrl, config }) {
  return apiRequest("/applications", {
    method: "POST",
    body: {
      name,
      target_url: targetUrl,
      default_scan_config: compactScanConfig(config) || {},
    },
  });
}

// Only the supplied fields are sent — the backend leaves the rest untouched.
export function updateApplication(appId, { name, targetUrl, config }) {
  const body = {};
  if (name !== undefined) body.name = name;
  if (targetUrl !== undefined) body.target_url = targetUrl;
  if (config !== undefined) body.default_scan_config = compactScanConfig(config) || {};
  return apiRequest(`/applications/${appId}`, { method: "PUT", body });
}

export function deleteApplication(appId) {
  return apiRequest(`/applications/${appId}`, { method: "DELETE" });
}

export function listApplicationScans(appId, { skip = 0, limit = 50, signal } = {}) {
  return apiRequest(`/applications/${appId}/scans?skip=${skip}&limit=${limit}`, {
    signal,
  });
}

export async function listAllApplicationScans(appId, { signal } = {}) {
  const limit = 100;
  const items = [];
  let skip = 0;

  while (true) {
    const page = await listApplicationScans(appId, { skip, limit, signal });
    const pageItems = Array.isArray(page?.items) ? page.items : [];
    items.push(...pageItems);
    if (pageItems.length < limit) break;
    skip += pageItems.length;
  }

  return { items, total: items.length };
}
