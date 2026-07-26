// Report service — wraps the backend `/reports/*` routes (mounted under /api/v1).
//
//   GET  /reports/{id}           -> full report payload (see reports.py)
//   GET  /reports/{id}/pdf       -> application/pdf attachment
import { apiRequest, API_BASE } from "./apiClient.js";

export function getReport(scanId, signal) {
  return apiRequest(`/reports/${scanId}`, { signal });
}

// The PDF endpoint returns raw bytes rather than the JSON envelope, so we
// fetch it directly (the HttpOnly session cookie authenticates automatically).
export async function downloadReportPdf(scanId) {
  let response;
  try {
    response = await fetch(`${API_BASE}/reports/${scanId}/pdf`, {
      credentials: "include",
    });
  } catch (err) {
    throw new Error("Cannot reach the server to build the PDF.", { cause: err });
  }
  if (!response.ok) {
    let message = `Could not generate the PDF (${response.status}).`;
    try {
      const payload = await response.json();
      message = payload?.detail?.message || payload?.detail || payload?.message || message;
    } catch { /* Keep the status fallback for non-JSON responses. */ }
    throw new Error(message);
  }
  return response.blob();
}
