// Report service — wraps the backend `/reports/*` routes (mounted under /api/v1).
//
//   GET  /reports/{id}           -> full report payload (see reports.py)
//   POST /reports/{id}/generate  -> regenerates the AI executive summary
//   GET  /reports/{id}/pdf       -> application/pdf attachment
import { apiRequest, API_BASE, getToken } from "./apiClient.js";

export function getReport(scanId, signal) {
  return apiRequest(`/reports/${scanId}`, { signal });
}

export function generateAiReport(scanId) {
  return apiRequest(`/reports/${scanId}/generate`, { method: "POST" });
}

// The PDF endpoint returns raw bytes rather than the JSON envelope, so we
// fetch it directly (still sending the bearer token) and hand back a Blob.
export async function downloadReportPdf(scanId) {
  const token = getToken();
  let response;
  try {
    response = await fetch(`${API_BASE}/reports/${scanId}/pdf`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
  } catch (err) {
    throw new Error("Cannot reach the server to build the PDF.", { cause: err });
  }
  if (!response.ok) {
    throw new Error(`Could not generate the PDF (${response.status}).`);
  }
  return response.blob();
}
