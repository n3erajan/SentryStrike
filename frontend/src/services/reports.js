// Report service — wraps the backend `/reports/*` routes (mounted under /api/v1).
//
//   GET  /reports/{id}           -> full report payload (see reports.py)
//   GET  /reports/{id}/pdf       -> application/pdf attachment
import { apiErrorFromResponse, apiRequest, API_BASE, ApiError } from "./apiClient.js";

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
    throw new ApiError(
      "We couldn't connect to SentryStrike to build the PDF. Check your connection and try again.",
      { code: "NETWORK_ERROR", cause: err },
    );
  }
  if (!response.ok) {
    throw await apiErrorFromResponse(
      response,
      "We couldn't generate the PDF. Please try again.",
    );
  }
  return response.blob();
}
