// Central HTTP client for the SentryStrike backend.
//
// Every backend route lives under `/api/v1` and wraps its payload in a
// `{ success, message, data }` envelope (see backend app/api/dependencies.py).
// This helper unwraps that envelope, and turns non-2xx or `{ success: false }`
// responses into thrown Errors that carry the backend's own `message`.
//
// The backend sets an HttpOnly session cookie on login; every request includes
// it via `credentials: "include"` — no client-side token storage needed.
//
// In dev, requests go to the relative `/api/v1` path which Vite proxies to the
// backend (see vite.config.js) — same-origin, no CORS. For a hosted build set
// VITE_API_URL to the backend origin, e.g. https://api.example.com/api/v1.

export const API_BASE = import.meta.env.VITE_API_URL || "/api/v1";

// Registered once by App.jsx so any 401 from any API call clears the session.
let onUnauthorized = null;
export function setOnUnauthorized(cb) {
  onUnauthorized = cb;
}

function extractMessage(payload, status) {
  if (payload) {
    if (typeof payload.message === "string" && payload.message) return payload.message;
    const detail = payload.detail;
    if (typeof detail === "string" && detail) return detail;
    if (detail && typeof detail.message === "string") return detail.message;
    if (Array.isArray(detail) && detail.length) {
      const first = detail[0];
      if (first && typeof first.msg === "string") {
        const loc = Array.isArray(first.loc) ? first.loc[first.loc.length - 1] : null;
        return loc ? `${loc}: ${first.msg}` : first.msg;
      }
    }
  }
  return `Request failed (${status})`;
}

export async function apiRequest(path, { method = "GET", body, signal } = {}) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";

  let response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal,
      credentials: "include",
    });
  } catch (err) {
    if (err.name === "AbortError") throw err;
    throw new Error("Cannot reach the server. Is the backend running?", { cause: err });
  }

  if (response.status === 401 && onUnauthorized) {
    onUnauthorized();
  }

  let payload = null;
  const text = await response.text();
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = null;
    }
  }

  if (!response.ok || (payload && payload.success === false)) {
    const msg = extractMessage(payload, response.status);
    const error = new Error(msg);
    error.status = response.status;
    error.responseBody = text || null;
    throw error;
  }

  if (payload && Object.prototype.hasOwnProperty.call(payload, "data")) {
    return payload.data;
  }
  return payload;
}
