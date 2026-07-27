// Central HTTP client for the SentryStrike backend.
//
// Every backend route lives under `/api/v1` and wraps its payload in a
// `{ success, message, data }` envelope (see backend app/api/dependencies.py).
// This helper unwraps that envelope and converts failures into safe, structured
// ApiErrors. Backend copy is accepted only when it passes defensive checks.
//
// The backend sets an HttpOnly session cookie on login; every request includes
// it via `credentials: "include"` — no client-side token storage needed.
//
// In dev, requests go to the relative `/api/v1` path which Vite proxies to the
// backend (see vite.config.js) — same-origin, no CORS. For a hosted build set
// VITE_API_URL to the backend origin, e.g. https://api.example.com/api/v1.

export const API_BASE = import.meta.env?.VITE_API_URL || "/api/v1";

// Registered once by App.jsx so any 401 from any API call clears the session.
let onUnauthorized = null;
export function setOnUnauthorized(cb) {
  onUnauthorized = cb;
}

const STATUS_MESSAGES = {
  400: "We couldn't process that request. Check the details and try again.",
  403: "You don't have permission to perform this action.",
  404: "We couldn't find the requested resource.",
  408: "The request took too long. Please try again.",
  413: "The submitted data is too large.",
  429: "Too many requests. Wait a moment and try again.",
  500: "We couldn't complete your request. Please try again.",
  502: "A required service is temporarily unavailable. Please try again.",
  503: "SentryStrike is temporarily unavailable. Please try again shortly.",
  504: "A required service took too long to respond. Please try again.",
};

const UNSAFE_MESSAGE =
  /(?:traceback|stack trace|exception|value error|internal server error|\b(?:sql|redis|mongo|pydantic|httpx)\b|[a-z]:\\|\/usr\/|\/app\/|errno\s*\d)/i;

function sentence(value) {
  const text = String(value || "").trim().replace(/^Value error,\s*/i, "");
  if (!text) return "";
  return /[.!?]$/.test(text) ? text : `${text}.`;
}

function fieldLabel(field) {
  const leaf = String(field || "request").split(".").at(-1);
  return leaf.replaceAll("_", " ").replace(/^./, (char) => char.toUpperCase());
}

function legacyFieldErrors(detail) {
  if (!Array.isArray(detail)) return [];
  return detail.map((item) => ({
    field: Array.isArray(item?.loc) ? item.loc.filter((part) => part !== "body").join(".") : "request",
    message:
      item?.type === "missing"
        ? "This field is required."
        : sentence(item?.msg) || "Enter a valid value.",
  }));
}

export class ApiError extends Error {
  constructor(message, { status = 0, code = "REQUEST_FAILED", requestId = "", fieldErrors = [], cause } = {}) {
    super(message, cause ? { cause } : undefined);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.requestId = requestId;
    this.fieldErrors = fieldErrors;
  }
}

export function apiErrorFromPayload(payload, status, fallback) {
  const fieldErrors = Array.isArray(payload?.field_errors)
    ? payload.field_errors
    : legacyFieldErrors(payload?.detail);
  const firstFieldError = fieldErrors[0];
  if (firstFieldError) {
    return new ApiError(
      `${fieldLabel(firstFieldError.field)}: ${sentence(firstFieldError.message)}`,
      {
        status,
        code: payload?.error_code || "VALIDATION_ERROR",
        requestId: payload?.request_id || "",
        fieldErrors,
      },
    );
  }

  const detail = payload?.detail;
  const candidate =
    (typeof payload?.message === "string" && payload.message) ||
    (typeof detail === "string" && detail) ||
    (detail && typeof detail.message === "string" && detail.message) ||
    "";
  const safeCandidate = Boolean(candidate) && status < 500 && candidate.length <= 320 && !UNSAFE_MESSAGE.test(candidate);
  const message = safeCandidate
    ? sentence(candidate)
    : fallback || STATUS_MESSAGES[status] || "We couldn't complete the request. Please try again.";

  return new ApiError(message, {
    status,
    code: payload?.error_code || detail?.code || `HTTP_${status}`,
    requestId: payload?.request_id || "",
  });
}

export async function apiErrorFromResponse(response, fallback) {
  let payload = null;
  try {
    payload = await response.clone().json();
  } catch {
    // Non-JSON proxy and gateway responses use the status-based fallback.
  }
  return apiErrorFromPayload(payload, response.status, fallback);
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
    throw new ApiError(
      "We couldn't connect to SentryStrike. Check your connection and try again.",
      { code: "NETWORK_ERROR", cause: err },
    );
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
    throw apiErrorFromPayload(payload, response.status);
  }

  if (payload && Object.prototype.hasOwnProperty.call(payload, "data")) {
    return payload.data;
  }
  return payload;
}
