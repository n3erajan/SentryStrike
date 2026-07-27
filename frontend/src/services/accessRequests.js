import { apiRequest } from "./apiClient.js";

export function getAccessRequestConfig(signal) {
  return apiRequest("/access-requests/config", { signal });
}

export function submitAccessRequest(payload) {
  return apiRequest("/access-requests", {
    method: "POST",
    body: payload,
  });
}
