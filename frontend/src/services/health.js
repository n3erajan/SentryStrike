import { apiRequest } from "./apiClient.js";

// The health route is public and reports scanner-worker heartbeats in addition
// to API health. A zero count means scans can queue, but no worker is available
// to claim them yet.
export function getHealth(signal) {
  return apiRequest("/health", { auth: false, signal });
}
