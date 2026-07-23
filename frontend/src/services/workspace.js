import { apiRequest } from "./apiClient.js";

export const listMembers = (signal) => apiRequest("/workspace/members", { signal });
export const listInvites = (signal) => apiRequest("/workspace/invites", { signal });
export const inviteMember = (email, role) =>
  apiRequest("/workspace/invites", { method: "POST", body: { email, role } });
export const cancelInvite = (inviteId) =>
  apiRequest(`/workspace/invites/${inviteId}/cancel`, { method: "POST" });
export const changeMemberRole = (userId, role) =>
  apiRequest(`/workspace/members/${userId}/role`, { method: "PATCH", body: { role } });
export const removeMember = (userId) =>
  apiRequest(`/workspace/members/${userId}`, { method: "DELETE" });
export const getDefaultConfig = (signal) => apiRequest("/workspace/default-config", { signal });
export const setDefaultConfig = (config) =>
  apiRequest("/workspace/default-config", { method: "PUT", body: { config } });
export const getRetention = (signal) => apiRequest("/workspace/retention", { signal });
export const setRetention = (retentionDays) =>
  apiRequest("/workspace/retention", { method: "PUT", body: { retention_days: retentionDays } });
export const getWorkspace = (signal) => apiRequest("/workspace", { signal });
export const listAuditLog = (signal) => apiRequest("/workspace/audit-log?limit=100", { signal });
