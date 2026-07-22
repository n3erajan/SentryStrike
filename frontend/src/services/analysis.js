import { apiRequest } from "./apiClient.js";

const findingPath = (scanId, findingId) =>
  `/analysis/scans/${scanId}/vulnerabilities/${findingId}`;

export const retryAnalysis = (scanId) =>
  apiRequest(`/analysis/scans/${scanId}/retry`, { method: "POST" });
export const assignFinding = (scanId, findingId, assigneeUserId) =>
  apiRequest(`${findingPath(scanId, findingId)}/assignment`, {
    method: "PUT", body: { assignee_user_id: assigneeUserId || null },
  });
export const addFindingComment = (scanId, findingId, body) =>
  apiRequest(`${findingPath(scanId, findingId)}/comments`, { method: "POST", body: { body } });
export const updateRemediation = (scanId, findingId, remediationStatus) =>
  apiRequest(`${findingPath(scanId, findingId)}/remediation`, {
    method: "PUT", body: { remediation_status: remediationStatus },
  });
export const reviewFinding = (scanId, findingId, disposition, reason) =>
  apiRequest(`${findingPath(scanId, findingId)}/review`, {
    method: "PUT", body: { disposition, reason },
  });
export const reverifyFinding = (scanId, findingId) =>
  apiRequest(`${findingPath(scanId, findingId)}/reverify`, { method: "POST", body: {} });
export const listReverifications = (scanId, findingId, signal) =>
  apiRequest(`${findingPath(scanId, findingId)}/reverifications`, { signal });
