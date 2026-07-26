import { apiRequest } from "./apiClient.js";

export const listNotifications = ({ skip = 0, limit = 15, unread_only, signal } = {}) => {
  let q = `/notifications?skip=${skip}&limit=${limit}`;
  if (unread_only) q += "&unread_only=true";
  return apiRequest(q, { signal });
};
export const getUnreadCount = (signal) => apiRequest("/notifications/unread-count", { signal });
export const markNotificationRead = (id) =>
  apiRequest(`/notifications/${id}/read`, { method: "PATCH" });
export const markAllNotificationsRead = () =>
  apiRequest("/notifications/read-all", { method: "POST" });
