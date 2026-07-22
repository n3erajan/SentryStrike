import { apiRequest } from "./apiClient.js";

export const listNotifications = (signal) => apiRequest("/notifications?limit=50", { signal });
export const getUnreadCount = (signal) => apiRequest("/notifications/unread-count", { signal });
export const markNotificationRead = (id) =>
  apiRequest(`/notifications/${id}/read`, { method: "PATCH" });
export const markAllNotificationsRead = () =>
  apiRequest("/notifications/read-all", { method: "POST" });
