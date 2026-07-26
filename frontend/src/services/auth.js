// Auth service — talks to the backend `/auth/*` routes via apiClient.
//
// Authentication is handled by an HttpOnly session cookie set by the backend
// on login/register and cleared on logout. The frontend never touches the token
// — no localStorage, no bearer header management.
//
// Contract (mounted under /api/v1):
//   POST /auth/register  { email, password, full_name, invite_token } -> 201 { user } + set-cookie
//   POST /auth/login     { email, password }                          ->     { user } + set-cookie
//   POST /auth/logout                                                 ->     { logged_out: true } + clear-cookie
//   GET  /auth/me                                                     ->     { id, email, ... }
//   GET  /auth/invite    ?token                                       ->     { email, role, org_name }
import { apiRequest } from "./apiClient.js";

export function getCurrentUser() {
  return null;
}

export function isAuthenticated() {
  return false;
}

export async function login(credentials) {
  const data = await apiRequest("/auth/login", {
    method: "POST",
    body: credentials,
  });
  return data.user;
}

export function previewInvite(inviteToken, signal) {
  return apiRequest(`/auth/invite?token=${encodeURIComponent(inviteToken)}`, { signal });
}

export async function register({ email, password, fullName, inviteToken }) {
  const data = await apiRequest("/auth/register", {
    method: "POST",
    body: {
      email,
      password,
      full_name: fullName,
      invite_token: inviteToken,
    },
  });
  return data.user;
}

export async function refreshCurrentUser() {
  return await apiRequest("/auth/me");
}

export async function logout() {
  try {
    await apiRequest("/auth/logout", { method: "POST" });
  } catch {
    // Ignore network/session errors — we clear local state regardless.
  }
}
