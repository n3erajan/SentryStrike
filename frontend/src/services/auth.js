// Auth service — talks to the backend `/auth/*` routes via apiClient.
//
// Contract (branch: backend, mounted under /api/v1):
//   POST /auth/register { email, password } -> 201 { user, access_token, token_type, expires_at }
//   POST /auth/login    { email, password } ->     { user, access_token, token_type, expires_at }
//   POST /auth/logout                        ->     { logged_out: true }
//   GET  /auth/me                            ->     { id, email, created_at }
//
// The backend also sets an httponly session cookie, but we authenticate with
// the returned bearer token so the client works regardless of cross-origin
// cookie rules.
import { apiRequest, getToken, setToken, clearToken } from "./apiClient.js";

const USER_KEY = "sentrystrike_user";

function saveUser(user) {
  if (user) localStorage.setItem(USER_KEY, JSON.stringify(user));
}

function clearUser() {
  localStorage.removeItem(USER_KEY);
}

export function getCurrentUser() {
  try {
    const raw = localStorage.getItem(USER_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export function isAuthenticated() {
  return !!getToken();
}

async function authenticate(path, credentials) {
  const data = await apiRequest(path, {
    method: "POST",
    auth: false,
    body: credentials,
  });
  setToken(data.access_token);
  saveUser(data.user);
  return data.user;
}

export function login(credentials) {
  return authenticate("/auth/login", credentials);
}

export function previewInvite(inviteToken, signal) {
  return apiRequest(`/auth/invite?token=${encodeURIComponent(inviteToken)}`, {
    auth: false,
    signal,
  });
}

export function register({ email, password, fullName, inviteToken }) {
  return authenticate("/auth/register", {
    email,
    password,
    full_name: fullName,
    invite_token: inviteToken,
  });
}

export async function refreshCurrentUser() {
  const user = await apiRequest("/auth/me");
  saveUser(user);
  return user;
}

export async function logout() {
  try {
    await apiRequest("/auth/logout", { method: "POST" });
  } catch {
    // Ignore network/session errors — we clear local state regardless.
  }
  clearToken();
  clearUser();
}
