// Auth service — matches the backend `/auth/*` routes.
//
// Contract (branch: backend):
//   POST /auth/register { email, password } -> { user, access_token, expires_at }
//   POST /auth/login    { email, password } -> { user, access_token, expires_at }
//   POST /auth/logout                       -> { logged_out: true }
//   GET  /auth/me                           -> { id, email, created_at }
//
// While USE_MOCK is true the calls resolve locally so the UI works without a
// running backend. Flip it to false once the API is reachable.
const USE_MOCK = true;
const TOKEN_KEY = "sentrystrike_token";

function setToken(token) {
  if (token) localStorage.setItem(TOKEN_KEY, token);
}

function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}

function clearToken() {
  localStorage.removeItem(TOKEN_KEY);
}
const USER_KEY = "sentrystrike_user";

function saveUser(user) {
  if (user) localStorage.setItem(USER_KEY, JSON.stringify(user));
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

export function logout() {
  if (!USE_MOCK) {
    apiRequest("/auth/logout", { method: "POST" }).catch(() => {});
  }
  clearToken();
  localStorage.removeItem(USER_KEY);
}

async function authenticate(path, { email, password }) {
  if (USE_MOCK) {
    await new Promise((r) => setTimeout(r, 500));
    if (!email || !password) throw new Error("Missing credentials");
    const user = {
      id: "mock-user",
      email,
      created_at: new Date().toISOString(),
    };
    setToken("mock-token");
    saveUser(user);
    return user;
  }

  const data = await apiRequest(path, {
    method: "POST",
    auth: false,
    body: { email, password },
  });
  setToken(data.access_token);
  saveUser(data.user);
  return data.user;
}

export function login(credentials) {
  return authenticate("/auth/login", credentials);
}

export function register(credentials) {
  return authenticate("/auth/register", credentials);
}
