import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useEffect,
  useState,
} from "react";
import { useNavigate } from "react-router-dom";
import {
  login as loginService,
  register as registerService,
  logout as logoutService,
  refreshCurrentUser,
} from "../services/auth.js";
import { setOnUnauthorized } from "../services/apiClient.js";

// Session is managed via an HttpOnly cookie set by the backend. On mount we
// validate the session by calling GET /auth/me; a 401 (or missing session)
// simply leaves the user null, which ProtectedRoute redirects to /login.
const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  const clearSession = useCallback(() => {
    setUser(null);
    navigate("/login", { replace: true });
  }, [navigate]);

  useEffect(() => {
    setOnUnauthorized(clearSession);
    refreshCurrentUser().then(setUser).catch(() => {}).finally(() => setLoading(false));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const login = useCallback(async (credentials) => {
    const authed = await loginService(credentials);
    setUser(authed);
    return authed;
  }, []);

  const register = useCallback(async (credentials) => {
    const authed = await registerService(credentials);
    setUser(authed);
    return authed;
  }, []);

  const logout = useCallback(async () => {
    await logoutService();
    setUser(null);
    navigate("/login", { replace: true });
  }, [navigate]);

  const value = useMemo(
    () => ({ user, loading, login, register, logout }),
    [user, loading, login, register, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

// eslint-disable-next-line react-refresh/only-exhaustive-deps
export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within an AuthProvider");
  return ctx;
}
