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
import { clearQueryCache } from "../services/queryCache.js";

// Session is managed via an HttpOnly cookie set by the backend. On mount we
// validate the session with the public session probe. Signed-out visitors get
// a null user without an expected 401 cluttering the browser console.
const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  const clearSession = useCallback(() => {
    clearQueryCache();
    setUser(null);
    navigate("/login", { replace: true });
  }, [navigate]);

  useEffect(() => {
    refreshCurrentUser().then(setUser).catch(() => {}).finally(() => {
      setOnUnauthorized(clearSession);
      setLoading(false);
    });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const login = useCallback(async (credentials) => {
    const authed = await loginService(credentials);
    clearQueryCache();
    setUser(authed);
    return authed;
  }, []);

  const register = useCallback(async (credentials) => {
    const authed = await registerService(credentials);
    clearQueryCache();
    setUser(authed);
    return authed;
  }, []);

  const logout = useCallback(async () => {
    await logoutService();
    clearQueryCache();
    setUser(null);
    navigate("/login", { replace: true });
  }, [navigate]);

  const value = useMemo(
    () => ({ user, loading, login, register, logout }),
    [user, loading, login, register, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

// eslint-disable-next-line react-refresh/only-export-components
export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within an AuthProvider");
  return ctx;
}
