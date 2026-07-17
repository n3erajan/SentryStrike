import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
} from "react";
import {
  getCurrentUser,
  login as loginService,
  register as registerService,
  logout as logoutService,
} from "../services/auth.js";

// Shared auth state for the whole app. Hydrates synchronously from the token +
// user cached in localStorage (see services/auth.js) so a page refresh keeps
// the session without a round-trip. The backend also validates the bearer token
// on every protected request, so a stale local user simply gets a 401 there.
const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(getCurrentUser);

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
  }, []);

  const value = useMemo(
    () => ({ user, login, register, logout }),
    [user, login, register, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

// eslint-disable-next-line react-refresh/only-export-components
export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within an AuthProvider");
  return ctx;
}
