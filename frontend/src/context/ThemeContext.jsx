import { createContext, useContext, useEffect, useMemo, useState } from "react";

const STORAGE_KEY = "sentrystrike-theme";
const ThemeContext = createContext(null);

function systemTheme() {
  return window.matchMedia("(prefers-color-scheme: dark)").matches
    ? "dark"
    : "light";
}

function storedTheme() {
  try {
    const value = window.localStorage.getItem(STORAGE_KEY);
    return value === "light" || value === "dark" ? value : null;
  } catch {
    return null;
  }
}

export function ThemeProvider({ children }) {
  const [preference, setPreference] = useState(storedTheme);
  const [system, setSystem] = useState(systemTheme);
  const theme = preference || system;

  useEffect(() => {
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const updateSystemTheme = (event) => setSystem(event.matches ? "dark" : "light");
    media.addEventListener("change", updateSystemTheme);
    return () => media.removeEventListener("change", updateSystemTheme);
  }, []);

  useEffect(() => {
    const root = document.documentElement;
    root.dataset.theme = theme;
    root.style.colorScheme = theme;

    const themeColor = document.querySelector('meta[name="theme-color"]');
    themeColor?.setAttribute("content", theme === "dark" ? "#151a24" : "#f7f9fc");
  }, [theme]);

  const value = useMemo(
    () => ({
      theme,
      toggleTheme() {
        const next = theme === "dark" ? "light" : "dark";
        setPreference(next);
        try {
          window.localStorage.setItem(STORAGE_KEY, next);
        } catch {
          // The current tab can still use the selected theme if storage is blocked.
        }
      },
    }),
    [theme],
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

// eslint-disable-next-line react-refresh/only-export-components
export function useTheme() {
  const value = useContext(ThemeContext);
  if (!value) throw new Error("useTheme must be used inside ThemeProvider");
  return value;
}
