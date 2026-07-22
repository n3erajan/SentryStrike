import { Moon, Sun } from "lucide-react";
import { useTheme } from "../context/ThemeContext.jsx";

function ThemeToggle({ className = "" }) {
  const { theme, toggleTheme } = useTheme();
  const dark = theme === "dark";
  const label = dark ? "Switch to light mode" : "Switch to dark mode";

  return (
    <button
      type='button'
      className={`theme-toggle${className ? ` ${className}` : ""}`}
      onClick={toggleTheme}
      aria-label={label}
      title={label}
      aria-pressed={dark}
    >
      {dark ? <Sun className='ico' /> : <Moon className='ico' />}
    </button>
  );
}

export default ThemeToggle;
