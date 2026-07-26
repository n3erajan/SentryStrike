import { Moon, Sun } from "lucide-react";
import { useTheme } from "../context/ThemeContext.jsx";
import Tooltip from "./Tooltip.jsx";

function ThemeToggle({ className = "" }) {
  const { theme, toggleTheme } = useTheme();
  const dark = theme === "dark";
  const label = dark ? "Switch to light mode" : "Switch to dark mode";

  return (
    <Tooltip label={label}>
      <button
        type='button'
        className={`theme-toggle${className ? ` ${className}` : ""}`}
        onClick={toggleTheme}
        aria-label={label}
        aria-pressed={dark}
      >
        {dark ? <Sun className='ico' /> : <Moon className='ico' />}
      </button>
    </Tooltip>
  );
}

export default ThemeToggle;
