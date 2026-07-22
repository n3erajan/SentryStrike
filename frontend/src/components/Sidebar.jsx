import { NavLink, useNavigate } from "react-router-dom";
import { X, LogOut } from "lucide-react";
import { NAV_ITEMS } from "../data/constants.js";
import { useAuth } from "../context/AuthContext.jsx";
import { useBackendHealth } from "../hooks/useBackendHealth.js";

function displayName(user) {
  if (!user) return "Signed in";
  if (user.fullName) return user.fullName;
  const email = user.email || "";
  const handle = email.split("@")[0];
  if (!handle) return "Signed in";
  return handle
    .split(/[._-]/)
    .filter(Boolean)
    .map((p) => p.charAt(0).toUpperCase() + p.slice(1))
    .join(" ");
}

function Sidebar({ open = false, onClose }) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const { health, loading: healthLoading, error: healthError } =
    useBackendHealth();
  const scannerCount = health?.active_scanners;
  const scannerStatusKnown = Number.isInteger(scannerCount) && !healthError;
  const scannersOnline = scannerStatusKnown && scannerCount > 0;

  let scannerStatus = "Scanner status unavailable";
  let scannerDetail = "Could not reach scanner health";
  if (healthLoading) {
    scannerStatus = "Checking scanner";
    scannerDetail = "Reading active scanners";
  } else if (scannerStatusKnown) {
    scannerStatus = scannersOnline ? "Scanner online" : "Scanner offline";
    scannerDetail = `${scannerCount} active ${scannerCount === 1 ? "scanner" : "scanners"}`;
  }

  async function handleLogout() {
    await logout();
    navigate("/", { replace: true });
  }

  return (
    <aside className={`side${open ? " open" : ""}`}>
      <div className='side-top'>
        <NavLink to='/home' className='brand' onClick={onClose}>
          <img src='/shield.png' className='mark-img' alt='' />
          SentryStrike
        </NavLink>
        <button
          type='button'
          className='side-close'
          onClick={onClose}
          aria-label='Close menu'
        >
          <X className='ico' />
        </button>
      </div>
      <nav className='app-nav' aria-label='Primary'>
        {NAV_ITEMS.map(({ to, label, Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            onClick={onClose}
            className={({ isActive }) => (isActive ? "active" : undefined)}
          >
            <Icon className='ico' />
            <span>{label}</span>
          </NavLink>
        ))}
      </nav>
      <div
        className={`scanner-status${
          healthLoading ? " checking" : scannersOnline ? " online" : " offline"
        }`}
        role='status'
        aria-live='polite'
      >
        <span className='scanner-status-dot' aria-hidden='true' />
        <span className='scanner-status-copy'>
          <b>{scannerStatus}</b>
          <small>{scannerDetail}</small>
        </span>
      </div>
      <div className='sidefoot'>
        <span>User</span>
        <b title={user?.email}>{displayName(user)}</b>

        <button
          className='text-btn'
          onClick={handleLogout}
          style={{
            marginTop: 8,
            display: "inline-flex",
            alignItems: "center",
            gap: 6,
          }}
        >
          <LogOut className='ico' />
          Sign out
        </button>
      </div>
    </aside>
  );
}

export default Sidebar;
export { displayName };
