import { NavLink, useNavigate } from "react-router-dom";
import { X, LogOut } from "lucide-react";
import { NAV_ITEMS } from "../data/constants.js";
import { useAuth } from "../context/AuthContext.jsx";
import { useActiveScans } from "../hooks/useActiveScans.js";

function workspaceName(user) {
  if (!user) return "Workspace";
  if (user.company) return user.company;
  const email = user.email || "";
  const domain = email.split("@")[1];
  if (!domain) return "Workspace";
  const base = domain.split(".")[0];
  return base
    ? `${base.charAt(0).toUpperCase()}${base.slice(1)} Workspace`
    : "Workspace";
}

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
  const { count } = useActiveScans();

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
      {/* <div className='workspace-name'>
        <b>{workspaceName(user)}</b>
        <small>Business plan</small>
      </div> */}
      <nav className='app-nav' aria-label='Workspace'>
        {NAV_ITEMS.map(({ to, label, Icon, badge, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            onClick={onClose}
            className={({ isActive }) => (isActive ? "active" : undefined)}
          >
            <Icon className='ico' />
            <span>{label}</span>
            {badge === "active" && count > 0 && (
              <span className='nav-badge'>{count}</span>
            )}
          </NavLink>
        ))}
      </nav>
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
export { workspaceName, displayName };
