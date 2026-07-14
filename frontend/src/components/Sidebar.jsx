import { NavLink, useNavigate } from "react-router-dom";
import { SignOut, UserCircle } from "@phosphor-icons/react";
import { NAV_ITEMS } from "../data/constants.js";
import { useAuth } from "../context/AuthContext.jsx";
import { useActiveScans } from "../hooks/useActiveScans.js";

// Vertical left navigation. Replaces the old top Navbar: brand at the top,
// primary routes in the middle (NavLink handles the active state), and the
// signed-in user + logout pinned to the bottom. The Active item shows a live
// badge with the number of queued/running scans.
function Sidebar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const { count } = useActiveScans();

  async function handleLogout() {
    await logout();
    navigate("/", { replace: true });
  }

  return (
    <aside className='sidebar'>
      <NavLink to='/app/scan' className='sidebar-logo'>
        <div className='logo-icon'>
          <img src='/shield.png' alt='SentryStrike' className='logo-img' />
        </div>
        <div className='logo-text'>
          <div className='brand'>
            Sentry<span>Strike</span>
          </div>
          <div className='tagline'>Web Vulnerability Scanner</div>
        </div>
      </NavLink>

      <nav className='sidebar-nav'>
        {NAV_ITEMS.map(({ to, label, Icon, badge, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) =>
              `sidebar-link ${isActive ? "active" : ""}`
            }
          >
            <Icon size={19} weight='bold' />
            <span className='sidebar-link-label'>{label}</span>
            {badge === "active" && count > 0 && (
              <span className='sidebar-badge'>{count}</span>
            )}
          </NavLink>
        ))}
      </nav>

      <div className='sidebar-foot'>
        {user?.email && (
          <div className='sidebar-user' title={user.email}>
            <UserCircle size={22} weight='fill' />
            <span className='sidebar-user-email'>{user.email}</span>
          </div>
        )}
        <button className='sidebar-logout' onClick={handleLogout}>
          <SignOut size={16} weight='bold' /> Logout
        </button>
      </div>
    </aside>
  );
}

export default Sidebar;
