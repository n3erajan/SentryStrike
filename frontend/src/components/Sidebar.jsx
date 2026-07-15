import { NavLink, useNavigate } from "react-router-dom";
import { ShieldCheck, SignOut } from "@phosphor-icons/react";
import { NAV_ITEMS } from "../data/constants.js";
import { useAuth } from "../context/AuthContext.jsx";
import { useActiveScans } from "../hooks/useActiveScans.js";

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
      <NavLink to='/app/scan' className='brand sidebar-brand'>
        <span className='mark'><ShieldCheck size={19} weight='bold' /></span>
        SentryStrike
      </NavLink>
      <div className='workspace-name'><b>Security workspace</b><small>Web vulnerability scanner</small></div>
      <nav className='sidebar-nav'>
        {NAV_ITEMS.map(({ to, label, Icon, badge, end }) => (
          <NavLink key={to} to={to} end={end} className={({ isActive }) => `sidebar-link ${isActive ? "active" : ""}`}>
            <Icon size={18} weight='bold' />
            <span className='sidebar-link-label'>{label}</span>
            {badge === "active" && count > 0 && <span className='sidebar-badge'>{count}</span>}
          </NavLink>
        ))}
      </nav>
      <div className='sidebar-foot'>
        <b title={user?.email}>{user?.email || "Signed in"}</b>
        <span>Authorized assessments</span>
        <button className='text-btn sidebar-logout' onClick={handleLogout}><SignOut size={15} weight='bold' />Sign out</button>
      </div>
    </aside>
  );
}

export default Sidebar;
