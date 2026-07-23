import { useEffect, useState } from "react";
import { Outlet, NavLink, useLocation, useNavigate } from "react-router-dom";
import { Menu, Plus } from "lucide-react";
import Sidebar from "./Sidebar.jsx";
import { MOBILE_NAV, ROUTE_NAMES } from "../data/constants.js";
import { useAuth } from "../context/AuthContext.jsx";
import { getWorkspace } from "../services/workspace.js";
import ThemeToggle from "./ThemeToggle.jsx";
import NotificationsMenu from "./NotificationsMenu.jsx";
import Tooltip from "./Tooltip.jsx";

function crumbFor(pathname) {
  if (pathname.startsWith("/active/")) return "Active scans / Live scan";
  if (pathname.startsWith("/report/")) return "Reports / Security report";
  for (const [route, name] of Object.entries(ROUTE_NAMES)) {
    if (pathname === route) return name;
  }
  return "Home";
}

function AppLayout() {
  const location = useLocation();
  const navigate = useNavigate();
  const { user } = useAuth();
  const onScanPage = location.pathname === "/scan";
  const [menuOpen, setMenuOpen] = useState(false);
  const [workspace, setWorkspace] = useState(null);

  useEffect(() => {
    getWorkspace().then(setWorkspace).catch(() => {});
  }, []);

  // Close the mobile drawer whenever the route changes.
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setMenuOpen(false);
  }, [location.pathname]);

  return (
    <div className='app-shell'>
      <Sidebar open={menuOpen} onClose={() => setMenuOpen(false)} />
      {menuOpen && (
        <button
          type='button'
          className='side-overlay'
          aria-label='Close menu'
          onClick={() => setMenuOpen(false)}
        />
      )}
      <main className='app-main'>
        <header className='app-top'>
          <div className='crumb'>
            <Tooltip label='Open menu'>
              <button
                type='button'
                className='menu-btn'
                aria-label='Open menu'
                aria-expanded={menuOpen}
                onClick={() => setMenuOpen(true)}
              >
                <Menu className='ico' />
              </button>
            </Tooltip>
            {workspace?.name || "Workspace"} / <b>{crumbFor(location.pathname)}</b>
          </div>
          <div className='app-actions'>
            <NotificationsMenu />
            <ThemeToggle />
            {!onScanPage && user?.role !== "viewer" && (
              <button className='btn primary' onClick={() => navigate("/scan")}>
                <Plus className='ico' />
                New Scan
              </button>
            )}
          </div>
        </header>
        <Outlet />
      </main>
      <nav className='mobile' aria-label='Mobile navigation'>
        {MOBILE_NAV.map(({ to, label, Icon }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) => (isActive ? "active" : undefined)}
          >
            <Icon className='ico' />
            {label}
          </NavLink>
        ))}
      </nav>
    </div>
  );
}

export default AppLayout;
