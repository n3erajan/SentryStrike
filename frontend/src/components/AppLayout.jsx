import { useEffect, useState } from "react";
import { Outlet, NavLink, useLocation, useNavigate } from "react-router-dom";
import { Menu, Plus } from "lucide-react";
import Sidebar, { displayName } from "./Sidebar.jsx";
import { MOBILE_NAV, ROUTE_NAMES } from "../data/constants.js";
import { useAuth } from "../context/AuthContext.jsx";

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

  // Close the mobile drawer whenever the route changes.
  useEffect(() => {
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
            <button
              type='button'
              className='menu-btn'
              aria-label='Open menu'
              aria-expanded={menuOpen}
              onClick={() => setMenuOpen(true)}
            >
              <Menu className='ico' />
            </button>
            {displayName(user)} / <b>{crumbFor(location.pathname)}</b>
          </div>
          <div className='app-actions'>
            {!onScanPage && (
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
