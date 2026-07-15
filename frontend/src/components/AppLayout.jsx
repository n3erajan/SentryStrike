import { Outlet, useLocation, useNavigate } from "react-router-dom";
import { Plus } from "@phosphor-icons/react";
import Sidebar from "./Sidebar.jsx";

function crumbFor(pathname) {
  if (pathname.includes("/report/")) return "History / Security report";
  if (pathname.includes("/active/")) return "Active scans / Live assessment";
  if (pathname.endsWith("/active")) return "Active scans";
  if (pathname.endsWith("/history")) return "Scan history";
  return "New assessment";
}

function AppLayout() {
  const location = useLocation();
  const navigate = useNavigate();
  const onScanPage = location.pathname.endsWith("/scan");

  return (
    <div className='app-shell'>
      <Sidebar />
      <div className='app-workspace'>
        <header className='app-top'>
          <div className='crumb'>SentryStrike / <b>{crumbFor(location.pathname)}</b></div>
          {!onScanPage && (
            <button className='btn primary app-new-scan' onClick={() => navigate("/app/scan")}>
              <Plus size={16} weight='bold' /> New assessment
            </button>
          )}
        </header>
        <main className='app-main'><Outlet /></main>
      </div>
    </div>
  );
}

export default AppLayout;
